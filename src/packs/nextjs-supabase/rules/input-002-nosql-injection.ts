import { Node, SyntaxKind } from 'ts-morph';
import { unwrapExpression } from '../../../context/ast.js';
import type { RawFinding, Rule } from '../../../types.js';
import { calleeName, calleeNameNode, findingAt, receiverOf, sourceFiles } from '../analysis/ast-utils.js';
import { isMongoCollection } from '../analysis/db-write.js';
import { entryFunctionOf, isUserInput } from '../analysis/taint.js';

const FILTER_METHODS = new Set([
  'find',
  'findOne',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findOneAndReplace',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'countDocuments',
  'replaceOne',
  'exists',
]);

export const input002: Rule = {
  id: 'INPUT-002',
  title: 'NoSQL injection',
  category: 'input-validation',
  severity: 'high',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Reports MongoDB collection methods (find, findOne, updateOne, deleteMany, ...) and Mongoose model methods (in files ' +
    'that import mongoose) whose filter is request data or spreads it, and any query object with a $where key. Receivers ' +
    'count as collections when they come from .collection()/getCollection() or are named like a collection.',
  explanation:
    'A filter object comes straight from the request, so a caller can send operators such as {"$ne": null} or {"$gt": ""} ' +
    'to match records they should not see, bypass checks, or delete everything.',
  fix: 'Validate the input with a schema and build the filter from typed fields, for example `{ status: input.status, userId: user.id }`. Avoid $where entirely.',
  falsePositiveNote: 'A body already validated by a strict schema elsewhere is still reported; build filters from named fields to be safe.',
  cwe: 'CWE-943',
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /mongo|collection|\$where/i.test(text))) {
      const sourceFile = ctx.getSourceFile(file);
      const mongoose = sourceFile.getImportDeclarations().some((d) => d.getModuleSpecifierValue() === 'mongoose');
      const reported = new Set<number>();
      const report = (node: Node) => {
        const finding = findingAt(node);
        if (!reported.has(finding.line!)) findings.push(finding);
        reported.add(finding.line!);
      };
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!FILTER_METHODS.has(calleeName(call))) continue;
        const receiver = receiverOf(call);
        const model = mongoose && receiver !== undefined && Node.isIdentifier(unwrapExpression(receiver)) && /^[A-Z]/.test(receiver.getText());
        if (!isMongoCollection(receiver) && !model) continue;
        const [filter] = call.getArguments();
        if (filter && isUserInput(filter, entryFunctionOf(call))) report(calleeNameNode(call));
      }
      for (const property of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
        if (property.getName().replace(/^['"]|['"]$/g, '') === '$where') report(property);
      }
    }
    return findings;
  },
};
