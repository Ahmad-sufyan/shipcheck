import { Node, SyntaxKind } from 'ts-morph';
import type { RawFinding, Rule } from '../../../types.js';
import { findingAt, sourceFiles } from '../analysis/ast-utils.js';
import { clientReachableModules } from '../analysis/import-graph.js';

/** Provider SDKs that need a secret key. AI SDK UI packages (@ai-sdk/react, ...) are meant for the browser and excluded. */
const LLM_MODULE = /^(?:openai|@anthropic-ai\/sdk|@google\/genai|@google\/generative-ai|groq-sdk|@mistralai\/mistralai|cohere-ai|@ai-sdk\/(?!react$|vue$|svelte$|solid$|rsc$|ui-utils$)[\w-]+)$/;
const PUBLIC_LLM_KEY = /^NEXT_PUBLIC_\w*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE|GROQ|MISTRAL|COHERE)\w*$/i;

interface Signal {
  node: Node;
  rank: number;
}

export const integ004: Rule = {
  id: 'INTEG-004',
  title: 'LLM API key in client code',
  category: 'integrations',
  severity: 'critical',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    "Reports client code (a 'use client' file or a project module it imports) that imports an LLM provider SDK (openai, " +
    '@anthropic-ai/sdk, @google/genai, groq-sdk, AI SDK provider packages) or sets dangerouslyAllowBrowser: true, and ' +
    'any NEXT_PUBLIC_ variable for an OpenAI, Anthropic, Gemini, Groq, Mistral or Cohere key. One finding per file, at ' +
    'the strongest signal.',
  explanation:
    'The LLM provider key ships to every visitor’s browser, so anyone can copy it and run up your AI bill or reach ' +
    'whatever the key can access.',
  fix: 'Call the model from a route handler or server action with a server-only key (no NEXT_PUBLIC_ prefix), and rotate any key that was exposed.',
  falsePositiveNote: 'None expected; provider keys are never safe in the browser.',
  cwe: 'CWE-522',
  references: ['https://github.com/openai/openai-node#requirements', 'https://nextjs.org/docs/app/guides/environment-variables'],
  run(ctx) {
    const reachable = clientReachableModules(ctx);
    const findings: RawFinding[] = [];
    for (const file of sourceFiles(ctx, (text) => /NEXT_PUBLIC_|openai|anthropic|genai|generative-ai|groq|mistral|cohere|@ai-sdk|dangerouslyAllowBrowser/i.test(text))) {
      const sourceFile = ctx.getSourceFile(file);
      const signals: Signal[] = [];
      if (reachable.has(file)) {
        for (const property of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
          if (property.getName() === 'dangerouslyAllowBrowser' && property.getInitializer()?.getText() === 'true') signals.push({ node: property, rank: 3 });
        }
        for (const declaration of sourceFile.getImportDeclarations()) {
          if (!declaration.isTypeOnly() && LLM_MODULE.test(declaration.getModuleSpecifierValue())) signals.push({ node: declaration, rank: 1 });
        }
      }
      for (const access of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
        if (access.getExpression().getText() === 'process.env' && PUBLIC_LLM_KEY.test(access.getName())) signals.push({ node: access, rank: 2 });
      }
      const strongest = signals.sort((a, b) => b.rank - a.rank || a.node.getStart() - b.node.getStart())[0];
      if (strongest) findings.push(findingAt(strongest.node));
    }
    return findings;
  },
};
