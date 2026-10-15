import { hasDirective } from '../../context/ast.js';
import { fileSetOf } from '../../context/files.js';
import type { NextSource } from './routes.js';

const SCRIPT_FILE = /\.(?:[cm]?[jt]sx?)$/;

/** Whether the file starts with a 'use client' directive (comments before it are allowed). */
export function isClientFile(source: NextSource, file: string): boolean {
  if (!SCRIPT_FILE.test(file) || !fileSetOf(source.files).has(file)) return false;
  if (!source.readText(file).includes('use client')) return false;
  return hasDirective(source.getSourceFile(file), 'use client');
}
