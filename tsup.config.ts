import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    cli: 'src/cli.ts',
    index: 'src/index.ts',
  },
  format: ['esm'],
  target: 'node22',
  platform: 'node',
  // tsup's declaration build sets `baseUrl`, which TypeScript 6 deprecates.
  dts: { entry: { index: 'src/index.ts' }, compilerOptions: { ignoreDeprecations: '6.0' } },
  clean: true,
  sourcemap: false,
  splitting: true,
  outDir: 'dist',
});
