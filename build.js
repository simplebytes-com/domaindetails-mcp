import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/index.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  outfile: 'build/index.js',
  external: ['@modelcontextprotocol/sdk'],
  banner: {
    js: '#!/usr/bin/env node\n',
  },
});

console.log('Build complete!');
