import * as esbuild from 'esbuild';
import { chmod, readFile, writeFile } from 'fs/promises';

await esbuild.build({
  entryPoints: ['src/index.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  outfile: 'build/index.js',
  external: ['@modelcontextprotocol/sdk'],
});

// Add shebang and make executable
const content = await readFile('build/index.js', 'utf-8');
await writeFile('build/index.js', `#!/usr/bin/env node\n${content}`);
await chmod('build/index.js', 0o755);

console.log('Build complete!');
