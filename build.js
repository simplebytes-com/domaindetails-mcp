import * as esbuild from 'esbuild';
import { chmod, readFile, writeFile, mkdir } from 'fs/promises';

// Ensure build directory exists
await mkdir('build', { recursive: true });

// Build CLI entry point
await esbuild.build({
  entryPoints: ['src/cli.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  outfile: 'build/cli.js',
  external: ['@modelcontextprotocol/sdk'],
});

// Build MCP server entry point
await esbuild.build({
  entryPoints: ['src/mcp-server.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  outfile: 'build/mcp-server.js',
  external: ['@modelcontextprotocol/sdk'],
});

// Build library entry point
await esbuild.build({
  entryPoints: ['src/lib.js'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  outfile: 'build/lib.js',
  external: ['@modelcontextprotocol/sdk'],
});

// Add shebang and make CLI executable
const cliContent = await readFile('build/cli.js', 'utf-8');
if (!cliContent.startsWith('#!/usr/bin/env node')) {
  await writeFile('build/cli.js', `#!/usr/bin/env node\n${cliContent}`);
}
await chmod('build/cli.js', 0o755);

// Add shebang and make MCP server executable
const mcpContent = await readFile('build/mcp-server.js', 'utf-8');
if (!mcpContent.startsWith('#!/usr/bin/env node')) {
  await writeFile('build/mcp-server.js', `#!/usr/bin/env node\n${mcpContent}`);
}
await chmod('build/mcp-server.js', 0o755);

console.log('Build complete!');
console.log('  - build/cli.js (CLI entry point)');
console.log('  - build/mcp-server.js (MCP server entry point)');
console.log('  - build/lib.js (Library entry point)');
