/**
 * Tiny static server for the playground. No dependencies.
 *   node playground/server.mjs
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 5174;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0];
  const file = url === '/' ? 'index.html' : url.replace(/^\/+/, '');
  try {
    const body = await readFile(join(here, file));
    res.writeHead(200, {
      'Content-Type': TYPES[extname(file)] || 'application/octet-stream',
      // Always serve fresh so a rebuild shows up on refresh.
      'Cache-Control': 'no-store, must-revalidate',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found: ' + file);
  }
}).listen(PORT, () => {
  console.log('llm-stream-guardrails playground on http://localhost:' + PORT);
});
