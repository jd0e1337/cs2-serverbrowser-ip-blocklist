import { writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const SOURCE = 'https://www.cs2monitor.com/api/blocklist';
const CATEGORIES = new Set(['abuse', 'unclassified', 'restricted']);

function ipv4(value) {
  return typeof value === 'string' && /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)
    && value.split('.').every(part => Number(part) <= 255);
}

export function buildLists(data) {
  if (!data || !['items', 'derivedItems', 'serverRules'].every(key => Array.isArray(data[key]))) {
    throw new Error('Incomplete blocklist response');
  }
  const base = new Set(), all = new Set();
  for (const [key, types] of [['items', ['ip', 'subnet']], ['derivedItems', ['ip']], ['serverRules', ['server_address']]]) {
    if (data[key].length > 100000) throw new Error('Oversized blocklist');
    for (const row of data[key]) {
      if (!row || !types.includes(row.type) || !CATEGORIES.has(row.category) || typeof row.value !== 'string') {
        throw new Error('Invalid address record');
      }
      let address = row.value;
      if (row.type === 'server_address') {
        const parts = address.split(':');
        if (parts.length !== 2 || !/^[1-9]\d{0,4}$/.test(parts[1]) || Number(parts[1]) > 65535) throw new Error('Invalid server port');
        address = parts[0];
      }
      if (row.type === 'subnet') {
        const parts = address.split('/');
        if (parts.length !== 2 || !ipv4(parts[0]) || !/^(?:[89]|[12]\d|3[0-2])$/.test(parts[1])) throw new Error('Invalid IPv4 network');
      } else if (!ipv4(address)) throw new Error('Invalid IPv4 address');
      all.add(address);
      if (row.category !== 'restricted') base.add(address);
    }
  }
  // Do not erase published lists on an unexpectedly empty upstream response.
  if (!base.size || !all.size) throw new Error('Empty blocklist; published files remain unchanged');
  const render = entries => [...entries].sort((a, b) => a.localeCompare(b, 'en', { numeric: true })).join('\n') + '\n';
  return { 'blocklist.txt': render(base), 'blocklist-with-restricted.txt': render(all) };
}

async function main() {
  const response = await fetch(SOURCE, {
    redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
  });
  if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Blocklist download failed');
  const date = Date.parse(response.headers.get('date') ?? '');
  if (!Number.isFinite(date) || Date.now() - date > 1800000 || date - Date.now() > 300000) throw new Error('Stale HTTP response');
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > 20 * 1024 * 1024) throw new Error('Oversized response');
    chunks.push(chunk);
  }
  const files = buildLists(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  // Validate the whole snapshot before writing either output. Only these files are committed.
  for (const [name, content] of Object.entries(files)) {
    await writeFile(new URL('../' + name, import.meta.url), content);
    console.log(`${name}: ${content.trim().split('\n').length} addresses / networks`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
