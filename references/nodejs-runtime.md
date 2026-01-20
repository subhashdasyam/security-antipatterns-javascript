# Node.js Runtime Security

**CWE:** CWE-1333 (ReDoS), CWE-400 (Resource Exhaustion)
**Node.js Specific**

## Regular Expression Denial of Service (ReDoS)

```typescript
// ❌ BAD: Catastrophic backtracking patterns
const emailRegex = /^([a-zA-Z0-9]+)+@/;      // (a+)+ pattern
const pathRegex = /^(\/*[^\/]*)*$/;          // Nested quantifiers
const htmlRegex = /<([^>]+)+>/;              // Nested quantifiers

// These can hang with crafted input like: "aaaaaaaaaaaaaaaaaaaaaaaaaaa!"

// ✅ GOOD: Safe regex patterns
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// ✅ GOOD: Use re2 for user-provided patterns
import RE2 from 're2';

function safeMatch(pattern: string, input: string): boolean {
  try {
    const re = new RE2(pattern);  // RE2 guarantees linear time
    return re.test(input);
  } catch {
    return false;  // Invalid pattern
  }
}

// ✅ GOOD: Limit input length before regex
function validateEmail(email: string): boolean {
  if (email.length > 254) return false;  // Max email length
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ✅ GOOD: Use timeout for regex operations
import { setTimeout } from 'timers/promises';

async function safeRegexTest(regex: RegExp, input: string, timeoutMs = 100): Promise<boolean> {
  return Promise.race([
    Promise.resolve(regex.test(input)),
    setTimeout(timeoutMs).then(() => { throw new Error('Regex timeout'); })
  ]);
}
```

## Event Loop Blocking

```typescript
// ❌ BAD: Blocking the event loop
import fs from 'fs';

app.get('/file', (req, res) => {
  const content = fs.readFileSync('/large/file.txt');  // Blocks all requests!
  res.send(content);
});

// ❌ BAD: Synchronous crypto operations on large data
const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');

// ✅ GOOD: Use async APIs
import fs from 'fs/promises';

app.get('/file', async (req, res) => {
  const content = await fs.readFile('/large/file.txt');
  res.send(content);
});

// ✅ GOOD: Async crypto
const hash = await new Promise<Buffer>((resolve, reject) => {
  crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, key) => {
    if (err) reject(err);
    else resolve(key);
  });
});

// ✅ GOOD: Worker threads for CPU-intensive tasks
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';

if (isMainThread) {
  const worker = new Worker(__filename, { workerData: heavyInput });
  worker.on('message', (result) => console.log(result));
} else {
  // CPU-intensive work here
  const result = processHeavyData(workerData);
  parentPort?.postMessage(result);
}
```

## Child Process Security

```typescript
// ❌ BAD: exec with user input (shell injection)
import { exec } from 'child_process';
exec(`ls ${userDir}`);  // userDir: "; rm -rf /"

// ❌ BAD: spawn with shell: true
import { spawn } from 'child_process';
spawn('ls', [userDir], { shell: true });  // Still vulnerable

// ✅ GOOD: execFile with argument array (no shell)
import { execFile } from 'child_process';
execFile('ls', [userDir], (error, stdout) => {
  if (error) throw error;
  console.log(stdout);
});

// ✅ GOOD: spawn without shell
spawn('ls', [userDir]);  // shell: false is default

// ✅ GOOD: Validate input before use
const ALLOWED_DIRS = ['/var/data', '/tmp/uploads'];

function isAllowedPath(dir: string): boolean {
  const resolved = path.resolve(dir);
  return ALLOWED_DIRS.some(allowed =>
    resolved.startsWith(allowed + path.sep)
  );
}

if (!isAllowedPath(userDir)) throw new Error('Invalid directory');
execFile('ls', [userDir]);
```

## Unhandled Rejections and Exceptions

```typescript
// ❌ BAD: No global error handlers
// Unhandled promise rejection crashes in Node 15+

// ✅ GOOD: Global error handlers
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Log to monitoring service
  // Graceful shutdown
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Log to monitoring service
});

// ✅ GOOD: Express error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Express error:', err);
  res.status(500).json({ error: 'Internal server error' });
});
```

## Resource Limits

```typescript
// ❌ BAD: Unbounded collections
const cache: Map<string, any> = new Map();

app.get('/data/:id', async (req, res) => {
  if (cache.has(req.params.id)) {
    return res.json(cache.get(req.params.id));
  }
  const data = await fetchData(req.params.id);
  cache.set(req.params.id, data);  // Unbounded growth = memory leak
  res.json(data);
});

// ✅ GOOD: LRU cache with size limit
import { LRUCache } from 'lru-cache';

const cache = new LRUCache<string, any>({
  max: 500,           // Max 500 entries
  maxSize: 50_000_000, // Max 50MB
  sizeCalculation: (value) => JSON.stringify(value).length,
  ttl: 1000 * 60 * 5  // 5 minute TTL
});

// ✅ GOOD: Bounded arrays
const MAX_ITEMS = 1000;
const items: string[] = [];

function addItem(item: string) {
  if (items.length >= MAX_ITEMS) {
    items.shift();  // Remove oldest
  }
  items.push(item);
}
```

## Stream Safety

```typescript
// ❌ BAD: Loading entire file into memory
const content = await fs.readFile('huge-file.csv');
processCSV(content.toString());

// ✅ GOOD: Stream processing
import { createReadStream } from 'fs';
import { pipeline } from 'stream/promises';

await pipeline(
  createReadStream('huge-file.csv'),
  new Transform({
    transform(chunk, encoding, callback) {
      // Process chunk
      callback(null, processedChunk);
    }
  }),
  createWriteStream('output.csv')
);
```

## Key Principles

1. **Avoid nested quantifiers** in regex - use re2 for user input
2. **Use async APIs** - never block the event loop
3. **Use execFile not exec** - avoid shell injection
4. **Set resource limits** - bounded caches, max sizes
5. **Handle all errors** - uncaughtException, unhandledRejection
6. **Stream large data** - don't load huge files into memory
