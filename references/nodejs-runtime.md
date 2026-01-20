# Node.js Runtime Security

**CWE:** CWE-1333 (ReDoS), CWE-400 (Resource Exhaustion), CWE-674 (Uncontrolled Recursion)
**CVE:** CVE-2025-59466 (Async Hooks Stack Exhaustion)

## Regular Expression Denial of Service (ReDoS)

### BAD

```typescript
// Catastrophic backtracking patterns
const emailRegex = /^([a-zA-Z0-9]+)+@/;      // (a+)+ pattern
const pathRegex = /^(\/*[^\/]*)*$/;          // Nested quantifiers
const htmlRegex = /<([^>]+)+>/;              // Nested quantifiers

// These can hang with crafted input like: "aaaaaaaaaaaaaaaaaaaaaaaaaaa!"
```

### GOOD

```typescript
// Safe regex patterns
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// Use re2 for user-provided patterns
import RE2 from 're2';

function safeMatch(pattern: string, input: string): boolean {
  try {
    const re = new RE2(pattern);  // RE2 guarantees linear time
    return re.test(input);
  } catch {
    return false;  // Invalid pattern
  }
}

// Limit input length before regex
function validateEmail(email: string): boolean {
  if (email.length > 254) return false;  // Max email length
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Use timeout for regex operations
import { setTimeout } from 'timers/promises';

async function safeRegexTest(regex: RegExp, input: string, timeoutMs = 100): Promise<boolean> {
  return Promise.race([
    Promise.resolve(regex.test(input)),
    setTimeout(timeoutMs).then(() => { throw new Error('Regex timeout'); })
  ]);
}
```

## Event Loop Blocking

### BAD

```typescript
// Blocking the event loop
import fs from 'fs';

app.get('/file', (req, res) => {
  const content = fs.readFileSync('/large/file.txt');  // Blocks all requests!
  res.send(content);
});

// Synchronous crypto operations on large data
const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
```

### GOOD

```typescript
// Use async APIs
import fs from 'fs/promises';

app.get('/file', async (req, res) => {
  const content = await fs.readFile('/large/file.txt');
  res.send(content);
});

// Async crypto
const hash = await new Promise<Buffer>((resolve, reject) => {
  crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, key) => {
    if (err) reject(err);
    else resolve(key);
  });
});

// Worker threads for CPU-intensive tasks
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

## Async Hooks Stack Exhaustion (CVE-2025-59466)

### BAD

```typescript
// Deep async recursion
async function recurse(n) { if (n > 0) await recurse(n-1); }  // Stack overflow, exit 7

// No depth limits
async_hooks.createHook({ init() {} }).enable();  // Amplifies

// Infinite promises
while (true) Promise.resolve();  // Hangs

// Nested awaits
await await await deepChain();  // Builds stack

// RSC deep trees
processRSC({ children: { /* deep */ } });  // Related to CVE-2025-55184

// No timeout
await longIO();  // Blocks

// Sync in async
function asyncWrap() { heavySync(); }  // Starves loop

// Many hooks
for (let i=0; i<1e6; i++) async_hooks.createHook();

// Deep middleware
app.use(nestMiddlewares(1000));  // Stack build

// Unhandled rejections pileup
Promise.reject();  // Memory leak
```

### GOOD

```typescript
// Iteration over recursion
async function iterate(n) { while (n--) await step(); }

// Depth guard
let depth=0; async function guarded() { if (++depth>1000) error(); /* */ depth--; }

// Timeouts
await Promise.race([io(), setTimeout(5000, () => error())]);

// Async microtasks
queueMicrotask(step);  // Avoids stack

// Limit hooks
if (hooks.length > 10) disableHooks();

// Handle rejections
process.on('unhandledRejection', logAndHandle);

// Flat middleware
app.use(flatChain());

// Worker offload
new Worker('heavy.js');

// Memory monitoring
if (process.memoryUsage().heapUsed > 1e9) gc();

// Rate limit deep calls
limiter.limit('recurse', 100);
```

## HTTP/2 Exhaustion

### BAD

```typescript
// Unlimited streams
http2.createServer();  // DoS via floods

// No session limits
server.on('session', () => {});  // Many sessions

// Large frames
settings: { maxFrameSize: 1e9 }  // Memory

// No header compression limits
// HPACK bombs

// Ping floods
// No rate on pings

// Settings floods
// Frequent updates

// Stream priority abuse
// Reorder exhausts

// No window size control
// Data floods

// Concurrent pushes
// Push overload

// No timeout
settings: { timeout: 0 }
```

### GOOD

```typescript
// Stream caps
http2.createServer({ settings: { maxConcurrentStreams: 50 } });

// Session counter
let sessions=0;
session.on('close', () => sessions--);
if (sessions++ > 100) session.destroy();

// Frame limits
{ settings: { maxFrameSize: 16384 } }

// HPACK limits
{ settings: { maxHeaderListSize: 4096 } }

// Ping rate limiting
rateLimit('ping', 10/60);

// Settings rate limiting
rateLimit('settings');

// Priority queue with bounds
// Use bounded queue

// Window updates
stream.respond({ ':status': 200 });

// Push limits
{ settings: { maxPushes: 10 } }

// Timeouts
{ settings: { timeout: 5000 } }
```

## Buffer/Race Conditions

### BAD

```typescript
// Unsafe alloc
Buffer.allocUnsafe(1e6);  // Old data leak

// Race in writes
fs.writeFile('file', data);  // Concurrent corrupts

// No locks
sharedBuffer[0] = val;  // Thread race

// Huge buffers
Buffer.from(hugeString);

// Unfilled buffers
const buf = Buffer.alloc(1024);  // Use without fill

// TOCTOU
if (fs.existsSync(file)) fs.readFileSync(file);  // Race delete

// Async races
await Promise.all([write1(), write2()]);  // Order undefined

// Shared state
global.buf = Buffer.alloc(1024);

// No bounds
buf.write(userData);  // Overflow

// Weak refs
// GC races
```

### GOOD

```typescript
// Safe alloc
Buffer.alloc(1e6, 0);

// Locks
import { Mutex } from 'async-mutex';
const mutex = new Mutex();
await mutex.runExclusive(() => fs.writeFile());

// Atomic ops
fs.writeFileSync();  // For small files

// Size checks
if (str.length > 1e6) throw new Error('Too large');

// Fill always
buf.fill(0);

// Atomic read
fs.readFileSync(ifExists(file));

// Sequenced
await write1(); await write2();

// Locals
let buf = Buffer.alloc(1024);

// Bounds
buf.write(userData, 0, Math.min(userData.length, buf.length));

// Strong refs
// Pin in scope
```

## Child Process Security

### BAD

```typescript
// exec with user input (shell injection)
import { exec } from 'child_process';
exec(`ls ${userDir}`);  // userDir: "; rm -rf /"

// spawn with shell: true
import { spawn } from 'child_process';
spawn('ls', [userDir], { shell: true });  // Still vulnerable
```

### GOOD

```typescript
// execFile with argument array (no shell)
import { execFile } from 'child_process';
execFile('ls', [userDir], (error, stdout) => {
  if (error) throw error;
  console.log(stdout);
});

// spawn without shell
spawn('ls', [userDir]);  // shell: false is default

// Validate input before use
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

### BAD

```typescript
// No global error handlers
// Unhandled promise rejection crashes in Node 15+
```

### GOOD

```typescript
// Global error handlers
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

// Express error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Express error:', err);
  res.status(500).json({ error: 'Internal server error' });
});
```

## Resource Limits

### BAD

```typescript
// Unbounded collections
const cache: Map<string, any> = new Map();

app.get('/data/:id', async (req, res) => {
  if (cache.has(req.params.id)) {
    return res.json(cache.get(req.params.id));
  }
  const data = await fetchData(req.params.id);
  cache.set(req.params.id, data);  // Unbounded growth = memory leak
  res.json(data);
});
```

### GOOD

```typescript
// LRU cache with size limit
import { LRUCache } from 'lru-cache';

const cache = new LRUCache<string, any>({
  max: 500,           // Max 500 entries
  maxSize: 50_000_000, // Max 50MB
  sizeCalculation: (value) => JSON.stringify(value).length,
  ttl: 1000 * 60 * 5  // 5 minute TTL
});

// Bounded arrays
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

### BAD

```typescript
// Loading entire file into memory
const content = await fs.readFile('huge-file.csv');
processCSV(content.toString());
```

### GOOD

```typescript
// Stream processing
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

## Summary

1. **Avoid nested quantifiers** in regex - use re2 for user input
2. **Use async APIs** - never block the event loop
3. **Use execFile not exec** - avoid shell injection
4. **Set resource limits** - bounded caches, max sizes
5. **Handle all errors** - uncaughtException, unhandledRejection
6. **Stream large data** - don't load huge files into memory
7. **Limit HTTP/2** - streams, sessions, frame sizes
8. **Safe buffers** - always alloc with fill, check bounds
