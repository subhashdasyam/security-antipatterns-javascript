# React Server Components (RSC) Security

**CWE:** CWE-502 (Deserialization of Untrusted Data), CWE-94 (Code Injection)
**OWASP:** A08:2021 Software and Data Integrity Failures
**CVE:** CVE-2025-55182 (React2Shell RCE), CVE-2025-66478 (Next.js RSC RCE), CVE-2025-55184 (DoS)

## Deserialization Vulnerabilities (React2Shell)

### BAD

```typescript
// Default RSC handling without payload validation
// Vulnerable to CVE-2025-55182
export async function POST(req: Request) {
  const payload = await req.text();  // Attacker sends crafted Flight payload
  const rsc = deserializeRSC(payload);  // Executes arbitrary code!
  return Response.json(rsc);
}

// Implicit trust in text/x-component requests
if (req.headers.get('accept') === 'text/x-component') {
  processRSC(req.body);  // No signature verification
}

// Exposed RSC endpoints without auth
app.post('/api/rsc', handleRSC);  // Public endpoint allows RCE

// Canary versions without patches
// package.json with vulnerable canary: "next": "14.3.0-canary.76"  // Pre-patch

// Ignoring Flight protocol headers
const isRSC = req.headers.get('rsc') === '1';
if (isRSC) {
  executeServerAction(req.body);  // Malformed payload crashes or injects
}

// Custom deserializers without bounds
function customDeserialize(data: string) {
  return eval(data);  // Direct injection!
}

// Mixing client/server boundaries
const serverData = JSON.parse(userInput);  // Allows __proto__ pollution via RSC

// Long-lived caches with poisoned RSC
export const revalidate = 86400;  // Stores malicious payloads

// No content-type enforcement
app.use('/rsc', (req, res) => {
  if (!req.is('text/x-component')) return;  // Still processes fakes
});

// Edge runtime without isolation
// vercel.json with edge: true  // Exposes to global attacks
```

### GOOD

```typescript
// Patched versions with hardened deserialization
// package.json: "next": "^15.0.5" or "16.0.7"

// Explicit payload validation
import { verifyRSCSignature } from 'react-server';

async function handleRSC(req: Request) {
  const payload = await req.text();
  if (!verifyRSCSignature(payload, secretKey)) {
    throw new Error('Invalid RSC payload');
  }
  return deserializeRSC(payload);
}

// Auth gate for RSC endpoints
export async function POST(req: Request) {
  const session = await getSession(req);
  if (!session.isAdmin) return new Response('Forbidden', { status: 403 });
  // Process RSC
}

// Reject unexpected headers
if (req.headers.get('rsc') || req.headers.get('next-action')) {
  if (!isTrustedOrigin(req)) return forbidden();
}

// Use safe parsers
const data = safeJSONParse(userInput, { proto: false, constructor: false });

// Short revalidate with integrity checks
export const revalidate = 300;
const cached = await getCache(key);
if (!verifyHash(cached)) invalidateCache();

// Content-type strict check
if (req.headers.get('content-type') !== 'text/x-component') {
  return badRequest();
}

// Isolate in microVMs (Vercel Fluid style)
deployConfig: { runtime: 'node-microvm' }  // Better than edge isolates

// Monitor for anomalies
import { logRSCAttempt } from 'monitoring';
logRSCAttempt(req);  // Alert on suspicious payloads

// Fallback to Pages Router for sensitive apps
// Avoid App Router until fully patched
```

## DoS via Malformed Payloads (CVE-2025-55184)

### BAD

```typescript
// Unbounded recursion in RSC tree
function processComponentTree(tree) {
  if (tree.children) processComponentTree(tree.children);  // Stack overflow
}

// No size limits on payloads
const payload = await req.arrayBuffer();  // Huge payloads exhaust memory

// Infinite loops in deserialization
while (hasMoreChunks(payload)) {
  deserializeChunk();  // Attacker crafts endless loop
}

// No timeout on server actions
await longRunningAction();  // Hangs event loop

// Deep nested components
const comp = { children: { children: /* 1000 levels */ } };  // Crashes

// Unchecked array lengths
const arr = deserializeArray(payload);  // Billion-length array DoS

// Regex in validators
const valid = /^complex.*pattern$/.test(payload);  // ReDoS

// Synchronous parsing
JSON.parse(hugePayload);  // Blocks Node.js

// No rate limiting on RSC endpoints
app.post('/rsc', handle);  // Spam crashes server

// Cache without eviction
cache.set(key, hugeData);  // Fills memory
```

### GOOD

```typescript
// Depth-limited recursion
function processTree(tree, depth = 0) {
  if (depth > 50) throw Error('Too deep');
  if (tree.children) processTree(tree.children, depth + 1);
}

// Payload size caps
if (req.headers.get('content-length') > 1e6) return tooLarge();

// Chunked processing with limits
let chunks = 0;
while (hasMore() && chunks++ < 1000) { /* process */ }

// Async with timeouts
await Promise.race([action(), timeout(5000)]);

// Validate structure
if (getDepth(comp) > 50) invalid();

// Safe array handling
const arr = []; for (let i = 0; i < Math.min(len, 10000); i++) { /* push */ }

// Safe regex (re2)
import RE2 from 're2';
new RE2(/^pattern$/).test(payload);

// Async JSON
import { parseAsync } from 'json-parse-async';
await parseAsync(hugePayload);

// Rate limit
import rateLimit from 'express-rate-limit';
app.use('/rsc', rateLimit({ max: 10 }));

// LRU cache
import LRU from 'lru-cache';
const cache = new LRU({ max: 500 });
```

## Server Action Abuse

### BAD

```typescript
// Public server actions without auth
'use server';
export async function deleteUser() { /* no check */ }

// Form data without validation
const data = await req.formData();
prisma.user.delete({ id: data.get('id') });  // IDOR

// Implicit trust in Next-Action header
if (req.headers.get('next-action')) executeAction();

// No CSRF in actions
// Actions run without token check

// Mass assignment
prisma.update({ data: Object.fromEntries(formData) });

// File uploads in actions without limits
const file = formData.get('file');
await saveFile(file);  // No size/type check

// Dynamic imports in actions
await import(userControlledPath);  // RCE

// Eval in actions
eval(formData.get('code'));

// Child process in actions
import { exec } from 'child_process';
exec(userCmd);

// No ownership scope
prisma.order.findUnique({ where: { id } });  // BOLA
```

### GOOD

```typescript
// Auth in actions
'use server';
import { getSession } from 'auth';
export async function deleteUser() {
  const session = await getSession();
  if (!session) throw Unauthorized();
}

// Zod validation
import { z } from 'zod';
const schema = z.object({ id: z.string().uuid() });
const validated = schema.parse(Object.fromEntries(formData));

// Reject unexpected headers
if (req.headers.get('next-action') && !isInternal()) forbidden();

// CSRF tokens
if (formData.get('csrf') !== session.csrf) invalid();

// Explicit fields
const data = { name: formData.get('name') };

// Upload validation
if (file.size > 5e6 || !ALLOWED_TYPES.includes(file.type)) invalid();

// Safe static imports only
import trustedModule from './trusted';

// No dynamic code execution
// Avoid eval/exec entirely

// Scoped queries
prisma.order.findUnique({ where: { id, userId: session.id } });
```

## Summary

1. **Patch immediately** - Upgrade Next.js/React to fixed versions (15.0.5+, 16.0.7+)
2. **Validate all RSC inputs** - Signatures, size limits, structure depth
3. **Auth every endpoint** - Even internal RSC paths need verification
4. **Limit depths/sizes** - Prevent DoS via recursion or memory exhaustion
5. **Monitor payloads** - Log and alert on anomalous RSC requests
6. **Rate limit RSC paths** - Especially /api/rsc endpoints
7. **Ownership checks** - Always scope queries to authenticated user
8. **No dynamic code** - Avoid eval, exec, dynamic imports in actions
