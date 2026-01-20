# Next.js Security

**CVE:** CVE-2025-29927 (Middleware Auth Bypass), CVE-2025-66478 (RSC RCE), CVE-2025-55182 (React2Shell)
**OWASP API:** API8:2023 (SSRF), A03:2021 (Injection)

See also: [rsc-security.md](rsc-security.md) for RSC-specific deserialization and DoS attacks.

## Middleware Auth Bypass (CVE-2025-29927)

The `x-middleware-subrequest` header can bypass middleware in vulnerable Next.js versions. NEVER rely solely on middleware for authentication.

### BAD

```typescript
// Auth ONLY in middleware
// middleware.ts
export function middleware(request: NextRequest) {
  const token = request.cookies.get('session');
  if (!token && request.nextUrl.pathname.startsWith('/api/')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
  return NextResponse.next();
}
// Route handlers have no auth check - vulnerable to bypass!

// No header checks
// Attacker sends x-middleware-subrequest: 1 to bypass

// Vulnerable versions
// package.json: "next": "14.2.24"  // Pre-patch

// Public admin paths
if (req.url.startsWith('/admin')) authCheck();  // Bypassed

// No defense in depth
// Route has no secondary auth

// Edge runtime exposure
// vercel.json: { "runtime": "edge" }  // Wider attack surface

// Custom headers trusted
const bypass = req.headers.get('x-custom'); if (bypass) skipAuth();

// No logging
// Silent bypasses

// Long sessions
session.maxAge = 30 * 24 * 3600;  // Persistent vuln

// No IP binding
// Sessions work from anywhere
```

### GOOD

```typescript
// Defense in depth - verify in route handlers too
// middleware.ts - First layer (can be bypassed)
export function middleware(request: NextRequest) {
  // Block bypass header
  if (request.headers.has('x-middleware-subrequest')) {
    return new NextResponse('Forbidden', { status: 403 });
  }
  const token = request.cookies.get('session');
  if (!token && request.nextUrl.pathname.startsWith('/api/')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
  return NextResponse.next();
}

// app/api/users/route.ts - Second layer (mandatory)
export async function GET(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  // Proceed with authenticated request
}

// Patch to fixed version
// "next": "^14.2.25"

// WAF rules
// Cloudflare: block if header x-middleware-subrequest

// Log attempts
console.warn('Bypass attempt:', req.headers);

// Short sessions
session.maxAge = 3600;

// IP/session binding
if (session.ip !== req.ip) invalidate();

// Multi-factor in middleware
if (!session.mfa) redirect('/mfa');

// Role checks
if (session.role !== 'admin') forbidden();

// Canary monitoring
// Deploy canary, watch for exploits
```

## Server Actions Security

### BAD

```typescript
// No validation in Server Action
'use server';

async function updateProfile(formData: FormData) {
  const data = Object.fromEntries(formData);
  await prisma.user.update({ data }); // Mass assignment + no auth!
}

// Trusting hidden form fields
async function deleteItem(formData: FormData) {
  const userId = formData.get('userId'); // User can modify this!
  await prisma.item.delete({ where: { userId } });
}

// No auth
'use server';
async function update(data) { prisma.update(data); }

// Mass assignment
const updates = Object.fromEntries(formData);

// No validation
const id = formData.get('id');  // Injection

// File ops without checks
fs.writeFile(userPath, content);  // Traversal

// Dynamic SQL
prisma.$queryRaw`UPDATE SET ${userCol} = ${val}`;

// Exec in actions
exec(userCmd);

// No rate limit
// Spam actions crash

// Huge data
const big = formData.get('big'); process(big);

// No CSRF
// Actions run cross-origin

// Exposed internals
export function internal() { /* secrets */ }
```

### GOOD

```typescript
// Validate + authorize in Server Action
'use server';

import { z } from 'zod';
import { getServerSession } from 'next-auth/next';

const updateProfileSchema = z.object({
  name: z.string().min(1).max(100),
  bio: z.string().max(500).optional()
});

async function updateProfile(formData: FormData) {
  // 1. Authenticate
  const session = await getServerSession(authOptions);
  if (!session) throw new Error('Unauthorized');

  // 2. Validate input
  const validated = updateProfileSchema.parse({
    name: formData.get('name'),
    bio: formData.get('bio')
  });

  // 3. Scope to authenticated user
  await prisma.user.update({
    where: { id: session.user.id }, // Use session, not form data
    data: validated
  });
}

// Explicit fields
const updates = { name: formData.get('name') };

// Zod
const schema = z.object({ id: z.string().uuid() });
schema.parse(data);

// Path resolution
const safePath = path.resolve(base, userFile);
if (!safePath.startsWith(base)) invalid();

// Parameterized
prisma.update({ where: { id }, data: { col: val } });

// No exec
// Use safe alternatives

// Limit middleware
app.use(rateLimit({ max: 5 }));

// Size caps
if (big.length > 1e6) tooLarge();

// CSRF in forms
<input type="hidden" name="csrf" value={token} />

// Private functions
async function internal() {}  // No export
```

## Server Components Data Exposure

### BAD

```typescript
// Passing sensitive data to Client Component
// app/dashboard/page.tsx (Server Component)
async function DashboardPage() {
  const user = await prisma.user.findUnique({
    where: { id: session.user.id }
  }); // Includes passwordHash, internal fields

  return <ClientDashboard user={user} />; // All data serialized to client!
}

// Full user object
return <ClientComp user={prisma.user.find({})} />;  // Leaks hash

// Env vars in components
const secret = process.env.SECRET;  // Serialized to client

// DB queries in client
'use client'; await prisma.find();  // Exposed

// No select
prisma.findMany();  // All fields

// Inline secrets
return <div>{process.env.DB_URL}</div>;

// Props with sensitives
<Props sensitive={true} />;

// Global state leak
global.secret = 'leak';  // Persists

// Cookie serialization
return <Comp cookies={req.cookies} />;

// Headers to client
const headers = req.headers;  // UA, IP leak

// No sanitization
return <Comp data={rawDB} />;
```

### GOOD

```typescript
// Create DTO with only needed fields
// app/dashboard/page.tsx
async function DashboardPage() {
  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: {
      id: true,
      name: true,
      email: true,
      avatarUrl: true
      // passwordHash, role, internalNotes NOT selected
    }
  });

  return <ClientDashboard user={user} />;
}

// Alternative: explicit DTO mapping
type UserDTO = { id: string; name: string; email: string };

function toUserDTO(user: User): UserDTO {
  return { id: user.id, name: user.name, email: user.email };
}

// DTOs
type SafeUser = Pick<User, 'id' | 'name'>;
return <ClientComp user={toSafeUser(dbUser)} />;

// Server-only env
// Access only in server files

// Server components only
// No 'use client' for DB

// Select fields
prisma.findMany({ select: { id: true, name: true } });

// Constants
const secret = getEnv('SECRET');  // Server-side

// Sanitize props
<Props safe={filter(sensitive)} />;

// No globals
// Use locals

// No cookies to client
// Process server-side

// Filter headers
const safeHeaders = { 'content-type': headers['content-type'] };

// Sanitize function
function sanitize(data) { delete data.password; return data; }
```

## SSRF in Redirects

### BAD

```typescript
// User-controlled redirect URL
import { redirect } from 'next/navigation';

async function handleLogin(formData: FormData) {
  // ... auth logic
  const returnUrl = formData.get('returnUrl') as string;
  redirect(returnUrl); // Could redirect to attacker's site!
}

// Open redirect in API route
export async function GET(request: Request) {
  const url = new URL(request.url);
  const target = url.searchParams.get('redirect');
  return Response.redirect(target!);
}

// No origin check
const url = new URL(target);

// Follow redirects
fetch(target, { redirect: 'follow' });

// Internal URLs
redirect('http://localhost/admin');

// Data URIs
redirect('data:text/plain,evil');

// No protocol limit
// Allows file://

// Query param injection
redirect(`/page?${userQuery}`);

// Header redirects
res.set('Location', userUrl);

// Open in actions
'use server'; redirect(formData.get('url'));

// No base
new URL(target);  // Relative evil
```

### GOOD

```typescript
// Validate redirect is internal
function safeRedirect(url: string, baseUrl: string): string {
  try {
    const parsed = new URL(url, baseUrl);
    // Only allow same-origin redirects
    if (parsed.origin !== new URL(baseUrl).origin) {
      return '/'; // Default to home on invalid redirect
    }
    return parsed.pathname + parsed.search;
  } catch {
    return '/';
  }
}

async function handleLogin(formData: FormData) {
  const returnUrl = formData.get('returnUrl') as string || '/';
  const safeUrl = safeRedirect(returnUrl, process.env.NEXTAUTH_URL!);
  redirect(safeUrl);
}

// Manual follow
if (res.redirected) validate(res.url);

// Block internal
if (u.host === 'localhost') invalid();

// No data:
if (u.protocol === 'data:') invalid();

// Only http/https
if (!['http:', 'https:'].includes(u.protocol)) invalid();

// Sanitize query
const safeQuery = pick(userQuery, allowedParams);

// Validate location
if (!isSafeUrl(userUrl)) defaultRedirect();

// Form validation
const schema = z.object({ url: z.string().url() });

// Base always
new URL(target, process.env.BASE_URL);
```

## API Route Handler Patterns

```typescript
// GOOD: Complete secure API route template
import { getServerSession } from 'next-auth/next';
import { z } from 'zod';
import { NextResponse } from 'next/server';

const requestSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().max(10000)
});

export async function POST(request: Request) {
  try {
    // 1. Auth check (defense in depth)
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // 2. Input validation
    const body = await request.json();
    const validated = requestSchema.parse(body);

    // 3. Business logic with ownership scope
    const post = await prisma.post.create({
      data: {
        ...validated,
        authorId: session.user.id // Scope to user
      }
    });

    return NextResponse.json(post, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: 'Validation failed' }, { status: 400 });
    }
    console.error('POST /api/posts error:', error);
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
```

## Security Headers in next.config.js

```typescript
// next.config.js
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  }
};
```

## Summary

1. **Never trust middleware alone** - Always verify auth in route handlers
2. **Validate Server Actions** - Auth + input validation + ownership scope
3. **Create DTOs** - Never pass full DB objects to Client Components
4. **Validate redirects** - Only allow same-origin URLs
5. **Set security headers** - X-Frame-Options, CSP, etc.
6. **Patch promptly** - Monitor CVEs and update Next.js
7. **Rate limit sensitive paths** - Especially Server Actions
8. **See rsc-security.md** - For RSC deserialization and DoS attacks
