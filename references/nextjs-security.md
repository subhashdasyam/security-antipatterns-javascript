# Next.js Security

**CVE:** CVE-2025-29927 (Middleware Auth Bypass)
**OWASP API:** API8:2023 (SSRF)

## Middleware Auth Bypass (CVE-2025-29927)

The `x-middleware-subrequest` header can bypass middleware in vulnerable Next.js versions. NEVER rely solely on middleware for authentication.

```typescript
// ❌ BAD: Auth ONLY in middleware
// middleware.ts
export function middleware(request: NextRequest) {
  const token = request.cookies.get('session');
  if (!token && request.nextUrl.pathname.startsWith('/api/')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
  return NextResponse.next();
}
// Route handlers have no auth check - vulnerable to bypass!

// ✅ GOOD: Defense in depth - verify in route handlers too
// middleware.ts - First layer (can be bypassed)
export function middleware(request: NextRequest) {
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
```

## Server Actions Security

```typescript
// ❌ BAD: No validation in Server Action
'use server';

async function updateProfile(formData: FormData) {
  const data = Object.fromEntries(formData);
  await prisma.user.update({ data }); // Mass assignment + no auth!
}

// ❌ BAD: Trusting hidden form fields
async function deleteItem(formData: FormData) {
  const userId = formData.get('userId'); // User can modify this!
  await prisma.item.delete({ where: { userId } });
}

// ✅ GOOD: Validate + authorize in Server Action
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
```

## Server Components Data Exposure

```typescript
// ❌ BAD: Passing sensitive data to Client Component
// app/dashboard/page.tsx (Server Component)
async function DashboardPage() {
  const user = await prisma.user.findUnique({
    where: { id: session.user.id }
  }); // Includes passwordHash, internal fields

  return <ClientDashboard user={user} />; // All data serialized to client!
}

// ✅ GOOD: Create DTO with only needed fields
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
```

## SSRF in Redirects

```typescript
// ❌ BAD: User-controlled redirect URL
import { redirect } from 'next/navigation';

async function handleLogin(formData: FormData) {
  // ... auth logic
  const returnUrl = formData.get('returnUrl') as string;
  redirect(returnUrl); // Could redirect to attacker's site!
}

// ❌ BAD: Open redirect in API route
export async function GET(request: Request) {
  const url = new URL(request.url);
  const target = url.searchParams.get('redirect');
  return Response.redirect(target!);
}

// ✅ GOOD: Validate redirect is internal
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
```

## API Route Handler Patterns

```typescript
// ✅ GOOD: Complete secure API route template
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

## Key Principles

1. **Never trust middleware alone** - Always verify auth in route handlers
2. **Validate Server Actions** - Auth + input validation + ownership scope
3. **Create DTOs** - Never pass full DB objects to Client Components
4. **Validate redirects** - Only allow same-origin URLs
5. **Set security headers** - X-Frame-Options, CSP, etc.
