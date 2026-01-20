# Authentication and Access Control

**CWE:** CWE-287 (Auth), CWE-384 (Session Fixation), CWE-862 (Missing Auth), CWE-863 (Incorrect Auth)
**OWASP API:** API1 (BOLA), API2 (Broken Auth), API3 (Object Property Auth), API5 (BFLA)

## BOLA (Broken Object Level Authorization)

```typescript
// ❌ BAD: No ownership verification
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const order = await prisma.order.findUnique({ where: { id: params.id } });
  return Response.json(order); // Anyone can access any order!
}

// ✅ GOOD: Verify ownership
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('Unauthorized', { status: 401 });

  const order = await prisma.order.findUnique({
    where: {
      id: params.id,
      userId: session.user.id  // Scope to user's orders only
    }
  });
  if (!order) return new Response('Not found', { status: 404 });
  return Response.json(order);
}
```

## BFLA (Broken Function Level Authorization)

```typescript
// ❌ BAD: Role check only on frontend
// Frontend: {user.role === 'admin' && <DeleteButton />}
// Backend: No role check at all

// ❌ BAD: Trusting client-sent role
export async function DELETE(req: Request) {
  const { role } = await req.json();
  if (role === 'admin') { /* delete */ } // User controls the role!
}

// ✅ GOOD: Server-side role verification
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('Unauthorized', { status: 401 });

  // Get role from database, not from request
  const user = await prisma.user.findUnique({ where: { id: session.user.id } });
  if (user?.role !== 'admin') return new Response('Forbidden', { status: 403 });

  await prisma.user.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
```

## JWT Security

```typescript
// ❌ BAD: Weak secret, no expiry
const token = jwt.sign({ userId }, 'secret123');

// ❌ BAD: Algorithm confusion vulnerability
const decoded = jwt.verify(token, secret); // Accepts 'none' algorithm!

// ✅ GOOD: Strong secret, short expiry, explicit algorithm
const token = jwt.sign(
  { userId, type: 'access' },
  process.env.JWT_SECRET!, // 256-bit+ secret
  {
    expiresIn: '15m',
    algorithm: 'HS256'
  }
);

// ✅ GOOD: Verify with explicit algorithms
const decoded = jwt.verify(token, process.env.JWT_SECRET!, {
  algorithms: ['HS256'] // Prevent algorithm switching
});
```

## Session Security

```typescript
// ❌ BAD: Session fixation - reusing session after login
app.post('/login', (req, res) => {
  if (validCredentials) {
    req.session.userId = user.id; // Same session ID!
  }
});

// ✅ GOOD: Regenerate session on auth state change
app.post('/login', (req, res) => {
  if (validCredentials) {
    req.session.regenerate((err) => { // New session ID
      req.session.userId = user.id;
      req.session.save();
    });
  }
});

// ✅ GOOD: NextAuth handles session regeneration automatically
// Use getServerSession for server-side auth checks
import { getServerSession } from 'next-auth/next';
const session = await getServerSession(authOptions);
```

## NextAuth Configuration

```typescript
// ✅ GOOD: Secure NextAuth config
export const authOptions: NextAuthOptions = {
  providers: [/* ... */],
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    jwt: async ({ token, user }) => {
      if (user) {
        token.id = user.id;
        token.role = user.role; // Include role in token
      }
      return token;
    },
    session: async ({ session, token }) => {
      session.user.id = token.id;
      session.user.role = token.role;
      return session;
    }
  }
};
```

## Defense in Depth

```typescript
// ❌ BAD: Auth only in middleware
// middleware.ts
export function middleware(req) {
  if (!req.cookies.get('session')) {
    return NextResponse.redirect('/login');
  }
}

// ✅ GOOD: Verify in both middleware AND route handlers
// middleware.ts - First layer
export function middleware(req) {
  const session = req.cookies.get('session');
  if (!session) return NextResponse.redirect('/login');
}

// app/api/protected/route.ts - Second layer
export async function GET(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('Unauthorized', { status: 401 });
  // Proceed with verified session
}
```

## Key Principles

1. **Always verify ownership** - Include userId in WHERE clauses
2. **Check roles server-side** - Never trust client-sent roles
3. **Regenerate sessions** on authentication state changes
4. **Use short-lived tokens** with refresh token rotation
5. **Defense in depth** - Validate auth at multiple layers
