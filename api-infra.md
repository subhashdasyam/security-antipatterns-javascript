# API and Infrastructure Security

**CWE:** CWE-770 (Resource Allocation), CWE-346 (Origin Validation), CWE-200 (Info Exposure), CWE-16 (Config)
**OWASP API:** API4 (Unrestricted Resource Consumption), API6 (Sensitive Business Flow), API7 (Misconfig)

## Rate Limiting

```typescript
// ❌ BAD: No rate limiting on sensitive endpoints
export async function POST(req: Request) {
  const { email, password } = await req.json();
  // Attacker can brute force passwords
  return await attemptLogin(email, password);
}

// ✅ GOOD: Rate limiting with Upstash (serverless-friendly)
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'), // 5 requests per minute
  analytics: true
});

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const { success, limit, reset, remaining } = await ratelimit.limit(ip);

  if (!success) {
    return new Response('Too many requests', {
      status: 429,
      headers: {
        'X-RateLimit-Limit': limit.toString(),
        'X-RateLimit-Remaining': remaining.toString(),
        'X-RateLimit-Reset': reset.toString()
      }
    });
  }

  // Proceed with login
}

// ✅ GOOD: Express rate limiting
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts',
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/login', loginLimiter, loginHandler);
```

## CORS Configuration

```typescript
// ❌ BAD: Wildcard CORS
app.use(cors({ origin: '*' })); // Any site can make requests!

// ❌ BAD: Reflecting origin without validation
app.use(cors({
  origin: (origin, callback) => callback(null, origin) // Reflects any origin
}));

// ✅ GOOD: Allowlist specific origins
const allowedOrigins = [
  'https://myapp.com',
  'https://admin.myapp.com'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// ✅ GOOD: Next.js API route CORS
export async function OPTIONS(request: Request) {
  return new Response(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': 'https://myapp.com',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
```

## Response Data Filtering

```typescript
// ❌ BAD: Returning full database objects
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await prisma.user.findUnique({ where: { id: params.id } });
  return Response.json(user); // Includes passwordHash, internalNotes, etc!
}

// ❌ BAD: Exposing all fields in list endpoints
const users = await prisma.user.findMany();
return Response.json(users); // All user data to anyone

// ✅ GOOD: Select only needed fields
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await prisma.user.findUnique({
    where: { id: params.id },
    select: {
      id: true,
      name: true,
      avatarUrl: true,
      createdAt: true
      // passwordHash, email, role NOT included
    }
  });
  return Response.json(user);
}

// ✅ GOOD: DTO transformation
type PublicUser = { id: string; name: string; avatarUrl: string | null };

function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    name: user.name,
    avatarUrl: user.avatarUrl
  };
}
```

## Error Handling

```typescript
// ❌ BAD: Exposing internal errors
export async function GET(req: Request) {
  try {
    return await fetchData();
  } catch (error) {
    return Response.json({
      error: error.message,  // "ECONNREFUSED 10.0.0.5:5432" - exposes internal IP!
      stack: error.stack     // Full stack trace - code paths exposed
    }, { status: 500 });
  }
}

// ✅ GOOD: Generic client errors, detailed server logs
export async function GET(req: Request) {
  try {
    return await fetchData();
  } catch (error) {
    // Log full details server-side
    console.error('GET /api/data failed:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      timestamp: new Date().toISOString()
    });

    // Generic response to client
    return Response.json(
      { error: 'An unexpected error occurred' },
      { status: 500 }
    );
  }
}
```

## Security Headers

```typescript
// ✅ GOOD: Express with Helmet
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' }
}));

// ✅ GOOD: Next.js middleware security headers
export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('X-XSS-Protection', '1; mode=block');

  return response;
}
```

## Request Size Limits

```typescript
// ✅ GOOD: Limit request body size
import express from 'express';

app.use(express.json({ limit: '100kb' })); // Prevent DoS via large payloads
app.use(express.urlencoded({ limit: '100kb', extended: true }));

// ✅ GOOD: Next.js route segment config
export const config = {
  api: {
    bodyParser: {
      sizeLimit: '100kb'
    }
  }
};
```

## Key Principles

1. **Rate limit sensitive endpoints** - Login, registration, password reset
2. **Allowlist CORS origins** - Never use wildcard in production
3. **Filter response data** - Return only necessary fields
4. **Generic client errors** - Log details server-side only
5. **Set security headers** - Use Helmet or manual headers
6. **Limit request sizes** - Prevent resource exhaustion
