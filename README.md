# Security Anti-Patterns for JavaScript

A skill for AI coding assistants that stops you from writing insecure JavaScript, TypeScript, and Next.js code.

## Supported platforms

| Platform | Status |
|----------|--------|
| Claude Code | Supported |
| Antigravity | TODO |
| Codex | TODO |

## What it does

When you're writing code that touches databases, handles user input, or deals with authentication, this skill kicks in and steers you away from common security mistakes. It covers the OWASP Top 10 and then some.

## Installation

### Claude Code

Clone to your personal skills directory:

```bash
git clone https://github.com/subhashdasyam/security-antipatterns-javascript ~/.claude/skills/security-antipatterns-javascript
```

For project-specific use, clone to `.claude/skills/` in your repo instead.

### Other platforms

Instructions coming once support is added.

## Coverage

The skill includes 11 modules:

- **injection.md** - SQL injection, command injection, NoSQL injection
- **xss-output.md** - Cross-site scripting and output encoding
- **auth-access.md** - Broken access control, BOLA, session management
- **crypto-secrets.md** - Password hashing, secrets management, encryption
- **input-validation.md** - Schema validation, file uploads, path traversal
- **prototype-pollution.md** - JavaScript-specific prototype attacks
- **typescript-safety.md** - Type coercion bugs and runtime validation gaps
- **nextjs-security.md** - Middleware bypass, Server Actions, RSC pitfalls
- **api-infra.md** - Rate limiting, CORS, security headers
- **dependencies.md** - Supply chain attacks, typosquatting
- **nodejs-runtime.md** - ReDoS, event loop blocking, child process safety

## The short version

Don't concatenate strings into SQL queries. Don't use `Math.random()` for tokens. Don't trust middleware alone for auth. Always check that users own what they're trying to access. Validate everything at API boundaries with zod or similar.

The skill has the full details with code examples showing what not to do and what to do instead.

## When it activates

Any time you're generating:
- Express or Fastify routes
- Next.js API routes or Server Actions
- Database queries (Prisma, Drizzle, raw SQL, MongoDB)
- Authentication logic
- File upload handlers
- Anything that touches user input

## License

MIT
