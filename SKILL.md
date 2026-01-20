---
name: security-antipatterns-javascript
description: Code generation guard for Node.js/TypeScript/Next.js - prevents OWASP Top 10 vulnerabilities while writing code
version: "1.0.0"
allowed-tools: "Read"
---

# Security Anti-Patterns Guard for Node.js/TypeScript/Next.js

## When to Activate

Activate this skill when generating ANY code involving:
- Node.js backend code
- TypeScript applications
- Next.js (App Router or Pages Router)
- Express/Fastify APIs
- Database queries (Prisma, Drizzle, raw SQL, MongoDB)
- Authentication/authorization logic
- File uploads or user input handling
- API endpoints or Server Actions

## Critical Rules (Top 10)

1. **NEVER** use string concatenation for SQL/NoSQL queries - use parameterized queries or ORM methods
2. **NEVER** use `dangerouslySetInnerHTML` with user input without DOMPurify sanitization
3. **ALWAYS** verify resource ownership (BOLA) - `where: { id, userId: session.user.id }`
4. **ALWAYS** validate ALL external input with zod/yup at API boundaries
5. **NEVER** hardcode secrets - use `process.env` (not `NEXT_PUBLIC_*` for secrets)
6. **ALWAYS** use `crypto.randomBytes()` or `crypto.randomUUID()` - never `Math.random()` for security
7. **NEVER** trust middleware alone for auth - verify in route handlers (defense in depth)
8. **ALWAYS** hash passwords with bcrypt/argon2 - never MD5/SHA1/unsalted
9. **NEVER** use `exec()` with user input - use `execFile()` with argument arrays
10. **ALWAYS** validate file uploads: extension, MIME type, size limits

## Module Index

Reference these modules for specific vulnerability patterns:

| Module | Covers | OWASP Reference |
|--------|--------|-----------------|
| [injection.md]({baseDir}/references/injection.md) | SQL, Command, NoSQL, Template, LDAP injection | A03:2021 |
| [xss-output.md]({baseDir}/references/xss-output.md) | XSS (Reflected, Stored, DOM), output encoding | A03:2021 |
| [auth-access.md]({baseDir}/references/auth-access.md) | BOLA, BFLA, auth, sessions, JWT | API1-3, API5 |
| [crypto-secrets.md]({baseDir}/references/crypto-secrets.md) | Secrets management, encryption, hashing | A02:2021 |
| [input-validation.md]({baseDir}/references/input-validation.md) | Validation, mass assignment, path traversal, uploads | A03:2021, API3 |
| [prototype-pollution.md]({baseDir}/references/prototype-pollution.md) | JS prototype pollution attacks | CWE-1321 |
| [typescript-safety.md]({baseDir}/references/typescript-safety.md) | Type safety gaps, runtime validation | CWE-843 |
| [nextjs-security.md]({baseDir}/references/nextjs-security.md) | Middleware bypass, Server Actions, RSC, SSRF | CVE-2025-29927 |
| [api-infra.md]({baseDir}/references/api-infra.md) | Rate limiting, CORS, headers, error handling | API4, API6-7 |
| [dependencies.md]({baseDir}/references/dependencies.md) | Supply chain, slopsquatting, typosquatting | A06:2021 |
| [nodejs-runtime.md]({baseDir}/references/nodejs-runtime.md) | ReDoS, event loop blocking, child processes | CWE-1333 |

## How to Use This Skill

When generating code:

1. **Identify applicable modules** based on what you're writing
2. **Reference the specific module** for detailed BAD/GOOD patterns
3. **Apply the GOOD pattern** - never generate code matching BAD patterns
4. **Verify the output** against the Critical Rules above

### Quick Reference by Task

| Writing... | Reference |
|------------|-----------|
| Database queries | {baseDir}/references/injection.md, {baseDir}/references/input-validation.md |
| API route/endpoint | {baseDir}/references/auth-access.md, {baseDir}/references/api-infra.md, {baseDir}/references/input-validation.md |
| User authentication | {baseDir}/references/auth-access.md, {baseDir}/references/crypto-secrets.md |
| Form handling | {baseDir}/references/input-validation.md, {baseDir}/references/xss-output.md |
| File operations | {baseDir}/references/input-validation.md, {baseDir}/references/nodejs-runtime.md |
| Next.js Server Actions | {baseDir}/references/nextjs-security.md, {baseDir}/references/auth-access.md |
| Third-party package usage | {baseDir}/references/dependencies.md |
| Rendering user content | {baseDir}/references/xss-output.md |
| Environment/config | {baseDir}/references/crypto-secrets.md |
| Child processes | {baseDir}/references/nodejs-runtime.md, {baseDir}/references/injection.md |

## Response Format

When this skill is active, ensure generated code:

1. Includes necessary imports (zod, bcrypt, etc.)
2. Shows the secure pattern being used
3. Includes brief comments explaining security measure if non-obvious
4. Does NOT include insecure alternatives "for reference"
