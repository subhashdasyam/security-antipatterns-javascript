# Security Anti-Patterns for JavaScript

AI coding agents don't think about security. They generate code that works, ship it, and move on. This skill makes them paranoid - in a good way.

## The problem

Here's what happens when you ask an AI to build an API endpoint:

```javascript
// AI-generated code - compiles fine, fails audit
app.get('/user/:id', async (req, res) => {
  const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(user);
});
```

No input validation. SQL injection. No auth check. The AI optimized for "fewest lines of code" instead of "won't get hacked."

This skill intercepts those patterns and fixes them.

## What it catches

11 modules covering OWASP Top 10 and JavaScript-specific issues:

| Module | What it prevents |
|--------|------------------|
| injection.md | SQL injection, command injection, NoSQL injection |
| xss-output.md | Cross-site scripting, missing output encoding |
| auth-access.md | Broken access control, BOLA, session issues |
| crypto-secrets.md | Weak hashing, hardcoded API keys, Math.random() for tokens |
| input-validation.md | Missing zod/yup validation, file upload attacks |
| prototype-pollution.md | Object.assign attacks, deep merge vulnerabilities |
| typescript-safety.md | Type coercion bugs, runtime validation gaps |
| nextjs-security.md | Middleware bypass, Server Actions pitfalls, RSC issues |
| api-infra.md | Missing rate limits, CORS misconfiguration, security headers |
| dependencies.md | Supply chain attacks, typosquatting |
| nodejs-runtime.md | ReDoS, event loop blocking, child_process dangers |

## The short version

- Never concatenate strings into queries. Use parameterized queries or an ORM.
- Never `Math.random()` for tokens. Use `crypto.randomUUID()`.
- Never trust middleware alone for auth. Check ownership in the handler.
- Always validate at API boundaries with zod or similar.
- Never `eval()` or `new Function()` with user input.

The skill has code examples showing what breaks and what doesn't.

## Supported platforms

| Platform | Status |
|----------|--------|
| Claude Code | Works |
| OpenAI Codex | Works |
| Google Antigravity | Works |
| Warp | Works |
| VS Code Copilot | Works |

This skill follows the [Agent Skills open standard](https://agentskills.io/). Works with any compatible AI tool.

## Installation

### Claude Code

Clone to your skills directory:

```bash
git clone https://github.com/subhashdasyam/security-antipatterns-javascript ~/.claude/skills/security-antipatterns-javascript
```

Or clone to `.claude/skills/` in a specific project.

### OpenAI Codex CLI

```bash
mkdir -p ~/.codex/skills
ln -s $(pwd) ~/.codex/skills/security-antipatterns-javascript
```

### Google Antigravity

```bash
mkdir -p ~/.antigravity/skills
ln -s $(pwd) ~/.antigravity/skills/security-antipatterns-javascript
```

### Warp Terminal

Copy to `~/.warp/skills/` or configure skill path in settings.

### VS Code Copilot

Copy skill folder to `.github/skills/` in your project.

### Other tools

Symlink or copy this folder to your tool's skills directory. Standard format - it should just work.

## When it activates

Kicks in when you're generating:

- Express or Fastify routes
- Next.js API routes or Server Actions
- Database queries (Prisma, Drizzle, raw SQL, MongoDB)
- Authentication logic
- File upload handlers
- Anything touching user input

## License

MIT
