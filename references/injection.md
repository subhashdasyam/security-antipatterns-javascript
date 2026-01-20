# Injection Vulnerabilities

**CWE:** CWE-89 (SQL), CWE-78 (OS Command), CWE-90 (LDAP), CWE-943 (NoSQL), CWE-1336 (Template)
**OWASP:** A03:2021 Injection

## SQL Injection

```typescript
// ❌ BAD: String concatenation
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE email = '${email}'`
);

// ❌ BAD: Template literal in raw query
const result = await db.execute(`SELECT * FROM orders WHERE id = ${orderId}`);

// ✅ GOOD: Parameterized query
const users = await prisma.$queryRaw`
  SELECT * FROM users WHERE email = ${email}
`;

// ✅ GOOD: Use ORM methods (automatically parameterized)
const users = await prisma.user.findMany({
  where: { email }
});

// ✅ GOOD: Drizzle ORM
const users = await db.select().from(users).where(eq(users.email, email));
```

## Command Injection

```typescript
// ❌ BAD: exec with user input
import { exec } from 'child_process';
exec(`convert ${userFilename} output.png`); // Shell injection!

// ❌ BAD: String concatenation in command
exec(`git clone ${repoUrl}`);

// ✅ GOOD: execFile with argument array (no shell)
import { execFile } from 'child_process';
execFile('convert', [userFilename, 'output.png']);

// ✅ GOOD: Validate input + execFile
const allowedRepos = ['repo1', 'repo2'];
if (!allowedRepos.includes(repoName)) throw new Error('Invalid repo');
execFile('git', ['clone', `https://github.com/org/${repoName}.git`]);
```

## NoSQL Injection (MongoDB)

```typescript
// ❌ BAD: Direct user input in query
const user = await collection.findOne({
  username: req.body.username,  // Could be { $gt: "" }
  password: req.body.password
});

// ✅ GOOD: Validate types with zod
const loginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(8)
});
const { username, password } = loginSchema.parse(req.body);
const user = await collection.findOne({ username, password: hashedPassword });

// ✅ GOOD: Mongoose with schema (enforces types)
const user = await User.findOne({ username }).exec();
```

## Template Injection

```typescript
// ❌ BAD: eval or Function constructor with user input
const result = eval(userExpression);
const fn = new Function('data', userCode);

// ❌ BAD: Dynamic require/import
const module = require(userInput);

// ✅ GOOD: Use sandboxed template engines
import Handlebars from 'handlebars';
const template = Handlebars.compile(trustedTemplate);
const html = template({ name: userInput }); // Data is escaped

// ✅ GOOD: Predefined operations only
const operations = {
  add: (a, b) => a + b,
  multiply: (a, b) => a * b
};
const result = operations[validatedOp]?.(a, b);
```

## LDAP Injection

```typescript
// ❌ BAD: Unescaped user input in LDAP filter
const filter = `(uid=${username})`;

// ✅ GOOD: Escape special characters
function escapeLDAP(str: string): string {
  return str.replace(/[\\*()"\0]/g, c => '\\' + c.charCodeAt(0).toString(16));
}
const filter = `(uid=${escapeLDAP(username)})`;
```

## Key Principles

1. **Never concatenate user input** into queries/commands
2. **Use parameterized queries** or ORM methods
3. **Validate input types** before use (zod/yup)
4. **Allowlist over denylist** for dynamic values
5. **Use execFile, not exec** for child processes
