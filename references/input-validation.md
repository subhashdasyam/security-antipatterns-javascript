# Input Validation

**CWE:** CWE-20 (Improper Validation), CWE-434 (Unrestricted Upload), CWE-22 (Path Traversal), CWE-915 (Mass Assignment)
**OWASP:** A03:2021 Injection, API3:2023 Broken Object Property Level Authorization

## Missing Validation

```typescript
// ❌ BAD: Using req.body directly
export async function POST(req: Request) {
  const { email, age, role } = await req.json();
  await prisma.user.create({ data: { email, age, role } }); // No validation!
}

// ❌ BAD: Trusting query params
const page = parseInt(req.query.page); // Could be NaN, negative, huge
const limit = parseInt(req.query.limit);

// ✅ GOOD: Zod validation
import { z } from 'zod';

const createUserSchema = z.object({
  email: z.string().email().max(255),
  age: z.number().int().min(0).max(150),
  name: z.string().min(1).max(100)
  // Note: 'role' is NOT included - prevent privilege escalation
});

export async function POST(req: Request) {
  const body = await req.json();
  const validated = createUserSchema.parse(body); // Throws on invalid

  await prisma.user.create({ data: validated });
}

// ✅ GOOD: Pagination with defaults and limits
const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20)
});

const { page, limit } = paginationSchema.parse(req.query);
```

## Mass Assignment

```typescript
// ❌ BAD: Spreading entire request body
export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const data = await req.json();
  await prisma.user.update({
    where: { id: params.id },
    data // User could send: { role: 'admin', isVerified: true }
  });
}

// ❌ BAD: Object.fromEntries without filtering
const data = Object.fromEntries(formData);
await db.update(data);

// ✅ GOOD: Explicit allowlist with zod
const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  bio: z.string().max(500).optional()
  // role, isAdmin, isVerified NOT included
});

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('Unauthorized', { status: 401 });

  const body = await req.json();
  const validated = updateUserSchema.parse(body);

  await prisma.user.update({
    where: { id: params.id, userId: session.user.id }, // Ownership check
    data: validated
  });
}
```

## Path Traversal

```typescript
// ❌ BAD: Direct path join with user input
import path from 'path';
import fs from 'fs/promises';

const filePath = path.join('/uploads', userFilename);
const content = await fs.readFile(filePath); // ../../../etc/passwd works!

// ❌ BAD: Insufficient validation
if (!userFilename.includes('..')) { /* still vulnerable */ }

// ✅ GOOD: Validate resolved path is within allowed directory
const UPLOAD_DIR = '/var/app/uploads';

async function safeReadFile(userFilename: string): Promise<Buffer> {
  // Resolve to absolute path
  const resolvedPath = path.resolve(UPLOAD_DIR, userFilename);

  // Verify path is within allowed directory
  if (!resolvedPath.startsWith(UPLOAD_DIR + path.sep)) {
    throw new Error('Invalid file path');
  }

  // Additional: check file exists and is a file (not directory)
  const stat = await fs.stat(resolvedPath);
  if (!stat.isFile()) {
    throw new Error('Not a file');
  }

  return fs.readFile(resolvedPath);
}
```

## File Upload Validation

```typescript
// ❌ BAD: No validation on uploads
export async function POST(req: Request) {
  const formData = await req.formData();
  const file = formData.get('file') as File;
  await writeFile(`/uploads/${file.name}`, Buffer.from(await file.arrayBuffer()));
}

// ✅ GOOD: Comprehensive upload validation
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB
const UPLOAD_DIR = '/var/app/uploads'; // Outside webroot

const uploadSchema = z.object({
  name: z.string().regex(/^[a-zA-Z0-9_-]+\.(jpg|jpeg|png|webp)$/i),
  size: z.number().max(MAX_SIZE),
  type: z.enum(ALLOWED_TYPES as [string, ...string[]])
});

export async function POST(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('Unauthorized', { status: 401 });

  const formData = await req.formData();
  const file = formData.get('file') as File;

  // Validate metadata
  uploadSchema.parse({ name: file.name, size: file.size, type: file.type });

  // Generate safe filename
  const ext = path.extname(file.name).toLowerCase();
  const safeFilename = `${crypto.randomUUID()}${ext}`;
  const filePath = path.join(UPLOAD_DIR, safeFilename);

  // Verify magic bytes match claimed type
  const buffer = Buffer.from(await file.arrayBuffer());
  if (!verifyMagicBytes(buffer, file.type)) {
    throw new Error('File type mismatch');
  }

  await writeFile(filePath, buffer);
  return Response.json({ filename: safeFilename });
}
```

## Type Coercion Attacks

```typescript
// ❌ BAD: Trusting typeof for validation
if (typeof req.body.isAdmin === 'boolean') {
  // Could pass: { isAdmin: { toString: () => 'true' } }
}

// ✅ GOOD: Strict zod validation
const schema = z.object({
  isAdmin: z.boolean().optional() // Strictly validates boolean type
});
```

## Key Principles

1. **Validate ALL external input** at API boundaries with zod
2. **Allowlist fields explicitly** - Never spread request body to DB
3. **Resolve and verify paths** - Check they're within allowed directories
4. **Validate uploads** - Extension, MIME type, size, and magic bytes
5. **Generate safe filenames** - Use UUIDs, not user-provided names
