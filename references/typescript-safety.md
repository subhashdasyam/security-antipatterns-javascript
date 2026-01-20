# TypeScript Type Safety

**CWE:** CWE-843 (Type Confusion)
**TypeScript Specific**

## Critical Understanding

**TypeScript types are erased at runtime.** Type annotations provide compile-time safety but offer ZERO runtime protection. External data (API responses, user input, file contents) MUST be validated at runtime.

## The `any` Problem

```typescript
// ❌ BAD: any defeats type checking
function processData(data: any) {
  return data.user.email.toLowerCase(); // No compile errors, runtime crash
}

// ❌ BAD: Implicit any in catch blocks
try {
  await fetchData();
} catch (e) {
  console.log(e.message); // e is 'unknown' in strict mode, any otherwise
}

// ✅ GOOD: Use unknown + type guards
function processData(data: unknown) {
  if (!isValidUserData(data)) {
    throw new Error('Invalid data structure');
  }
  return data.user.email.toLowerCase(); // Now type-safe
}

function isValidUserData(data: unknown): data is { user: { email: string } } {
  return (
    typeof data === 'object' && data !== null &&
    'user' in data && typeof (data as any).user === 'object' &&
    'email' in (data as any).user && typeof (data as any).user.email === 'string'
  );
}

// ✅ GOOD: Type-safe error handling
try {
  await fetchData();
} catch (e) {
  const message = e instanceof Error ? e.message : 'Unknown error';
  console.log(message);
}
```

## Dangerous Type Assertions

```typescript
// ❌ BAD: Type assertion without validation
interface User {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

const user = apiResponse as User; // No runtime check!
if (user.role === 'admin') { /* Dangerous if apiResponse is malformed */ }

// ❌ BAD: Double assertion to bypass type system
const adminUser = data as unknown as AdminUser; // Never do this for security

// ❌ BAD: Non-null assertion
const userId = session.user!.id; // Crashes if user is null

// ✅ GOOD: Zod validation then type
import { z } from 'zod';

const UserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(['user', 'admin'])
});
type User = z.infer<typeof UserSchema>;

const user = UserSchema.parse(apiResponse); // Runtime validation + type inference
if (user.role === 'admin') { /* Safe - role was validated */ }

// ✅ GOOD: Explicit null checks
if (session?.user) {
  const userId = session.user.id;
}
```

## External Data Boundaries

```typescript
// ❌ BAD: Trusting API response types
interface ApiResponse {
  users: User[];
}

async function getUsers(): Promise<User[]> {
  const response = await fetch('/api/users');
  const data: ApiResponse = await response.json(); // No validation!
  return data.users;
}

// ✅ GOOD: Validate at system boundaries
const ApiResponseSchema = z.object({
  users: z.array(UserSchema)
});

async function getUsers(): Promise<User[]> {
  const response = await fetch('/api/users');
  const data = await response.json();
  const validated = ApiResponseSchema.parse(data); // Throws if invalid
  return validated.users;
}

// ✅ GOOD: Safe parse for graceful handling
async function getUsers(): Promise<User[]> {
  const response = await fetch('/api/users');
  const data = await response.json();
  const result = ApiResponseSchema.safeParse(data);

  if (!result.success) {
    console.error('API response validation failed:', result.error);
    return [];
  }
  return result.data.users;
}
```

## Discriminated Unions

```typescript
// ✅ GOOD: Use discriminated unions for type narrowing
type ApiResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

function handleResult(result: ApiResult<User>) {
  if (result.success) {
    console.log(result.data.email); // TypeScript knows data exists
  } else {
    console.error(result.error); // TypeScript knows error exists
  }
}
```

## Index Signatures

```typescript
// ❌ BAD: Unchecked index access
interface Config {
  [key: string]: string;
}
const value = config['someKey'].toUpperCase(); // Could be undefined!

// ✅ GOOD: Enable noUncheckedIndexedAccess in tsconfig
// tsconfig.json: { "compilerOptions": { "noUncheckedIndexedAccess": true } }
const value = config['someKey'];
if (value) {
  console.log(value.toUpperCase()); // Must check first
}
```

## Recommended tsconfig.json

```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noImplicitReturns": true,
    "useUnknownInCatchVariables": true
  }
}
```

## Key Principles

1. **Types are compile-time only** - Always validate external data at runtime
2. **Avoid `any`** - Use `unknown` with type guards instead
3. **Never trust type assertions** for security-relevant data
4. **Validate at boundaries** - API responses, user input, file reads
5. **Use zod** to create runtime validators that infer TypeScript types
6. **Enable strict mode** in tsconfig.json
