# Cryptography and Secrets Management

**CWE:** CWE-798 (Hardcoded Credentials), CWE-327 (Weak Crypto), CWE-330 (Weak PRNG), CWE-916 (Weak Password Hash)
**OWASP:** A02:2021 Cryptographic Failures

## Hardcoded Secrets

```typescript
// ❌ BAD: Hardcoded API keys
const stripe = new Stripe('sk_live_abc123...', { apiVersion: '2023-10-16' });

// ❌ BAD: Secrets in code
const JWT_SECRET = 'my-super-secret-key';
const DB_PASSWORD = 'password123';

// ❌ BAD: Next.js public env for secrets
// .env.local
NEXT_PUBLIC_API_SECRET=sk_secret_key  // Exposed to browser!

// ✅ GOOD: Environment variables
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16'
});

// ✅ GOOD: Server-only env vars in Next.js
// .env.local
STRIPE_SECRET_KEY=sk_live_abc123  // No NEXT_PUBLIC_ prefix

// ✅ GOOD: Validate required env vars at startup
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET', 'STRIPE_SECRET_KEY'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}
```

## Password Hashing

```typescript
// ❌ BAD: Weak/unsalted hashing
import crypto from 'crypto';
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash = crypto.createHash('sha1').update(password).digest('hex');
const hash = crypto.createHash('sha256').update(password).digest('hex'); // No salt!

// ✅ GOOD: bcrypt with proper cost factor
import bcrypt from 'bcrypt';
const SALT_ROUNDS = 12; // Adjust based on server capacity

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ✅ GOOD: argon2 (preferred for new projects)
import argon2 from 'argon2';

async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4
  });
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return argon2.verify(hash, password);
}
```

## Secure Random Values

```typescript
// ❌ BAD: Math.random for security purposes
const token = Math.random().toString(36).slice(2);
const otp = Math.floor(Math.random() * 1000000);
const sessionId = `session_${Math.random()}`;

// ✅ GOOD: crypto.randomBytes for tokens
import crypto from 'crypto';

function generateToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

// ✅ GOOD: crypto.randomUUID for IDs
const sessionId = crypto.randomUUID();

// ✅ GOOD: Secure OTP generation
function generateOTP(digits: number = 6): string {
  const max = Math.pow(10, digits);
  const randomNumber = crypto.randomInt(0, max);
  return randomNumber.toString().padStart(digits, '0');
}
```

## Encryption

```typescript
// ❌ BAD: Weak algorithms
import crypto from 'crypto';
const cipher = crypto.createCipher('des', key);  // DES is broken
const cipher = crypto.createCipheriv('aes-128-ecb', key, ''); // ECB mode is insecure

// ✅ GOOD: AES-256-GCM (authenticated encryption)
const ALGORITHM = 'aes-256-gcm';

function encrypt(plaintext: string, key: Buffer): { ciphertext: string; iv: string; tag: string } {
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag();

  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

function decrypt(ciphertext: string, key: Buffer, iv: string, tag: string): string {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));

  let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}
```

## Key Derivation

```typescript
// ❌ BAD: Using password directly as key
const key = Buffer.from(password);

// ✅ GOOD: PBKDF2 for key derivation
function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

// ✅ GOOD: scrypt for key derivation
async function deriveKeyScrypt(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 32, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}
```

## Key Principles

1. **Never hardcode secrets** - Use environment variables
2. **Never use NEXT_PUBLIC_** prefix for secrets - Browser can see them
3. **Use bcrypt or argon2** for passwords - Never MD5/SHA family
4. **Use crypto.randomBytes** for tokens - Never Math.random()
5. **Use AES-256-GCM** for encryption - Never DES or ECB mode
