# Prototype Pollution

**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
**Node.js/JavaScript Specific**

## What is Prototype Pollution?

Attackers inject properties into JavaScript object prototypes, affecting all objects that inherit from them. This can lead to denial of service, property injection, and in some cases RCE.

## Deep Merge Vulnerabilities

```typescript
// ❌ BAD: lodash merge with user input
import _ from 'lodash';
const config = {};
_.merge(config, userInput); // User sends: {"__proto__": {"isAdmin": true}}
// Now: ({}).isAdmin === true for ALL objects!

// ❌ BAD: Recursive merge without protection
function deepMerge(target: any, source: any) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ✅ GOOD: lodash mergeWith with prototype check
import _ from 'lodash';

function safeMerge(target: object, source: object): object {
  return _.mergeWith(target, source, (objValue, srcValue, key) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return objValue; // Ignore dangerous keys
    }
  });
}

// ✅ GOOD: Use structuredClone (no prototype issues)
const cleanData = structuredClone(userInput);
const config = { ...defaults, ...cleanData };
```

## Object.assign and Spread

```typescript
// ❌ BAD: Object.assign with user input containing __proto__
const userInput = JSON.parse('{"__proto__": {"polluted": true}}');
Object.assign({}, userInput);
// Some parsers may set __proto__

// ✅ GOOD: Sanitize keys before assignment
function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];
  const clean: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (DANGEROUS_KEYS.includes(key)) continue;
    clean[key] = typeof value === 'object' && value !== null
      ? sanitizeObject(value as Record<string, unknown>)
      : value;
  }
  return clean;
}

const safeData = sanitizeObject(userInput);
```

## Dynamic Property Access

```typescript
// ❌ BAD: User-controlled property keys
const key = req.query.key as string;
const value = req.query.value;
config[key] = value; // key could be "__proto__"

// ❌ BAD: Computed property names from user input
const data = { [userKey]: userValue };

// ✅ GOOD: Allowlist valid keys
const ALLOWED_KEYS = ['theme', 'language', 'timezone'] as const;
type AllowedKey = typeof ALLOWED_KEYS[number];

function isAllowedKey(key: string): key is AllowedKey {
  return ALLOWED_KEYS.includes(key as AllowedKey);
}

if (isAllowedKey(key)) {
  config[key] = value;
}

// ✅ GOOD: Use Map instead of object for dynamic keys
const userPrefs = new Map<string, string>();
userPrefs.set(userKey, userValue); // Maps don't have prototype pollution
```

## JSON.parse Protection

```typescript
// ❌ BAD: Direct JSON.parse of untrusted input
const data = JSON.parse(untrustedJson);

// ✅ GOOD: JSON.parse with reviver to strip dangerous keys
function safeJsonParse(json: string): unknown {
  return JSON.parse(json, (key, value) => {
    if (key === '__proto__' || key === 'constructor') {
      return undefined; // Remove dangerous keys
    }
    return value;
  });
}
```

## Prototype Freezing (Defense in Depth)

```typescript
// ✅ GOOD: Freeze prototypes at application startup
// Add to your app's entry point (e.g., instrumentation.ts in Next.js)

Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);

// Note: Some libraries may break if they modify prototypes
// Test thoroughly before deploying
```

## Using null-prototype Objects

```typescript
// ✅ GOOD: Objects without prototype
const config = Object.create(null);
config.key = 'value';
// config has no __proto__, toString, etc.

// ✅ GOOD: Map for key-value storage
const settings = new Map<string, unknown>();
```

## Key Principles

1. **Never use lodash.merge** with untrusted input without key filtering
2. **Sanitize __proto__, constructor, prototype** keys from user input
3. **Use Map** instead of plain objects for dynamic key-value storage
4. **Consider Object.freeze** on prototypes at app startup
5. **Use JSON.parse with reviver** to strip dangerous keys
6. **Validate property names** against an allowlist
