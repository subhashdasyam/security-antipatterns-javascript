# Dependency Security

**CWE:** CWE-1104 (Unmaintained Components), CWE-1357 (Vulnerable Dependencies)
**OWASP:** A06:2021 Vulnerable and Outdated Components

## Slopsquatting (AI-Hallucinated Packages)

AI models sometimes hallucinate package names that don't exist. Attackers register these names with malicious code.

```typescript
// ❌ BAD: Installing AI-suggested package without verification
// AI suggests: npm install express-middleware-validator
// This package may not exist or be malicious!

// ✅ GOOD: Verify package before installing
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
// ❌ BAD: Typos in package names
npm install lodahs     // Typo of 'lodash'
npm install expresss   // Typo of 'express'
npm install coler      // Typo of 'color'

// ✅ GOOD: Double-check package names
// Use official documentation links
// Copy package names from npmjs.com

// ✅ GOOD: Review what you're installing
npm install lodash --dry-run  // See what would be installed
```

## Dependency Auditing

```bash
# ✅ GOOD: Regular security audits
npm audit                    # Check for vulnerabilities
npm audit fix               # Auto-fix where possible
npm audit fix --force       # Fix even with breaking changes (review first!)

# ✅ GOOD: Check outdated packages
npm outdated                # List outdated packages

# ✅ GOOD: Use lockfile integrity
npm ci                      # Install from lockfile (CI environments)
```

## Package Verification Checklist

Before adding any new dependency:

```typescript
// ✅ GOOD: Verification script
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
# ✅ GOOD: Dependabot configuration (.github/dependabot.yml)
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
# ✅ GOOD: Renovate configuration (renovate.json)
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
// ❌ BAD: Ignoring lockfile
// .gitignore
package-lock.json  // Don't ignore this!

// ✅ GOOD: Commit and use lockfile
git add package-lock.json  // Always commit
npm ci                     // Use in CI (installs from lockfile exactly)

// ✅ GOOD: Enable lockfile verification
// package.json
{
  "scripts": {
    "preinstall": "npx npm-lockfile-lint --type npm --path package-lock.json --allowed-hosts npm yarn"
  }
}
```

## Minimal Dependencies

```typescript
// ❌ BAD: Heavy dependencies for simple tasks
import _ from 'lodash';           // 70KB for one function
const isEmpty = _.isEmpty(obj);

import moment from 'moment';      // 300KB+ for date formatting
const formatted = moment().format('YYYY-MM-DD');

// ✅ GOOD: Native alternatives or lighter packages
// Native
const isEmpty = obj == null || Object.keys(obj).length === 0;
const formatted = new Date().toISOString().split('T')[0];

// Or use lighter alternatives
import { isEmpty } from 'lodash-es/isEmpty';  // Tree-shakeable
import { format } from 'date-fns';            // Modular
```

## Runtime Dependency Checks

```typescript
// ✅ GOOD: Check for known vulnerabilities at startup (optional)
import { execSync } from 'child_process';

function checkDependencies(): void {
  try {
    const result = execSync('npm audit --json', { encoding: 'utf-8' });
    const audit = JSON.parse(result);
    if (audit.metadata.vulnerabilities.high > 0 ||
        audit.metadata.vulnerabilities.critical > 0) {
      console.warn('⚠️  High/Critical vulnerabilities detected. Run npm audit.');
    }
  } catch {
    // Audit command failed or found issues - log warning
  }
}
```

## Key Principles

1. **Verify packages exist** before installing AI-suggested dependencies
2. **Check package health** - downloads, last update, maintainer
3. **Run npm audit regularly** and fix vulnerabilities
4. **Use lockfiles** - commit and use `npm ci` in CI
5. **Minimize dependencies** - use native APIs when possible
6. **Enable automated updates** - Dependabot or Renovate
