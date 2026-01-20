# XSS and Output Encoding

**CWE:** CWE-79 (Cross-site Scripting)
**OWASP:** A03:2021 Injection

## React/Next.js XSS

```typescript
// ❌ BAD: dangerouslySetInnerHTML with user content
function Comment({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// ❌ BAD: Rendering user HTML without sanitization
<div dangerouslySetInnerHTML={{ __html: userBio }} />

// ✅ GOOD: Use text content (auto-escaped by React)
function Comment({ content }: { content: string }) {
  return <div>{content}</div>; // < > & " are escaped
}

// ✅ GOOD: DOMPurify for rich content that MUST be HTML
import DOMPurify from 'isomorphic-dompurify';

function RichContent({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href']
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

## URL-based XSS

```typescript
// ❌ BAD: User-controlled href without validation
<a href={userUrl}>Click here</a>  // javascript: URLs execute!

// ❌ BAD: User input in src attribute
<img src={userImageUrl} />  // data: URLs can be malicious

// ✅ GOOD: Validate URL scheme
function SafeLink({ url, children }: { url: string; children: React.ReactNode }) {
  const isValidUrl = (str: string): boolean => {
    try {
      const parsed = new URL(str);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  };

  if (!isValidUrl(url)) return <span>{children}</span>;
  return <a href={url} rel="noopener noreferrer">{children}</a>;
}

// ✅ GOOD: Allowlist for image sources
const allowedImageHosts = ['cdn.example.com', 'images.example.com'];
function isAllowedImage(url: string): boolean {
  try {
    return allowedImageHosts.includes(new URL(url).host);
  } catch {
    return false;
  }
}
```

## DOM XSS (Vanilla JS)

```typescript
// ❌ BAD: innerHTML with user input
element.innerHTML = userContent;
document.write(userContent);

// ✅ GOOD: textContent for plain text
element.textContent = userContent;

// ✅ GOOD: createElement for DOM manipulation
const div = document.createElement('div');
div.textContent = userContent;
parent.appendChild(div);
```

## Server-Side Rendering

```typescript
// ❌ BAD: Template string interpolation
const html = `<div>${userInput}</div>`;

// ✅ GOOD: Use proper escaping
import { escape } from 'html-escaper';
const html = `<div>${escape(userInput)}</div>`;

// ✅ GOOD: React SSR (auto-escapes)
import { renderToString } from 'react-dom/server';
const html = renderToString(<div>{userInput}</div>);
```

## Content Security Policy

```typescript
// next.config.js - Add CSP headers
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'", // Avoid unsafe-inline if possible
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self' https://api.example.com"
    ].join('; ')
  }
];
```

## Key Principles

1. **Prefer text content** over HTML rendering
2. **Sanitize with DOMPurify** when HTML is required
3. **Validate URL schemes** - only allow http/https
4. **Use CSP headers** as defense in depth
5. **Never use eval, document.write**, or innerHTML with user data
