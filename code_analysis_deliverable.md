# CODE ANALYSIS REPORT: OWASP Juice Shop
## Penetration Test Scope & Security Assessment

**Application:** OWASP Juice Shop v19.1.1
**Analysis Date:** 2026-02-24
**Assessment Type:** Comprehensive Pre-Reconnaissance Code Analysis
**Target:** Network-Accessible Attack Surface Only

---

# Penetration Test Scope & Boundaries

**Primary Directive:** This analysis is strictly limited to the **network-accessible attack surface** of the application. All subsequent tasks must adhere to this scope.

### In-Scope: Network-Reachable Components
A component is considered **in-scope** if its execution can be initiated, directly or indirectly, by a network request that the deployed application server is capable of receiving. This includes:
- Publicly exposed web pages and API endpoints
- Endpoints requiring authentication via the application's standard login mechanisms
- Any developer utility, debug console, or script that has been mistakenly exposed through a route or is otherwise callable from other in-scope, network-reachable code

### Out-of-Scope: Locally Executable Only
A component is **out-of-scope** if it **cannot** be invoked through the running application's network interface and requires an execution context completely external to the application's request-response cycle. This includes:
- Command-line interfaces (e.g., `go run ./cmd/...`, `python scripts/...`)
- Development environment tooling (e.g., IDE "run script" buttons)
- CI/CD pipeline scripts or build tools
- Database migration scripts, backup tools, maintenance utilities
- Local development servers, test harnesses, debugging utilities
- Static files requiring manual opening (not served by the application)

---

## 1. Executive Summary

OWASP Juice Shop is an **intentionally vulnerable web application** designed for security training and awareness. This comprehensive code analysis identified the application as a Node.js/Express-based monolithic web application with an Angular frontend, containing numerous deliberate security weaknesses across all OWASP Top 10 categories.

### Critical Security Findings

**Vulnerability Count:**
- **23 dangerous sinks** spanning SQL injection, XSS, NoSQL injection, code execution, template injection, XXE, path traversal, and SSRF
- **27 data security vulnerabilities** including plaintext TOTP secrets, MD5 password hashing, and unencrypted credit card storage
- **115+ network-accessible entry points** with minimal security controls
- **Hardcoded cryptographic secrets** including JWT RSA private keys and HMAC secrets

**Compliance Status:**
- **PCI-DSS: CRITICAL FAILURE** - Credit card numbers stored in plaintext
- **GDPR: NON-COMPLIANT** - Data erasure not fully implemented, indefinite retention
- **Security Score: 15 Critical + 8 High severity findings**

### Architectural Overview

The application employs a **hybrid monolithic architecture** combining:
- **Backend:** Express.js 4.21.0 on Node.js 20-24 with TypeScript
- **Frontend:** Angular 20.1.0 SPA with Angular Material UI
- **Databases:** SQLite 5.1.7 (relational), MongoDB (orders/reviews)
- **Real-time:** Socket.io 3.1.2 for WebSocket communication
- **Authentication:** JWT (RS256) with express-jwt 0.1.3 (critically outdated)

**Security Posture:** Deliberately weakened with:
- Outdated vulnerable libraries (express-jwt 0.1.3 from 2013, jsonwebtoken 0.4.0 from 2014)
- Disabled XSS protections (Helmet XSS filter commented out)
- Unrestricted CORS (allows all origins)
- Hardcoded RSA private keys in source code
- MD5 password hashing without salt

### Attack Surface Scope

This analysis identified **115 network-accessible entry points**, including:
- **86 REST API endpoints** (custom + auto-generated CRUD)
- **3 file upload handlers** (profile images, complaints, memory photos)
- **1 WebSocket endpoint** (Socket.io for real-time notifications)
- **8 HTML page routes** (profile, data erasure, promotion video)
- **5 static file serving directories** (FTP, logs, encryption keys, .well-known)
- **Multiple hidden routes** (easter eggs, premium rewards, privacy proof)

All endpoints were evaluated against the penetration test scope to exclude local-only developer tools and focus exclusively on remotely exploitable attack vectors.

### Cascade Impact Warning

**Critical:** This code analysis serves as the foundational intelligence baseline for all subsequent security assessment phases (reconnaissance, vulnerability analysis, exploitation, reporting). The thoroughness and accuracy of this document directly determines the success of the entire assessment workflow.

---

## 2. Architecture & Technology Stack

### 2.1 Framework & Language

**Primary Stack:**
- **Runtime:** Node.js (versions 20-24 supported, v22 in CI/CD)
- **Language:** TypeScript 5.3.3 (backend), TypeScript 5.8.2 (frontend)
- **Compilation:** Target ES2020, output CommonJS
- **Web Framework:** Express.js 4.21.0
- **Frontend Framework:** Angular 20.1.0 with Angular Material UI

**Security Implications:**
- Modern Node.js versions provide good security features (native crypto, updated V8)
- TypeScript adds type safety but doesn't prevent runtime injection attacks
- Express.js 4.x is mature but requires proper middleware configuration
- Angular 20.1.0 includes built-in XSS protection (deliberately bypassed in this app)

### 2.2 Architectural Pattern

**Pattern Classification:** Hybrid Monolithic Web Application

**Architecture Diagram:**
```
┌─────────────────────────────────────────────────────────────┐
│                    OWASP Juice Shop                         │
├─────────────────────────────────────────────────────────────┤
│  Frontend (Angular SPA)                                     │
│  ├─ Angular 20.1.0 + Material + CDK                        │
│  ├─ Socket.io Client (Real-time)                           │
│  └─ Static Assets (served by Express)                      │
├─────────────────────────────────────────────────────────────┤
│  Backend (Node.js/Express/TypeScript)                       │
│  ├─ HTTP Server (Express 4.21.0)                          │
│  ├─ WebSocket Server (Socket.io 3.1.2)                    │
│  ├─ REST API (Finale-rest + Custom Routes)                │
│  ├─ B2B JSON API (/b2b/v2 with Swagger docs)              │
│  └─ Security Middleware (Helmet, CORS, Rate Limit)        │
├─────────────────────────────────────────────────────────────┤
│  Data Access Layer                                          │
│  ├─ Sequelize ORM v6.37.3                                 │
│  └─ 20 Model Definitions                                   │
├─────────────────────────────────────────────────────────────┤
│  Data Persistence                                           │
│  ├─ SQLite v5.1.7 (data/juiceshop.sqlite)                 │
│  └─ MongoDB (orders, reviews)                              │
└─────────────────────────────────────────────────────────────┘
```

**Trust Boundary Analysis:**

The application has three critical trust boundaries:

1. **Client ↔ Server Boundary:**
   - CORS allows all origins (trust boundary violation)
   - No CSRF protection
   - JWT tokens stored in cookies without HttpOnly flag
   - Client-side routing bypassable

2. **Server ↔ Database Boundary:**
   - SQL injection bypasses ORM protections (raw queries)
   - NoSQL injection via $where operator
   - No encryption at rest

3. **Application ↔ External Services:**
   - SSRF vulnerabilities allow internal network access
   - Webhook system trusts environment-configured URLs
   - OAuth implementation lacks state/nonce validation

**Deployment Model:**
- **Development:** `ts-node app.ts` with concurrent frontend dev server
- **Production:** Compiled JavaScript (`node build/app.js`)
- **Container:** Multi-stage Docker build (Node 22 → Distroless base)
- **Orchestration:** Kubernetes-ready with manifests in `/repos/juice-shop/kubernetes/`

### 2.3 Critical Security Components

#### Authentication System

**Location:** `/repos/juice-shop/routes/login.ts`

**Flow:**
1. Client POSTs email + password to `/rest/user/login`
2. Server performs SQL query with string interpolation (**SQL injection vulnerability**)
3. If valid, JWT token generated with RSA-256 signature
4. Token stored in-memory (`authenticatedUsers.tokenMap`)
5. Client receives token + basket ID + email

**Critical Vulnerabilities:**

**SQL Injection in Login** (`/repos/juice-shop/routes/login.ts:34`):
```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}'
   AND password = '${security.hash(req.body.password || '')}'
   AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```
- **Severity:** CRITICAL
- **Impact:** Complete authentication bypass, credential extraction
- **Payload:** `' OR '1'='1' --`

**JWT Implementation** (`/repos/juice-shop/lib/insecurity.ts:22-23, 54-58`):
```typescript
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAK...' // HARDCODED!
export const publicKey = fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')

export const authorize = (user = {}) =>
  jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```
- **Severity:** CRITICAL
- **Issue:** 1024-bit RSA private key hardcoded in source code
- **Impact:** Anyone with source code can forge valid JWTs
- **CVE:** express-jwt 0.1.3 has known algorithm confusion vulnerabilities

**2FA Implementation** (`/repos/juice-shop/routes/2fa.ts`):
- Uses otplib v12.0.1 for TOTP generation
- TOTP secrets stored in **plaintext** in database (`/repos/juice-shop/models/user.ts:113-115`)
- Rate limiting: 100 attempts per 5 minutes (insufficient for 6-digit codes)
- Password reset **bypasses 2FA** completely

#### Session Management

**In-Memory Storage** (`/repos/juice-shop/lib/insecurity.ts:72-93`):
```typescript
export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},  // token -> user object
  idMap: {},     // user ID -> token
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  }
}
```

**Critical Issues:**
- No token expiration enforcement (JWT has 6h expiry but server never removes from map)
- No logout endpoint to clear tokens
- Not horizontally scalable (in-memory state lost on restart)
- Vulnerable to token theft/reuse

**Cookie Configuration** (`/repos/juice-shop/lib/insecurity.ts:195`):
```typescript
res.cookie('token', token)  // Missing HttpOnly, Secure, SameSite flags!
```
- **Missing HttpOnly:** XSS can steal tokens
- **Missing Secure:** Tokens transmitted over HTTP
- **Missing SameSite:** Vulnerable to CSRF

#### Authorization Model

**Roles** (`/repos/juice-shop/lib/insecurity.ts:144-149`):
- customer (default)
- deluxe (paid membership)
- accounting (internal)
- admin (privileged)

**Role Assignment Vulnerability** (`/repos/juice-shop/routes/verify.ts:50-55`):
```typescript
export const registerAdminChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
    return req.body && req.body.role === security.roles.admin
  })
  next()
}
```
- Client can set `role` parameter during registration
- No server-side validation enforces default role
- Direct path to admin account creation

#### Input Validation & Sanitization

**Sanitization Functions** (`/repos/juice-shop/lib/insecurity.ts:60-70`):
```typescript
export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}
```

**Conditional Sanitization** (`/repos/juice-shop/models/user.ts:48-55`):
```typescript
set (username: string) {
  if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
    username = security.sanitizeLegacy(username)  // WEAK
  } else {
    username = security.sanitizeSecure(username)  // STRONG
  }
  this.setDataValue('username', username)
}
```
- Sanitization strength depends on challenge configuration
- When challenges enabled, weak regex-based sanitization allows XSS

#### Security Middleware

**CORS Configuration** (`/repos/juice-shop/server.ts:180-182`):
```typescript
/* Bludgeon solution for possible CORS problems: Allow everything! */
app.options('*', cors())
app.use(cors())
```
- **Vulnerability:** Allows all origins (`Access-Control-Allow-Origin: *`)
- **Impact:** Cross-origin attacks, CSRF, data theft

**Security Headers** (`/repos/juice-shop/server.ts:184-193`):
```typescript
app.use(helmet.noSniff())
app.use(helmet.frameguard())
// app.use(helmet.xssFilter()); // = no protection from persisted XSS via RESTful API
app.disable('x-powered-by')
```
- ✓ X-Content-Type-Options: nosniff
- ✓ X-Frame-Options: SAMEORIGIN
- ❌ **X-XSS-Protection: DISABLED** (commented out)
- ❌ **HSTS: MISSING** (no HTTP Strict Transport Security)
- ❌ **CSP: MISSING** (no Content Security Policy except on profile page)

**Rate Limiting** (`/repos/juice-shop/server.ts:338-342`):
```typescript
app.use('/rest/user/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator ({ headers, ip }: { headers: any, ip: any }) {
    return headers['X-Forwarded-For'] ?? ip  // BYPASSABLE
  }
}))
```
- **Vulnerability:** X-Forwarded-For header trusted for IP identification
- **Impact:** Attacker can spoof IP to bypass rate limits
- **Coverage:** Only password reset endpoint (login has NO rate limiting)

