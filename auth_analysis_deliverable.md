# Authentication Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Critical authentication flaws were identified across all authentication mechanisms, including weak password storage (MD5 hashing), missing transport security (HTTP-only server), absent session cookie security flags, bypassable rate limiting, and no server-side logout implementation.
- **Purpose of this Document:** This report provides comprehensive analysis of the OWASP Juice Shop application's authentication mechanisms, documenting systematic security control failures and architectural weaknesses necessary for the exploitation phase.

**Critical Statistics:**
- **12 Critical Vulnerabilities** identified across authentication flows
- **0 of 6** authentication endpoints enforce HTTPS
- **0 of 6** authentication endpoints have proper cache-control headers
- **0 of 6** authentication endpoints have adequate rate limiting
- **0 of 1** logout implementations perform server-side token invalidation
- **100%** of passwords stored using broken MD5 hashing without salt

**Dominant Attack Vectors:**
1. **Credential Brute-Forcing:** No rate limiting on login endpoint enables unlimited password guessing
2. **Session Hijacking:** Missing HttpOnly/Secure flags allow XSS-based token theft
3. **Credential Cracking:** MD5 password hashes trivially crackable with modern tools
4. **Rate Limit Bypass:** X-Forwarded-For header manipulation bypasses password reset rate limiting
5. **User Enumeration:** Multiple endpoints leak user existence information
6. **Session Persistence After Logout:** Tokens remain valid server-side for 6 hours after logout

## 2. Dominant Vulnerability Patterns

### Pattern 1: Complete Absence of Transport Security Controls
- **Description:** The application runs as an HTTP-only server with no HTTPS enforcement, no HSTS headers, and no cache-control headers on any authentication endpoints. All credentials and session tokens are transmitted in plaintext.
- **Implication:** All authentication traffic is vulnerable to man-in-the-middle attacks. Attackers on the network can intercept credentials, session tokens, and even TOTP secrets. Session tokens and credentials may be cached by browsers or intermediary proxies.
- **Representative Findings:** AUTH-VULN-01 (HTTP-only server), AUTH-VULN-02 (Missing cache-control on all auth endpoints).
- **Affected Endpoints:** ALL authentication endpoints including `/rest/user/login`, `/api/Users`, `/rest/user/reset-password`, `/rest/2fa/verify`, `/rest/2fa/status`, `/rest/2fa/setup`, `/rest/2fa/disable`.

### Pattern 2: Weak or Missing Rate Limiting Enables Brute-Force Attacks
- **Description:** The login and registration endpoints have no rate limiting whatsoever. The password reset endpoint has rate limiting that can be trivially bypassed by manipulating the X-Forwarded-For HTTP header. 2FA endpoints allow 100 attempts per 5 minutes (1,200 per hour).
- **Implication:** Attackers can perform unlimited credential stuffing attacks, password spraying, user enumeration, and TOTP brute-forcing without any throttling.
- **Representative Findings:** AUTH-VULN-03 (No rate limit on login), AUTH-VULN-04 (Bypassable password reset rate limit), AUTH-VULN-05 (Weak 2FA rate limits).
- **Affected Endpoints:** `POST /rest/user/login`, `POST /api/Users`, `POST /rest/user/reset-password`, `POST /rest/2fa/verify`.

### Pattern 3: Insecure Session Cookie Configuration
- **Description:** Session cookies lack all security flags (HttpOnly, Secure, SameSite), making them accessible to JavaScript and transmittable over insecure connections. The application sets cookies both server-side and client-side without any security configuration.
- **Implication:** XSS attacks can steal session tokens via `document.cookie`. Session tokens can be intercepted via MITM. The application is vulnerable to CSRF attacks due to missing SameSite attribute.
- **Representative Findings:** AUTH-VULN-06 (Missing HttpOnly flag), AUTH-VULN-07 (Missing Secure flag), AUTH-VULN-08 (Missing SameSite attribute).
- **Cookie Implementation:** Client-side: `/repos/juice-shop/frontend/src/app/login/login.component.ts:102-104`; Server-side: `/repos/juice-shop/lib/insecurity.ts:195`.

### Pattern 4: Client-Side Only Logout with No Server-Side Token Invalidation
- **Description:** The logout function only removes tokens from client-side storage (localStorage, cookies, sessionStorage) but never invalidates the token on the server. The JWT remains valid in the server's in-memory token map and continues to authenticate requests until the 6-hour expiration.
- **Implication:** Stolen tokens remain usable after the victim logs out. An attacker who captures a token before logout can continue using it for up to 6 hours. There is no mechanism to revoke compromised tokens.
- **Representative Findings:** AUTH-VULN-09 (No server-side logout invalidation).
- **Code Location:** Client logout: `/repos/juice-shop/frontend/src/app/navbar/navbar.component.ts:236-244`; Server token map: `/repos/juice-shop/lib/insecurity.ts:72-93`.

### Pattern 5: Cryptographically Broken Password Storage
- **Description:** All passwords are hashed using MD5 without any salt. MD5 is cryptographically broken and can be brute-forced at billions of hashes per second using modern GPUs. Identical passwords produce identical hashes, enabling rainbow table attacks.
- **Implication:** Database compromise immediately exposes all user passwords. Attackers can crack most passwords in seconds to minutes. Pre-computed rainbow tables for MD5 are widely available online.
- **Representative Findings:** AUTH-VULN-10 (MD5 password hashing), AUTH-VULN-11 (No password salting).
- **Code Location:** Hash function: `/repos/juice-shop/lib/insecurity.ts:43`; User model: `/repos/juice-shop/models/user.ts:74-79`.

### Pattern 6: Hardcoded Cryptographic Secrets
- **Description:** The JWT RSA private key is hardcoded directly in the source code, the cookie parser secret is set to 'kekse', and the HMAC key for security question answers is hardcoded. All secrets are committed to the public repository.
- **Implication:** Anyone with access to the source code (which is publicly available on GitHub) can forge valid JWT tokens, decrypt cookies, and generate valid HMAC signatures for security question answers.
- **Representative Findings:** AUTH-VULN-12 (Hardcoded JWT private key), AUTH-VULN-13 (Weak cookie secret).
- **Code Locations:** JWT key: `/repos/juice-shop/lib/insecurity.ts:23`; Cookie secret: `/repos/juice-shop/server.ts:289`; HMAC key: `/repos/juice-shop/lib/insecurity.ts:44`.

## 3. Strategic Intelligence for Exploitation

### Authentication Architecture Overview

**Authentication Method:** JWT-based stateless authentication with RS256 (RSA-SHA256) signing algorithm.

**Session Token Details:**
- **Token Type:** JSON Web Token (JWT) signed with RSA private key
- **Algorithm:** RS256 (asymmetric cryptography)
- **Expiration:** 6 hours from issuance (`expiresIn: '6h'`)
- **Storage Locations:**
  - Client: localStorage (key: `token`), cookie (name: `token`, expires: 8 hours), Authorization header (`Bearer <token>`)
  - Server: In-memory maps (`authenticatedUsers.tokenMap`, `authenticatedUsers.idMap`)
- **Transmission:** Sent via Cookie header OR Authorization Bearer header
- **Generation:** `/repos/juice-shop/lib/insecurity.ts:56` - `jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })`
- **Validation:** Express-JWT middleware (`/repos/juice-shop/lib/insecurity.ts:54`) + custom verify function (line 57)

**Critical Weakness:** The RSA private key is hardcoded in source code at `/repos/juice-shop/lib/insecurity.ts:23`. This means anyone with source code access can forge arbitrary JWT tokens with any user ID, email, and role.

### Password Policy

**Client-Side Requirements:**
- Minimum length: 5 characters (registration form validation)
- Maximum length: 40 characters
- Password strength indicator checks for: lowercase, uppercase, digits, special characters, 8+ length

**Server-Side Enforcement:**
- **CRITICAL GAP:** Server only validates that password is NOT EMPTY
- No minimum length enforcement
- No complexity requirements
- No check against common password lists
- Passwords can be as short as 1 character if client validation is bypassed

**Code Locations:**
- Client validation: `/repos/juice-shop/frontend/src/app/register/register.component.ts:53`
- Server validation: `/repos/juice-shop/server.ts:402-413` (only checks non-empty)
- Password strength component: `/repos/juice-shop/frontend/src/app/password-strength/password-strength.component.ts`

**Exploitation Implication:** Attackers can register accounts with 1-character passwords by sending direct API requests.

### Default Credentials

**Known Default Accounts:**
1. **Primary Admin:** `admin@juice-sh.op` / `admin123` (intentionally weak for challenges)
2. **Support Admin:** `support@juice-sh.op` / `J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P`
3. **Demo User:** `demo@juice-sh.op` / `demo`
4. **Jim:** `jim@juice-sh.op` / `ncc-1701`
5. **Bender:** `bender@juice-sh.op` / `OhG0dPlease1nsertLiquor!`

**Source:** `/repos/juice-shop/data/static/users.yml` (plaintext credentials)

**User Roles:**
- `customer` (default for registration)
- `deluxe` (paid membership, upgradeable via `/rest/deluxe-membership`)
- `accounting` (business operations access, must be set in database)
- `admin` (full privileges, must be set in database or use default admin accounts)

### Two-Factor Authentication (2FA)

**Implementation:** TOTP (Time-based One-Time Password) using otplib library

**TOTP Configuration:**
- Algorithm: SHA-1
- Digits: 6
- Period: 30 seconds
- Window: ±1 period (90 seconds total validity)

**Critical Vulnerabilities:**
1. **TOTP Secrets Stored in Plaintext:** Database column `totpSecret` contains unencrypted TOTP secrets (`/repos/juice-shop/models/user.ts:113-116`)
2. **Excessive Rate Limiting:** 100 attempts per 5 minutes allows brute-forcing 6-digit codes
3. **2FA Bypass via Password Reset:** Security question-based password reset completely bypasses 2FA
4. **No Backup Codes:** Users who lose their authenticator have no recovery mechanism

**Setup Flow:**
1. `GET /rest/2fa/status` - Returns TOTP secret and setupToken
2. User configures authenticator app with secret
3. `POST /rest/2fa/setup` - Requires password, setupToken, and initial TOTP code
4. TOTP secret stored in database in plaintext

**Verification Flow:**
1. User submits credentials to `POST /rest/user/login`
2. If 2FA enabled, receive `tmpToken` (temporary JWT with type `password_valid_needs_second_factor_token`)
3. Submit tmpToken and TOTP code to `POST /rest/2fa/verify`
4. Receive full authentication token

**Exploitation Strategy:** With 100 attempts per 5 minutes and 1,000,000 possible 6-digit codes, brute-force is theoretically feasible but time-intensive (~833 hours for full keyspace). More practical: exploit password reset bypass or database compromise to extract plaintext TOTP secrets.

### Password Reset Mechanism

**Flow:**
1. `GET /rest/user/security-question?email=<email>` - Returns security question (unauthenticated, enables user enumeration)
2. `POST /rest/user/reset-password` - Submit email, answer, new password, password repeat
3. Server validates answer using HMAC-SHA256 comparison
4. Password immediately updated if answer correct

**Critical Missing Controls:**
- **No email verification** - No token sent to user's email address
- **No time-limited token** - Password can be reset immediately without waiting
- **No single-use token enforcement** - N/A as tokens aren't used
- **Rate limiting bypassable** - X-Forwarded-For header can be spoofed

**Security Question Answers:**
- Stored as HMAC-SHA256 hashes (good practice)
- HMAC key: `pa4qacea4VK9t9nGv7yZtwmj` (hardcoded in `/repos/juice-shop/lib/insecurity.ts:44`)
- Answer submitted in plaintext over HTTP (transport security issue)

**Exploitation Strategy:** Brute-force security question answers using X-Forwarded-For rotation to bypass rate limiting. Common answers for typical security questions (pet names, mother's maiden name, etc.) can be tested rapidly.

### Session Fixation & Token Rotation

**Token Rotation:** New JWT is generated on each login (`security.authorize(user)` at `/repos/juice-shop/routes/login.ts:23`)

**Session Fixation Resistance:**
- **PASS:** Pre-login session identifiers are not reused
- **PASS:** Fresh JWT generated with new signature

**Token Reuse Issue:**
- Old tokens remain valid in `tokenMap` even after new login
- Multiple simultaneous valid tokens possible for same user
- No cleanup of old tokens on new login

### Rate Limiting Configuration Summary

| Endpoint | Rate Limit | Bypass Method | Effectiveness |
|----------|------------|---------------|---------------|
| `POST /rest/user/login` | None | N/A | ❌ No protection |
| `POST /api/Users` | None | N/A | ❌ No protection |
| `POST /rest/user/reset-password` | 100/5min per X-Forwarded-For | Spoof X-Forwarded-For header | ❌ Easily bypassable |
| `POST /rest/2fa/verify` | 100/5min per IP | IP rotation | ⚠️ Weak protection |
| `POST /rest/2fa/setup` | 100/5min per IP | IP rotation | ⚠️ Weak protection |
| `POST /rest/2fa/disable` | 100/5min per IP | IP rotation | ⚠️ Weak protection |

**Express-rate-limit Version:** 7.5.0

**Configuration Locations:** `/repos/juice-shop/server.ts` lines 338-342 (password reset), 452-468 (2FA endpoints)

### SQL Injection in Authentication

**Location:** `/repos/juice-shop/routes/login.ts:34`

**Vulnerable Code:**
```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

**Exploitation Impact:**
- Bypass authentication entirely using SQL injection payloads like `' OR '1'='1'--`
- Extract user data including password hashes
- Enumerate all users
- Authenticate as any user without knowing password

**Exploitation Strategy:** Submit email parameter with SQL injection payload to bypass password check. Example: `admin@juice-sh.op' --` bypasses password validation.

## 4. Secure by Design: Validated Components

These components were analyzed and found to have proper implementation or acceptable security posture within the application's threat model. They are documented here to avoid redundant testing in the exploitation phase.

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| JWT Expiration Enforcement | `/repos/juice-shop/lib/insecurity.ts:54` | Express-JWT middleware automatically validates `exp` claim and rejects expired tokens | SAFE |
| Security Question Answer Storage | `/repos/juice-shop/models/securityAnswer.ts:45-46` | Answers stored as HMAC-SHA256, not plaintext | SAFE |
| Session ID Generation | `/repos/juice-shop/routes/login.ts:23` | Fresh JWT generated on each login with cryptographic signature | SAFE |
| Password Change Authentication | `/repos/juice-shop/routes/changePassword.ts:39` | Requires current password verification before allowing change | SAFE |
| 2FA Setup Password Verification | `/repos/juice-shop/routes/2fa.ts:113` | Requires user's current password to enable 2FA | SAFE |
| 2FA Disable Password Verification | `/repos/juice-shop/routes/2fa.ts:156` | Requires user's current password to disable 2FA | SAFE |
| 2FA Initial Token Validation | `/repos/juice-shop/routes/2fa.ts:125-127` | Validates first TOTP code before enabling 2FA to confirm proper setup | SAFE |
| Token Type Validation | `/repos/juice-shop/routes/2fa.ts:28-30, 121-124` | Verifies JWT token types to prevent token reuse across different flows | SAFE |
| Helmet NoSniff Header | `/repos/juice-shop/server.ts:185` | X-Content-Type-Options: nosniff prevents MIME-type sniffing | SAFE |
| Helmet Frameguard | `/repos/juice-shop/server.ts:186` | X-Frame-Options prevents clickjacking | SAFE |
| Email Uniqueness Constraint | `/repos/juice-shop/models/user.ts:58` | Database enforces unique email addresses | SAFE |
| Role Validation Constraint | `/repos/juice-shop/models/user.ts:82-85` | Database model validates role is one of: customer, deluxe, accounting, admin | SAFE |

**Note:** These components are marked as "SAFE" relative to their specific function, but the overall authentication system remains critically vulnerable due to the patterns documented in Section 2.

