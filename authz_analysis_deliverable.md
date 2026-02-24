# Authorization Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** 26 high-confidence authorization vulnerabilities identified across horizontal, vertical, and context/workflow categories. All externally exploitable findings have been passed to the exploitation phase via the machine-readable JSON queue.
- **Purpose of this Document:** This report provides strategic context, dominant vulnerability patterns, and architectural intelligence necessary to effectively exploit the vulnerabilities listed in the queue.

### Vulnerability Distribution

| Category | Count | Severity Breakdown |
|----------|-------|-------------------|
| Horizontal Privilege Escalation (IDOR) | 11 | 9 Critical, 2 High |
| Vertical Privilege Escalation | 7 | 4 Critical, 3 High |
| Context-Based Workflow Bypass | 8 | 4 Critical, 2 High, 2 Medium |
| **TOTAL** | **26** | **17 Critical, 7 High, 2 Medium** |

### Key Architectural Finding

The application uses **challenge detection instead of authorization enforcement**. The codebase includes `challengeUtils.solveIf()` calls that **detect** when security controls are bypassed (for gamification purposes) but **do not prevent** the unauthorized access. This pattern appears consistently across vulnerable endpoints.

## 2. Dominant Vulnerability Patterns

### Pattern 1: Challenge Detection Without Enforcement (Horizontal & Vertical)
- **Description:** Endpoints use `challengeUtils.solveIf()` to track when security violations occur but always call `next()` afterward, allowing the vulnerable action to proceed
- **Implication:** Authorization violations are monitored for scoring but not blocked, enabling real exploitation
- **Representative Vulnerabilities:** AUTHZ-VULN-01 (basket IDOR), AUTHZ-VULN-06 (review author forgery), AUTHZ-VULN-07 (review update IDOR), AUTHZ-VULN-12 (admin registration)
- **Code Pattern:**
```typescript
challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
  return user?.bid != parseInt(id, 10)  // Detects unauthorized access
})
// Always continues regardless of check result
res.json(utils.queryResultToJson(basket))  // Returns data anyway
```

### Pattern 2: Missing Ownership Validation in IDOR (Horizontal)
- **Description:** Endpoints accept resource IDs from URL parameters or request body but never validate that the authenticated user owns those resources
- **Implication:** Users can access, modify, or delete other users' data by manipulating ID parameters
- **Representative Vulnerabilities:** AUTHZ-VULN-01 (baskets), AUTHZ-VULN-02 (checkout), AUTHZ-VULN-03 (order tracking), AUTHZ-VULN-04 (data export), AUTHZ-VULN-09 (user profiles), AUTHZ-VULN-10 (feedback)
- **Code Pattern:**
```typescript
// Vulnerable: ID from parameter, no ownership check
BasketModel.findOne({ where: { id: req.params.id } })
  .then(basket => res.json(basket))  // Returns any basket
```

### Pattern 3: Finale Auto-Generated Endpoints Without Authorization (Horizontal & Vertical)
- **Description:** The epilogue-ts/finale framework auto-generates REST CRUD endpoints with no default authorization. Developers must explicitly add authorization hooks, which are missing
- **Implication:** All Finale-generated endpoints expose data without ownership or role checks
- **Representative Vulnerabilities:** AUTHZ-VULN-09 (GET /api/Users/:id), AUTHZ-VULN-10 (GET /api/Feedbacks/:id), AUTHZ-VULN-15 (PUT /api/Products/:id), AUTHZ-VULN-16 (DELETE /api/Feedbacks/:id), AUTHZ-VULN-17 (GET /api/Users), AUTHZ-VULN-18 (POST /api/Products)
- **Root Cause:** Lines 494-545 in server.ts register Finale resources with no `.read.auth` or `.write.auth` hooks configured

### Pattern 4: Mass Assignment Privilege Escalation (Vertical)
- **Description:** Endpoints accept sensitive fields (role, UserId, BasketId) from request body without validation, allowing privilege escalation through parameter injection
- **Implication:** Anonymous users can register as admin, users can submit feedback as others, users can manipulate basket ownership
- **Representative Vulnerabilities:** AUTHZ-VULN-12 (admin registration via role parameter), AUTHZ-VULN-13 (feedback forgery via UserId), AUTHZ-VULN-14 (basket manipulation via BasketId)
- **Code Pattern:**
```typescript
// User model accepts role from request
role: {
  validate: { isIn: [['customer', 'deluxe', 'accounting', 'admin']] }
  // Validates format but not authorization to use privileged role
}
// Challenge detects but doesn't prevent
challengeUtils.solveIf(challenges.registerAdminChallenge, () =>
  req.body.role === 'admin'
)
next()  // Always proceeds
```

### Pattern 5: Workflow Payment Bypass (Context)
- **Description:** Multi-step workflows validate specific payment methods but lack else clauses to enforce that ALL payments are valid, allowing bypass through invalid values
- **Implication:** Users can checkout, upgrade memberships, or complete transactions without payment
- **Representative Vulnerabilities:** AUTHZ-VULN-19 (checkout payment bypass), AUTHZ-VULN-22 (deluxe membership bypass)
- **Code Pattern:**
```typescript
if (req.body.orderDetails.paymentId === 'wallet') {
  // Validate wallet
}
// Missing else clause to reject invalid payment modes
// Order proceeds regardless if paymentId is 'bitcoin', 'free', etc
```

### Pattern 6: Missing Token/State Validation in Workflows (Context)
- **Description:** Critical operations (password reset, data erasure, 2FA) lack proper token validation or state verification from prior workflow steps
- **Implication:** Users can skip workflow steps, reset passwords without email verification, erase data without security answers
- **Representative Vulnerabilities:** AUTHZ-VULN-20 (password reset without token), AUTHZ-VULN-21 (2FA brute-force), AUTHZ-VULN-24 (data erasure without answer validation)

### Pattern 7: Complete Lack of Authentication (Critical)
- **Description:** Several endpoints have no `security.isAuthorized()` middleware at all, allowing anonymous access to sensitive operations
- **Implication:** Public can access order data, user recycle requests, all memories, apply coupons, create/update reviews
- **Representative Vulnerabilities:** AUTHZ-VULN-03 (order tracking), AUTHZ-VULN-05 (recycles), AUTHZ-VULN-06 (review creation), AUTHZ-VULN-08 (all memories), AUTHZ-VULN-11 (coupon manipulation), AUTHZ-VULN-15 (product modification)

## 3. Strategic Intelligence for Exploitation

### Session Management Architecture
- **Token Type:** JWT (RS256) with 6-hour expiration
- **Storage:** localStorage (primary), cookie (8h expiration), in-memory server map
- **Payload Structure:** Contains complete user object including `id`, `email`, `role`, `bid` (basket ID), `deluxeToken`
- **Critical Finding:** JWT contains all privilege information - no server-side session state to revoke
- **Exploitation Note:** Once JWT obtained, all authorization checks rely solely on token contents. Middleware extracts user from JWT but doesn't validate resource ownership.

### Role/Permission Model
- **Roles:** anonymous < customer < deluxe | accounting < admin
- **Role Storage:** JWT payload field `data.role` + database Users table
- **Critical Findings:**
  - No `isAdmin()` middleware exists despite admin role being defined
  - Frontend has AdminGuard but backend has no equivalent
  - Admin endpoints either missing or only require authentication (not admin role)
  - Accounting role properly enforced with `isAccounting()` middleware
  - Deluxe role validated but can be obtained without payment (AUTHZ-VULN-22)

### Resource Access Patterns
- **ID Parameters:** Most resources identified by numeric IDs in URL (baskets, orders, users, feedback)
- **Ownership Model:** Resources have `UserId` foreign key but ownership rarely validated
- **Critical Finding:** Application trusts client-supplied IDs without server-side authorization
- **Pattern:** `findOne({ where: { id: req.params.id } })` with no `UserId` filter

### Middleware Architecture
- **security.isAuthorized():** Validates JWT signature only, extracts user to `req.user`
- **security.appendUserId():** Extracts user ID from JWT, sets `req.body.UserId`
  - **Vulnerability:** Client can override req.body.UserId after middleware runs
- **security.isAccounting():** Validates role === 'accounting' (properly implemented)
- **security.isDeluxe():** Validates role === 'deluxe' + deluxeToken match
- **Missing:** No isAdmin(), no ownership validation middleware

### Challenge System Architecture
- **Purpose:** Gamification - tracks when users solve security challenges
- **Implementation:** `challengeUtils.solveIf(challenge, () => condition)`
- **Critical Flaw:** Detection happens but doesn't prevent vulnerable action
- **Pattern:** Challenge fires → `next()` always called → vulnerable code executes
- **Exploitation Impact:** All challenge-tracked vulnerabilities are real and exploitable

### Finale Framework Integration
- **Purpose:** Auto-generates RESTful CRUD endpoints from Sequelize models
- **Configuration:** Lines 494-545 in server.ts register 20+ resources
- **Authorization Hooks:** None configured (`resource.read.auth`, `resource.write.auth` missing)
- **Impact:** All `/api/*` endpoints lack ownership and role validation
- **Affected Resources:** Users, Products, Feedbacks, Baskets, Cards, Addresses, etc.

### Payment Processing Flows
- **Wallet Payment:** Validated (checks balance, deducts amount)
- **Card Payment:** NOT validated (no Card table lookup, no ownership check)
- **Other Modes:** NOT validated (any invalid mode bypasses payment)
- **Critical Finding:** Lines 139-148 in order.ts only validate `paymentId === 'wallet'`
- **Exploitation:** Provide `paymentId: 'free'` or any invalid value to skip payment

### Workflow State Management
- **Password Reset:** No token system, accepts direct email+answer
- **2FA:** Uses tmpToken but lacks per-token rate limiting
- **Checkout:** No basket validation (can be empty, use others' baskets)
- **Data Erasure:** Shows security question but never validates answer
- **Deluxe Upgrade:** Payment validation can be skipped
- **Critical Finding:** Workflows assume prior steps completed but don't verify

## 4. Secure by Design: Validated Components

These authorization checks were traced and confirmed to have robust, properly-placed guards. They are **low-priority** for exploitation testing as they correctly implement authorization controls.

| **Endpoint** | **Guard Location** | **Defense Mechanism** | **Verdict** |
|--------------|-------------------|----------------------|-------------|
| `GET /rest/order-history/orders` | routes/orderHistory.ts:25 | `security.isAccounting()` enforced before MongoDB query | **SAFE** - Role check dominates sink |
| `PUT /rest/order-history/:id/delivery-status` | routes/orderHistory.ts:32 | `security.isAccounting()` enforced before update | **SAFE** - Role check dominates sink |
| `GET /api/Quantitys/:id` | server.ts:425 | `security.isAccounting()` + IP whitelist filter | **SAFE** - Defense in depth |
| `PUT /api/Quantitys/:id` | server.ts:425 | `security.isAccounting()` + IP whitelist filter | **SAFE** - Defense in depth |
| `POST /rest/user/logout` | N/A | Session invalidation, no authorization needed | **SAFE** - Appropriate for logout |
| `GET /rest/user/whoami` | routes/currentUser.ts:22 | Returns authenticated user's own data from JWT | **SAFE** - No parameter manipulation possible |
| `GET /api/Cards` | routes/payment.ts:18 | `appendUserId()` + query filters by UserId | **SAFE** - Ownership validated |
| `GET /api/Cards/:id` | routes/payment.ts:39 | `appendUserId()` + ownership check in query | **SAFE** - Ownership validated |
| `DELETE /api/Cards/:id` | routes/payment.ts:68 | `appendUserId()` + ownership validation | **SAFE** - Ownership validated |
| `GET /api/Addresss` | routes/address.ts:9 | `appendUserId()` + query filters by UserId | **SAFE** - Ownership validated |
| `GET /api/Addresss/:id` | routes/address.ts:16 | `appendUserId()` + ownership validation | **SAFE** - Ownership validated |
| `DELETE /api/Addresss/:id` | routes/address.ts:27 | `appendUserId()` + ownership check | **SAFE** - Ownership validated |
| `GET /rest/wallet/balance` | routes/wallet.ts:10 | `appendUserId()` + query by UserId | **SAFE** - Ownership validated |
| `PUT /rest/wallet/balance` | routes/wallet.ts:21 | `appendUserId()` + validation | **SAFE** - Ownership validated |

**Key Observation:** Properly secured endpoints follow this pattern:
1. Apply `security.isAuthorized()` middleware (validates JWT)
2. Apply `security.appendUserId()` middleware (extracts user ID)
3. Include `UserId: req.body.UserId` in database queries
4. Validate resource existence and ownership

**What Makes Accounting Endpoints Secure:**
- `security.isAccounting()` uses `verify()` AND `decode()` with logical AND operator
- If JWT signature invalid, `verify()` returns false, short-circuits the AND, prevents decode()
- Role check `decodedToken?.data?.role === 'accounting'` fails if token forged
- Customers cannot escalate to accounting role without private key to sign JWT

## 5. Analysis Constraints and Blind Spots

### Untraced Components
- **Internal Microservices:** Some endpoints make calls to services not included in source code analysis
- **Frontend Authorization:** Angular route guards analyzed but client-side enforcement not sufficient for server security
- **Runtime Permission System:** Dynamic permissions loaded from database could not be fully validated through static analysis

### Assumptions Made
- **JWT Private Key Security:** Analysis assumes RSA private key remains secret. If compromised, all authorization fails.
- **No JWT Algorithm Confusion:** Assumed RS256 enforcement works. Did not test algorithm downgrade attacks.
- **Database Integrity:** Assumed database constraints (foreign keys, NOT NULL) are enforced
- **No Race Conditions:** Static analysis cannot detect TOCTOU vulnerabilities in concurrent requests

### Out of Scope
- **Injection Vulnerabilities:** SQL/NoSQL injection found but analyzed separately
- **Business Logic Flaws:** Focused on authorization, not pricing/discount logic abuse
- **Rate Limiting:** Analyzed for 2FA but not comprehensively tested across all endpoints
- **Session Fixation:** JWT-based auth makes traditional session attacks less relevant

### Testing Limitations
- **No Live Exploitation:** Analysis phase identifies vulnerabilities but doesn't confirm exploitability
- **No Privilege Escalation Chains:** Focused on direct authorization flaws, not multi-step escalation
- **No Social Engineering:** Did not analyze security question guessability or answer enumeration

