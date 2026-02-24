# Reconnaissance Deliverable: OWASP Juice Shop

## 0) HOW TO READ THIS
This reconnaissance report provides a comprehensive map of the application's attack surface, with special emphasis on authorization and privilege escalation opportunities for the Authorization Analysis Specialist.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint - focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls - understand what each guard means before analyzing vulnerabilities.
- **Section 7 (Role & Privilege Architecture):** Complete role hierarchy and privilege mapping - use this to understand the privilege lattice and identify escalation targets.
- **Section 8 (Authorization Vulnerability Candidates):** Pre-prioritized lists of endpoints for horizontal, vertical, and context-based authorization testing.

**How to Use the Network Mapping (Section 6):** The entity/flow mapping shows system boundaries and data sensitivity levels. Pay special attention to flows marked with authorization guards and entities handling PII/sensitive data.

**Priority Order for Testing:** Start with Section 8's High-priority horizontal candidates, then vertical escalation endpoints for each role level, finally context-based workflow bypasses.

## 1. Executive Summary

OWASP Juice Shop is an intentionally vulnerable e-commerce web application designed for security training, awareness demonstrations, and testing of security tools. This white-box reconnaissance analysis has comprehensively mapped the application's attack surface through source code analysis.

**Application Purpose**: Online juice shop with product catalog, shopping cart, order management, user accounts, payment processing, and administrative functions.

**Core Technology Stack**:
- **Frontend**: Angular v20.1.0, Angular Material, RxJS, Socket.io client
- **Backend**: Node.js with Express v4.21.0, TypeScript v5.3.3
- **Database**: SQLite3 with Sequelize ORM v6.37.3, MongoDB for reviews/orders
- **Authentication**: JWT (RS256) with 6-hour expiration, TOTP 2FA support
- **Infrastructure**: Can be deployed standalone, via Docker, or cloud platforms
- **Additional Technologies**: WebSockets (Socket.io v3.1.2), Prometheus metrics, Swagger API docs

**Primary Attack Surface Components**:
- 120+ REST API endpoints covering authentication, e-commerce, admin functions, B2B integration, Web3/NFT features
- File upload capabilities (complaints, profile images, memory photos)
- WebSocket event handlers for real-time notifications
- Multiple file serving endpoints (FTP, logs, quarantine, encryption keys)
- Template rendering system with Pug templates

**Key Security Observations**:
- Intentionally vulnerable application with OWASP Top 10 vulnerabilities
- Weak authentication (MD5 password hashing)
- Multiple SQL and NoSQL injection points
- Authorization bypass opportunities (IDOR vulnerabilities)
- Path traversal and LFI vulnerabilities
- Remote code execution vectors (eval(), unsafe deserialization)
- SSRF, XXE, and SSTI vulnerabilities present

**Version**: 19.1.1
**Repository**: https://github.com/juice-shop/juice-shop

## 2. Technology & Service Map

### Frontend Technologies
- **Framework**: Angular v20.1.0 (TypeScript-based SPA)
- **UI Library**: Angular Material v20.1.0 (Material Design components)
- **Build Tool**: Angular CLI with custom webpack configuration
- **Key Libraries**:
  - RxJS v7.8.2 (reactive programming)
  - Socket.io-client (WebSocket communication)
  - ngx-translate (i18n localization)
  - CodeMirror (code editor for Solidity contracts)
  - File upload, QR code, clipboard utilities
  - Angular routing with route guards (LoginGuard, AdminGuard, AccountingGuard, DeluxeGuard)

### Backend Technologies
- **Language**: TypeScript v5.3.3 compiled to JavaScript
- **Framework**: Express.js v4.21.0 (Node.js web framework)
- **Runtime**: Node.js v20-24 required
- **ORM**: Sequelize v6.37.3 for relational database operations
- **Key Dependencies**:
  - **Authentication**: jsonwebtoken (JWT with RS256), express-jwt, otplib (TOTP 2FA)
  - **Security Middleware**: helmet, cors, express-rate-limit
  - **File Handling**: multer (uploads), unzipper, pdfkit (PDF generation)
  - **Database**: sqlite3, mongodb client
  - **WebSocket**: socket.io v3.1.2
  - **API Documentation**: swagger-ui-express
  - **Monitoring**: prom-client (Prometheus metrics)
  - **Parsing**: body-parser, cookie-parser, libxml (XML), yaml (YAML)
  - **Blockchain**: web3, ethers (Ethereum integration)
  - **Templating**: pug (server-side templates)
  - **Utilities**: morgan (HTTP logging), i18n (internationalization)
  - **Code Execution**: notevil, vm2 (sandboxed evaluation)

### Infrastructure
- **Hosting**: Can run standalone, Docker container, or cloud deployment
- **Database Engine**:
  - SQLite3 (primary data store for users, products, orders, etc.)
  - MongoDB (reviews, orders collection - NoSQL)
- **CDN**: None (serves static files directly)
- **Port**: 3000 (default, configurable via PORT environment variable)
- **Build Output**:
  - Backend compiled to `/build` directory
  - Frontend compiled to `/frontend/dist/frontend` directory

### Identified Subdomains
- **Primary Domain**: localhost:3000 (local deployment)
- **No external subdomains identified** (single-server deployment architecture)

### Open Ports & Services
Based on source code analysis:
- **Port 3000**: HTTP server (Express.js + Angular SPA + WebSocket)
  - Serves Angular frontend as SPA
  - REST API endpoints (120+ endpoints)
  - WebSocket server (Socket.io) on same port
  - Prometheus metrics endpoint (`/metrics`)
  - Swagger API documentation (`/api-docs`)
  - Static file serving (FTP, logs, images, encryption keys)

**Note**: Application is designed as single-port deployment. No external network scans were performed as analysis is white-box source code review.

## 3. Authentication & Session Management Flow

### Entry Points
- **Primary Login**: `POST /rest/user/login` - Email and password authentication
- **User Registration**: `POST /api/Users` - Self-service account creation
- **Password Reset**: `POST /rest/user/reset-password` - Security question-based reset
- **2FA Verification**: `POST /rest/2fa/verify` - TOTP token verification
- **OAuth/SSO**: Not implemented (no external identity providers)

### Authentication Mechanism - Step-by-Step Process

**1. Credential Submission** (`/repos/juice-shop/routes/login.ts:34`)
```typescript
POST /rest/user/login
Body: { email: "user@example.com", password: "password123" }
```

**2. Password Hashing** (`/repos/juice-shop/lib/insecurity.ts:43`)
- Password hashed using **MD5** (intentionally weak for training)
- Hash: `security.hash(password)` = `crypto.createHash('md5').update(password).digest('hex')`

**3. Database Query** (`/repos/juice-shop/routes/login.ts:34`)
- **SQL Injection Vulnerable**: Direct string interpolation
```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}'
   AND password = '${security.hash(req.body.password)}'
   AND deletedAt IS NULL`
)
```

**4. Two-Factor Authentication Check** (`/repos/juice-shop/routes/login.ts:37-46`)
- If user has `totpSecret` configured, return temporary token
- User must verify TOTP code at `POST /rest/2fa/verify`
- Temporary token has shorter lifespan

**5. JWT Token Generation** (`/repos/juice-shop/lib/insecurity.ts:56`)
```typescript
export const authorize = (user = {}) =>
  jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```
- **Algorithm**: RS256 (RSA with SHA-256)
- **Expiration**: 6 hours
- **Private Key**: Hardcoded in source code `/repos/juice-shop/lib/insecurity.ts:23`
- **Public Key**: Read from `/encryptionkeys/jwt.pub`
- **Payload**: Entire user object (id, email, role, etc.)

**6. Session Storage** (`/repos/juice-shop/routes/login.ts:25`)
- In-memory map: `authenticatedUsers.tokenMap[token] = user`
- Bidirectional mapping: `authenticatedUsers.idMap[user.id] = token`
- No database persistence (sessions lost on server restart)

**7. Response to Client** (`/repos/juice-shop/routes/login.ts:26`)
```json
{
  "authentication": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "bid": 1,
    "umail": "user@example.com"
  }
}
```

**8. Client-Side Storage** (`/repos/juice-shop/frontend/src/app/login/login.component.ts:101-105`)
- **localStorage**: `token` (primary storage)
- **Cookie**: `token` with 8-hour expiration
- **sessionStorage**: `bid` (basket ID)

**9. Request Authentication** (`/repos/juice-shop/frontend/src/app/Services/request.interceptor.ts:13-18`)
- HTTP Interceptor automatically adds header to all requests:
```javascript
Authorization: Bearer <token>
```

**10. Server-Side Validation** (`/repos/juice-shop/lib/insecurity.ts:54`)
- Middleware: `security.isAuthorized()` uses `express-jwt`
- Verifies JWT signature with public key
- Decodes payload and attaches to `req.user`

### Code Pointers
- **Login Route**: `/repos/juice-shop/routes/login.ts` (lines 18-56)
- **JWT Functions**: `/repos/juice-shop/lib/insecurity.ts` (lines 22-58)
- **Password Hashing**: `/repos/juice-shop/lib/insecurity.ts:43`
- **Token Extraction**: `/repos/juice-shop/lib/utils.ts:130-143`
- **Session Store**: `/repos/juice-shop/lib/insecurity.ts:72-93`
- **Frontend Login**: `/repos/juice-shop/frontend/src/app/login/login.component.ts:95-131`
- **HTTP Interceptor**: `/repos/juice-shop/frontend/src/app/Services/request.interceptor.ts:12-19`

### 3.1 Role Assignment Process

**Role Determination** (`/repos/juice-shop/models/user.ts:80-84`)
- Roles defined in User model with validation constraint:
```typescript
role: {
  type: DataTypes.STRING,
  defaultValue: 'customer',
  validate: {
    isIn: [['customer', 'deluxe', 'accounting', 'admin']]
  }
}
```

**Default Role**: `'customer'` for all new registrations

**Role Upgrade Paths**:
1. **Deluxe Membership**:
   - User-initiated via `POST /rest/deluxe-membership`
   - Requires payment (wallet balance or credit card)
   - Costs are defined in application configuration
   - File: `/repos/juice-shop/routes/deluxe.ts:16-57`

2. **Admin/Accounting Roles**:
   - No self-service upgrade mechanism
   - Must be set directly in database or during data seeding
   - Pre-seeded admin accounts in `/repos/juice-shop/data/static/users.yml`

**Code Implementation**:
- **Role Definition**: `/repos/juice-shop/lib/insecurity.ts:144-149`
```typescript
export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}
```
- **User Model**: `/repos/juice-shop/models/user.ts:80-99`
- **Deluxe Upgrade**: `/repos/juice-shop/routes/deluxe.ts:19`
- **Data Seeding**: `/repos/juice-shop/data/static/users.yml`

### 3.2 Privilege Storage & Validation

**Storage Location**:
- **Primary**: JWT token payload (encoded in token itself)
- **Secondary**: In-memory session map `authenticatedUsers.tokenMap`
- **Database**: User table `role` column (source of truth)

**Validation Points**:

1. **Middleware Functions** (`/repos/juice-shop/lib/insecurity.ts`)
   - `isAuthorized()` (line 54): Validates JWT signature
   - `isAccounting()` (lines 156-165): Checks `role === 'accounting'`
   - `isDeluxe()` (lines 167-170): Validates deluxe role + deluxe token
   - `isCustomer()` (lines 172-175): Checks `role === 'customer'`

2. **Frontend Route Guards** (`/repos/juice-shop/frontend/src/app/app.guard.ts`)
   - `LoginGuard` (lines 12-24): Checks token exists
   - `AdminGuard` (lines 48-61): Validates `role === 'admin'`
   - `AccountingGuard` (lines 64-77): Validates `role === 'accounting'`
   - `DeluxeGuard` (lines 80-88): Validates `role === 'deluxe'`

3. **Inline Checks**: Some routes check role directly from decoded token

**Cache/Session Persistence**:
- **JWT Token**: Valid for 6 hours from issuance
- **In-Memory Map**: Persists until server restart (no eviction policy)
- **Client Storage**: localStorage (indefinite), cookie (8 hours)
- **Refresh Mechanism**: None (must re-authenticate after expiration)

**Code Pointers**:
- **Middleware**: `/repos/juice-shop/lib/insecurity.ts:54-175`
- **Frontend Guards**: `/repos/juice-shop/frontend/src/app/app.guard.ts`
- **Token Decode**: `/repos/juice-shop/lib/insecurity.ts:58`

### 3.3 Role Switching & Impersonation

**Impersonation Features**: None implemented
- No admin impersonation capability found in codebase
- No "act as user" or "sudo mode" functionality

**Role Switching**: None
- Users cannot temporarily elevate privileges
- No "sudo mode" or temporary role escalation
- Role changes require direct database modification or deluxe membership purchase

**Audit Trail**: Minimal
- HTTP request logging via Morgan middleware
- No specific audit trail for role changes or administrative actions
- Challenge system tracks vulnerability exploitation attempts

**Code Implementation**: Not applicable (features not present)

**Security Implications**:
- Lack of impersonation makes testing user permissions more difficult for admins
- No audit trail makes forensics and monitoring challenging
- Role stored only in JWT means changes require new token issuance

## 4. API Endpoint Inventory

**Network Surface Focus**: This section catalogs only API endpoints accessible through the target web application's network interface. Development tools, local CLI utilities, and build scripts are excluded.

### Authentication & User Management Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /rest/user/login | anon | None | None | User login with SQL injection vulnerability. `/repos/juice-shop/routes/login.ts:18` |
| GET | /rest/user/whoami | user | None | JWT via cookie/header, `updateAuthenticatedUsers()` | Get current logged-in user info. `/repos/juice-shop/routes/currentUser.ts:22` |
| GET | /rest/user/authentication-details | user | None | `security.isAuthorized()` | Get authentication details. `/repos/juice-shop/routes/authenticatedUsers.ts` |
| GET | /rest/user/change-password | user | None | JWT Bearer token | Change user password (query params: current, new, repeat). `/repos/juice-shop/routes/changePassword.ts:12` |
| POST | /rest/user/reset-password | anon | None | Rate limited (100/5min) | Reset password via security question. `/repos/juice-shop/routes/resetPassword.ts:16` |
| GET | /rest/user/security-question | anon | None | None | Get security question for email. `/repos/juice-shop/routes/securityQuestion.ts` |
| POST | /rest/user/data-export | user | None | `appendUserId()`, Image CAPTCHA | Export user data (GDPR). `/repos/juice-shop/routes/dataExport.ts:15` |
| POST | /api/Users | anon | None | Email validation | Register new user. `/repos/juice-shop/server.ts:402-416` |
| GET | /api/Users | user | None | `security.isAuthorized()` | List all users. `/repos/juice-shop/server.ts:357` |
| GET | /api/Users/:id | user | user_id | `security.isAuthorized()` | Get user by ID. `/repos/juice-shop/server.ts:359` |
| PUT | /api/Users/:id | blocked | user_id | `security.denyAll()` | Update user (blocked). `/repos/juice-shop/server.ts:360` |
| DELETE | /api/Users/:id | blocked | user_id | `security.denyAll()` | Delete user (blocked). `/repos/juice-shop/server.ts:361` |

### Two-Factor Authentication Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /rest/2fa/verify | anon | None | Rate limited (100/5min) | Verify 2FA TOTP token. `/repos/juice-shop/routes/2fa.ts:22` |
| GET | /rest/2fa/status | user | None | `security.isAuthorized()` | Check 2FA status. `/repos/juice-shop/routes/2fa.ts:64` |
| POST | /rest/2fa/setup | user | None | `security.isAuthorized()`, Rate limited | Enable 2FA. `/repos/juice-shop/routes/2fa.ts:103` |
| POST | /rest/2fa/disable | user | None | `security.isAuthorized()`, Rate limited | Disable 2FA. `/repos/juice-shop/routes/2fa.ts:148` |

### Product & Search Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/products/search | anon | None | None | Search products (SQL injection vulnerable). `/repos/juice-shop/routes/search.ts:19` |
| GET | /api/Products | anon | None | None | List all products (Finale auto-generated). `/repos/juice-shop/server.ts:479` |
| GET | /api/Products/:id | anon | product_id | None | Get product by ID. `/repos/juice-shop/server.ts:479` |
| POST | /api/Products | user | None | `security.isAuthorized()` | Create new product. `/repos/juice-shop/server.ts:363` |
| PUT | /api/Products/:id | user | product_id | None (commented out) | Update product (authorization bypass). `/repos/juice-shop/server.ts:364` |
| DELETE | /api/Products/:id | blocked | product_id | `security.denyAll()` | Delete product (blocked). `/repos/juice-shop/server.ts:365` |

### Basket & Checkout Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/basket/:id | user | basket_id | `security.isAuthorized()`, `appendUserId()` (weak check) | Get basket by ID (IDOR vulnerable). `/repos/juice-shop/routes/basket.ts:15` |
| POST | /rest/basket/:id/checkout | user | basket_id | `security.isAuthorized()` | Place order and generate PDF (IDOR vulnerable). `/repos/juice-shop/routes/order.ts:33` |
| PUT | /rest/basket/:id/coupon/:coupon | anon | basket_id, coupon | None | Apply coupon to basket. `/repos/juice-shop/routes/coupon.ts:10` |
| POST | /api/BasketItems | user | None | `security.isAuthorized()`, `appendUserId()`, quantity check | Add item to basket. `/repos/juice-shop/routes/basketItems.ts:19` |
| PUT | /api/BasketItems/:id | user | basket_item_id | `appendUserId()`, quantity check | Update basket item. `/repos/juice-shop/server.ts:420` |
| GET | /api/BasketItems | user | None | `security.isAuthorized()` | List basket items. `/repos/juice-shop/server.ts:481` |
| GET | /api/BasketItems/:id | user | basket_item_id | `security.isAuthorized()` | Get basket item by ID. `/repos/juice-shop/server.ts:481` |
| DELETE | /api/BasketItems/:id | user | basket_item_id | `security.isAuthorized()` | Delete basket item. `/repos/juice-shop/server.ts:481` |

### Order & Delivery Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/track-order/:id | anon | order_id | None | Track order by ID (NoSQL injection). `/repos/juice-shop/routes/trackOrder.ts` |
| GET | /rest/order-history | user | None | JWT in Authorization header | Get order history for user. `/repos/juice-shop/routes/orderHistory.ts:11` |
| GET | /rest/order-history/orders | accounting | None | `security.isAccounting()` | Get all orders. `/repos/juice-shop/routes/orderHistory.ts:25` |
| PUT | /rest/order-history/:id/delivery-status | accounting | order_id | `security.isAccounting()` | Toggle delivery status. `/repos/juice-shop/routes/orderHistory.ts:32` |
| GET | /api/Deliverys | anon | None | None | Get all delivery methods. `/repos/juice-shop/routes/delivery.ts:11` |
| GET | /api/Deliverys/:id | anon | delivery_id | None | Get delivery method by ID. `/repos/juice-shop/routes/delivery.ts:32` |

### Payment & Wallet Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /api/Cards | user | None | `appendUserId()` | Add payment card. `/repos/juice-shop/server.ts:432` |
| GET | /api/Cards | user | None | `appendUserId()` | Get user's payment methods. `/repos/juice-shop/routes/payment.ts:18` |
| GET | /api/Cards/:id | user | card_id | `appendUserId()` | Get payment card by ID. `/repos/juice-shop/routes/payment.ts:39` |
| DELETE | /api/Cards/:id | user | card_id | `appendUserId()` | Delete payment card. `/repos/juice-shop/routes/payment.ts:68` |
| GET | /rest/wallet/balance | user | None | `appendUserId()` | Get wallet balance. `/repos/juice-shop/routes/wallet.ts:10` |
| PUT | /rest/wallet/balance | user | None | `appendUserId()` | Add balance to wallet. `/repos/juice-shop/routes/wallet.ts:21` |
| GET | /rest/deluxe-membership | anon | None | None | Get deluxe membership status. `/repos/juice-shop/routes/deluxe.ts:60` |
| POST | /rest/deluxe-membership | user | None | `appendUserId()` | Upgrade to deluxe membership. `/repos/juice-shop/routes/deluxe.ts:16` |

### Address Management Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /api/Addresss | user | None | `appendUserId()` | Create new address. `/repos/juice-shop/server.ts:442` |
| GET | /api/Addresss | user | None | `appendUserId()` | Get all addresses for user. `/repos/juice-shop/routes/address.ts:9` |
| GET | /api/Addresss/:id | user | address_id | `appendUserId()` | Get address by ID. `/repos/juice-shop/routes/address.ts:16` |
| PUT | /api/Addresss/:id | user | address_id | `appendUserId()` | Update address. `/repos/juice-shop/server.ts:444` |
| DELETE | /api/Addresss/:id | user | address_id | `appendUserId()` | Delete address. `/repos/juice-shop/routes/address.ts:27` |

### Feedback & Complaints Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /api/Feedbacks | anon | None | None | List all feedback. `/repos/juice-shop/server.ts:480` |
| POST | /api/Feedbacks | anon | None | CAPTCHA verification | Submit feedback (XSS vulnerable). `/repos/juice-shop/server.ts:396-400` |
| GET | /api/Feedbacks/:id | user | feedback_id | `security.isAuthorized()` | Get feedback by ID. `/repos/juice-shop/server.ts:355` |
| PUT | /api/Feedbacks/:id | blocked | feedback_id | `security.denyAll()` | Update feedback (blocked). `/repos/juice-shop/server.ts:427` |
| DELETE | /api/Feedbacks/:id | anon | feedback_id | None | Delete feedback. `/repos/juice-shop/server.ts:480` |
| GET | /api/Complaints | user | None | `security.isAuthorized()` | List complaints. `/repos/juice-shop/server.ts:375` |
| POST | /api/Complaints | user | None | `security.isAuthorized()` | Submit complaint. `/repos/juice-shop/server.ts:376` |
| * | /api/Complaints/:id | blocked | complaint_id | `security.denyAll()` | All operations blocked. `/repos/juice-shop/server.ts:377` |

### Product Reviews Endpoints (NoSQL)

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/products/:id/reviews | anon | product_id | None | Get reviews for product (NoSQL injection). `/repos/juice-shop/routes/showProductReviews.ts:28` |
| PUT | /rest/products/:id/reviews | anon | product_id | None | Create product review (can forge author). `/repos/juice-shop/routes/createProductReviews.ts` |
| PATCH | /rest/products/reviews | user | None | `security.isAuthorized()` | Update product review (NoSQL injection). `/repos/juice-shop/routes/updateProductReviews.ts` |
| POST | /rest/products/reviews | user | None | `security.isAuthorized()` | Like product review. `/repos/juice-shop/routes/likeProductReviews.ts` |

### Profile Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /profile | user | None | Cookie token, `updateAuthenticatedUsers()` | Get user profile (SSTI vulnerable). `/repos/juice-shop/routes/userProfile.ts:25` |
| POST | /profile | user | None | None | Update user profile. `/repos/juice-shop/routes/updateUserProfile.ts` |

### Recycling Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /api/Recycles | blocked | None | Custom blocker | List recycles (blocked). `/repos/juice-shop/routes/recycles.ts:23` |
| POST | /api/Recycles | user | None | `security.isAuthorized()` | Submit recycle request. `/repos/juice-shop/server.ts:380` |
| GET | /api/Recycles/:id | anon | recycle_id | None | Get recycle by ID (JSON injection). `/repos/juice-shop/routes/recycles.ts:11` |
| PUT | /api/Recycles/:id | blocked | recycle_id | `security.denyAll()` | Update recycle (blocked). `/repos/juice-shop/server.ts:383` |
| DELETE | /api/Recycles/:id | blocked | recycle_id | `security.denyAll()` | Delete recycle (blocked). `/repos/juice-shop/server.ts:384` |

### B2B Integration Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /b2b/v2/orders | user | None | `security.isAuthorized()` | Place B2B order (RCE via VM eval). `/repos/juice-shop/routes/b2bOrder.ts:16` |

### Web3 / NFT Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /rest/web3/submitKey | anon | None | None | Submit Web3 keys. `/repos/juice-shop/routes/checkKeys.ts` |
| GET | /rest/web3/nftUnlocked | anon | None | None | Check if NFT unlocked. `/repos/juice-shop/routes/checkKeys.ts` |
| GET | /rest/web3/nftMintListen | anon | None | None | Listen for NFT mint events. `/repos/juice-shop/routes/nftMint.ts` |
| POST | /rest/web3/walletNFTVerify | anon | None | None | Verify wallet NFT. `/repos/juice-shop/routes/nftMint.ts` |
| POST | /rest/web3/walletExploitAddress | anon | None | None | Register wallet for exploit listener. `/repos/juice-shop/routes/web3Wallet.ts:13` |

### File Upload Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| POST | /file-upload | anon | None | File validation, Size check | Upload file (ZIP/XML/YAML, XXE vulnerable). `/repos/juice-shop/server.ts:304` |
| POST | /profile/image/file | user | None | File validation | Upload profile image (file). `/repos/juice-shop/server.ts:305` |
| POST | /profile/image/url | user | None | None | Upload profile image (URL, SSRF vulnerable). `/repos/juice-shop/server.ts:306` |
| POST | /rest/memories | user | None | `appendUserId()`, File upload | Add memory/photo. `/repos/juice-shop/server.ts:307` |
| GET | /rest/memories | anon | None | None | Get all memories (no privacy). `/repos/juice-shop/routes/memory.ts:22` |

### File Serving Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /ftp/:file | anon | file | None | Download FTP files (path traversal). `/repos/juice-shop/server.ts:270` |
| GET | /ftp/quarantine/:file | anon | file | None | Download quarantined files. `/repos/juice-shop/server.ts:271` |
| GET | /encryptionkeys/:file | anon | file | None | Download encryption keys. `/repos/juice-shop/server.ts:278` |
| GET | /support/logs/:file | anon | file | Access control check | Download log files. `/repos/juice-shop/server.ts:283` |

### Admin & Configuration Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/admin/application-version | anon | None | None | Get application version. `/repos/juice-shop/routes/appVersion.ts` |
| GET | /rest/admin/application-configuration | anon | None | None | Get app configuration. `/repos/juice-shop/routes/appConfiguration.ts` |
| GET | /rest/languages | anon | None | None | Get available languages. `/repos/juice-shop/routes/languages.ts` |
| GET | /rest/country-mapping | anon | None | None | Get country mapping data. `/repos/juice-shop/routes/countryMapping.ts` |

### Chatbot Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/chatbot/status | user | None | JWT from cookie/header | Check chatbot status. `/repos/juice-shop/routes/chatbot.ts:157` |
| POST | /rest/chatbot/respond | user | None | JWT from cookie/header | Process chatbot interaction. `/repos/juice-shop/routes/chatbot.ts:205` |

### Utility & Misc Endpoints

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|--------|--------------|---------------|---------------------|------------------------|----------------------------|
| GET | /rest/captcha | anon | None | None | Generate math CAPTCHA. `/repos/juice-shop/routes/captcha.ts:10` |
| GET | /rest/image-captcha | anon | None | None | Generate image CAPTCHA. `/repos/juice-shop/routes/imageCaptcha.ts` |
| GET | /rest/repeat-notification | anon | None | None | Repeat last notification. `/repos/juice-shop/routes/repeatNotification.ts` |
| GET | /rest/saveLoginIp | anon | None | None | Save login IP (XSS vulnerable). `/repos/juice-shop/routes/saveLoginIp.ts` |
| GET | /redirect | anon | None | None | Perform redirect (SSRF). `/repos/juice-shop/routes/redirect.ts` |
| GET | /promotion | anon | None | None | Promotion video page. `/repos/juice-shop/routes/videoHandler.ts` |
| GET | /video | anon | None | None | Get video content. `/repos/juice-shop/routes/videoHandler.ts` |
| GET | /metrics | anon | None | None | Prometheus metrics. `/repos/juice-shop/server.ts:713` |
| GET | /api-docs | anon | None | None | Swagger API documentation. `/repos/juice-shop/server.ts:286` |

**Total Endpoints Cataloged**: 120+

## 5. Potential Input Vectors for Vulnerability Analysis

**Network Surface Focus**: This section reports input vectors accessible through the target web application's network interface. Local-only scripts, build tools, and development utilities are excluded.

### 5.1 URL Parameters (req.params)

| Endpoint | Parameter Name | File:Line | Validation | Usage Description |
|----------|----------------|-----------|------------|-------------------|
| `/rest/basket/:id` | `id` (basket ID) | `/repos/juice-shop/routes/basket.ts:17` | None | Direct database query |
| `/rest/basket/:id/checkout` | `id` (basket ID) | `/repos/juice-shop/routes/order.ts:35` | None | Order checkout |
| `/rest/basket/:id/coupon/:coupon` | `coupon` | `/repos/juice-shop/routes/coupon.ts:13-14` | URL decode only | Coupon validation |
| `/rest/track-order/:id` | `id` (order ID) | `/repos/juice-shop/routes/trackOrder.ts:15` | Conditional sanitization | NoSQL $where injection |
| `/rest/products/:id/reviews` | `id` (product ID) | `/repos/juice-shop/routes/showProductReviews.ts:31` | Conditional truncation | NoSQL $where injection |
| `/api/BasketItems/:id` | `id` (basket item ID) | `/repos/juice-shop/routes/basketItems.ts:67` | None | Database query |
| `/api/Cards/:id` | `id` (card ID) | `/repos/juice-shop/routes/payment.ts:41,70` | None | Card lookup/deletion |
| `/api/Addresss/:id` | `id` (address ID) | `/repos/juice-shop/routes/address.ts:18,29` | None | Address operations |
| `/api/Deliverys/:id` | `id` (delivery ID) | `/repos/juice-shop/routes/delivery.ts:34` | None | Delivery method lookup |
| `/rest/order-history/:id/delivery-status` | `id` (order ID) | `/repos/juice-shop/routes/orderHistory.ts:36` | None | MongoDB update |
| `/api/Recycles/:id` | `id` (recycle ID) | `/repos/juice-shop/routes/recycles.ts:14` | JSON.parse() | Sequelize operator injection |
| `/ftp/:file` | `file` (filename) | `/repos/juice-shop/routes/fileServer.ts:28-33` | Forward slash check, extension allowlist | Path traversal, null byte |
| `/ftp/quarantine/:file` | `file` (filename) | `/repos/juice-shop/routes/quarantineServer.ts:11-14` | Forward slash check | Path traversal |
| `/encryptionkeys/:file` | `file` (filename) | `/repos/juice-shop/routes/keyServer.ts:11-14` | Forward slash check | Path traversal |
| `/support/logs/:file` | `file` (filename) | `/repos/juice-shop/routes/logfileServer.ts:11-14` | Forward slash check, access control | Path traversal |
| `/snippets/:challenge` | `challenge` (key) | `/repos/juice-shop/routes/vulnCodeSnippet.ts:44` | None | File system access |
| `/snippets/fixes/:key` | `key` (fix key) | `/repos/juice-shop/routes/vulnCodeFixes.ts:57` | None | File system access |

### 5.2 Query Parameters (req.query)

| Endpoint | Parameter Name | File:Line | Validation | Usage Description |
|----------|----------------|-----------|------------|-------------------|
| `/rest/products/search` | `q` (search term) | `/repos/juice-shop/routes/search.ts:21` | 200 char limit only | **SQL injection** - direct string interpolation |
| `/rest/user/change-password` | `current`, `new`, `repeat` | `/repos/juice-shop/routes/changePassword.ts:14-17` | Equality check, non-'undefined' | Password validation |
| `/rest/user/security-question` | `email` | `/repos/juice-shop/routes/securityQuestion.ts:13` | toString() only | Security question lookup |
| `/rest/user/whoami` | `callback` (JSONP) | `/repos/juice-shop/routes/currentUser.ts:22` | None | JSONP response (XSS) |
| `/solve/challenges/server-side` | `key` | `/repos/juice-shop/routes/verify.ts:92` | Exact match | Challenge verification |
| `/redirect` | `to` (URL) | `/repos/juice-shop/routes/redirect.ts:15` | `isRedirectAllowed()` | Open redirect/SSRF |

### 5.3 POST Body Fields (req.body)

#### Authentication & User Management

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/rest/user/login` | `email`, `password` | `/repos/juice-shop/routes/login.ts:34` | **None** | **SQL injection** - direct interpolation |
| `/rest/user/reset-password` | `email`, `answer`, `new`, `repeat` | `/repos/juice-shop/routes/resetPassword.ts:17-21` | Password match, HMAC answer | Password reset |
| `/rest/2fa/verify` | `tmpToken`, `totpToken` | `/repos/juice-shop/routes/2fa.ts:23` | JWT + TOTP validation | 2FA verification |
| `/rest/2fa/setup` | `password`, `setupToken`, `initialToken` | `/repos/juice-shop/routes/2fa.ts:111` | Hash comparison, JWT, TOTP | 2FA setup |
| `/rest/2fa/disable` | `password` | `/repos/juice-shop/routes/2fa.ts:156` | Hash comparison | 2FA disable |
| `/api/Users` (POST) | `email`, `password`, `passwordRepeat`, `role` | `/repos/juice-shop/server.ts:402-416` | Trim, empty check | User registration (role injection) |

#### Shopping & Orders

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/api/BasketItems` (POST) | `ProductId`, `BasketId`, `quantity` | `/repos/juice-shop/routes/basketItems.ts:19-54` | Custom JSON parse, quantity | Add to basket |
| `/api/BasketItems/:id` (PUT) | `quantity`, `BasketId` | `/repos/juice-shop/routes/basketItems.ts:65-82` | Quantity availability | Update basket item |
| `/rest/basket/:id/checkout` (POST) | `UserId`, `deliveryMethodId`, `paymentId`, `addressId`, `couponData` | `/repos/juice-shop/routes/order.ts:34-176` | Wallet balance, delivery validation | Order checkout |
| `/b2b/v2/orders` | `cid`, `orderLinesData` | `/repos/juice-shop/routes/b2bOrder.ts:17-37` | **None** | **RCE** via notevil eval |

#### Feedback & Reviews

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/api/Feedbacks` | `comment`, `rating`, `captcha`, `captchaId`, `UserId` | `/repos/juice-shop/server.ts:396-400` | CAPTCHA verification | Submit feedback (XSS) |
| `/rest/products/:id/reviews` (PUT) | `message`, `author` | `/repos/juice-shop/routes/createProductReviews.ts:15-34` | None | Create review (forge author) |
| `/rest/products/reviews` (PATCH) | `id`, `message` | `/repos/juice-shop/routes/updateProductReviews.ts:15-29` | **None** | **NoSQL injection** (multi-update) |
| `/rest/products/reviews` (POST) | `id` | `/repos/juice-shop/routes/likeProductReviews.ts:17-61` | Auth only | Like review |

#### Profile & Account

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/profile` (POST) | `username` | `/repos/juice-shop/routes/updateUserProfile.ts:14-46` | **None** | **SSTI** - Pug template injection |
| `/rest/chatbot/respond` | `action`, `query` | `/repos/juice-shop/routes/chatbot.ts:205-234` | JWT auth | Chatbot interaction |
| `/rest/user/data-export` | `UserId`, `answer` | `/repos/juice-shop/routes/dataExport.ts:15-114` | Image CAPTCHA | GDPR data export (UserId injection) |

#### Payment & Wallet

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/rest/wallet/balance` (PUT) | `balance`, `paymentId` | `/repos/juice-shop/routes/wallet.ts:21-34` | Card ownership | Add wallet balance |
| `/rest/deluxe-membership` | `paymentMode`, `paymentId` | `/repos/juice-shop/routes/deluxe.ts:16-57` | Role check, balance/card validation | Deluxe upgrade |
| `/api/Cards` | `fullName`, `cardNum`, `expMonth`, `expYear`, `UserId` | Server auto-appends UserId | UserId auto-appended | Add payment card |
| `/api/Addresss` | `fullName`, `mobileNum`, `zipCode`, `streetAddress`, `city`, `country`, `state`, `UserId` | Server auto-appends UserId | UserId auto-appended | Add address |

#### File Operations

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/dataerasure` | `email`, `securityAnswer`, `layout` | `/repos/juice-shop/routes/dataErasure.ts:54-93` | Path blacklist (ftp, ctf.key, encryptionkeys) | **LFI** via layout parameter |
| `/rest/memories` | `caption`, `UserId` | `/repos/juice-shop/routes/memory.ts:10-19` | File upload validation | Add photo memory |
| `/profile/image/url` | `imageUrl` | `/repos/juice-shop/routes/profileImageUrlUpload.ts:17-31` | **None** | **SSRF** - arbitrary URL fetch |

#### Web3/NFT

| Endpoint | Field Name | File:Line | Validation | Usage Description |
|----------|-----------|-----------|------------|-------------------|
| `/rest/web3/submitKey` | `privateKey` | `/repos/juice-shop/routes/checkKeys.ts:7-32` | Hardcoded comparison | NFT unlock challenge |
| `/rest/web3/walletNFTVerify` | `walletAddress` | `/repos/juice-shop/routes/nftMint.ts:33-47` | NFT mint check | NFT verification |
| `/rest/web3/walletExploitAddress` | `walletAddress` | `/repos/juice-shop/routes/web3Wallet.ts:13-33` | None | Wallet exploit listener |

### 5.4 HTTP Headers

| Header Name | File:Line | Validation | Usage Description |
|-------------|-----------|------------|-------------------|
| `Authorization` | Multiple files | JWT signature verification | Bearer token authentication |
| `True-Client-IP` | `/repos/juice-shop/routes/saveLoginIp.ts:18` | Conditional sanitization | **XSS vulnerable** - stored in database |
| `X-User-Email` | `/repos/juice-shop/lib/insecurity.ts:95-96` | None | Alternative email extraction |
| `Range` | `/repos/juice-shop/routes/videoHandler.ts:24` | Parsing for video streaming | HTTP range requests |
| `Origin` | `/repos/juice-shop/routes/updateUserProfile.ts:31-32` | String contains check | CSRF challenge detection |
| `Referer` | `/repos/juice-shop/routes/updateUserProfile.ts:31-32` | String contains check | CSRF challenge detection |
| `Content-Type` | `/repos/juice-shop/server.ts:313` | application/json check | JSON body parsing decision |

### 5.5 Cookie Values

| Cookie Name | File:Line | Usage Description |
|-------------|-----------|-------------------|
| `token` | Multiple routes | JWT session authentication (primary) |
| `language` | `/repos/juice-shop/server.ts:296` | User language preference (i18n) |

### 5.6 File Uploads

#### /file-upload (POST)
- **Multer Field**: `'file'` (single file to memory)
- **Size Limit**: 200KB
- **File**: `/repos/juice-shop/routes/fileUpload.ts`
- **Validation**: File presence, size check, type check
- **File Types Handled**:
  - **.zip**: Extracted via unzipper - **PATH TRAVERSAL VULNERABLE** (lines 27-58)
  - **.xml**: **XXE VULNERABLE** - parsed with libxml `noent: true` flag (lines 75-105)
  - **.yml/.yaml**: **YAML BOMB VULNERABLE** - parsed with `yaml.load()` (lines 108-136)
- **Destination**: `/uploads/complaints/` (for zip contents)

#### /profile/image/file (POST)
- **Multer Field**: `'file'` (single file to memory)
- **Size Limit**: 200KB
- **File**: `/repos/juice-shop/routes/profileImageFileUpload.ts`
- **Validation**: File type detection via `file-type` library, must be image/* MIME
- **Destination**: `frontend/dist/frontend/assets/public/images/uploads/{userId}.{ext}`

#### /profile/image/url (POST)
- **Body Parameter**: `imageUrl` (URL to fetch)
- **File**: `/repos/juice-shop/routes/profileImageUrlUpload.ts:16-49`
- **Validation**: **None on URL**
- **Vulnerability**: **SSRF** - fetches arbitrary URL via `fetch(url)`
- **Destination**: `frontend/dist/frontend/assets/public/images/uploads/{userId}.{ext}`

#### /rest/memories (POST)
- **Multer Field**: `'image'` (single file to disk)
- **File**: `/repos/juice-shop/routes/memory.ts:10-19`
- **Validation**: Must be image/* (png/jpeg/jpg), MIME type validation, filename sanitization
- **Destination**: `frontend/dist/frontend/assets/public/images/uploads/`
- **Filename**: `{sanitized-name}-{timestamp}.{ext}`

### 5.7 WebSocket Messages

**WebSocket Server**: Same port as HTTP (3000), Socket.io v3.1.2
**File**: `/repos/juice-shop/lib/startup/registerWebsocketEvents.ts`
**CORS**: `http://localhost:4200`

#### Client → Server Events:

| Event Name | Data Parameter | File:Line | Validation | Usage Description |
|------------|----------------|-----------|------------|-------------------|
| `notification received` | `data` (flag/notification ID) | `registerWebsocketEvents.ts:34` | None | Remove notification from cache |
| `verifyLocalXssChallenge` | `data` (payload string) | `registerWebsocketEvents.ts:41` | None | XSS detection check |
| `verifySvgInjectionChallenge` | `data` (payload string) | `registerWebsocketEvents.ts:46` | Regex + `isRedirectAllowed()` | SVG injection verification |
| `verifyCloseNotificationsChallenge` | `data` (array) | `registerWebsocketEvents.ts:50` | Array length check | Notification closure verification |

#### Server → Client Events:

| Event Name | Trigger | Description |
|------------|---------|-------------|
| `server started` | First connection | Server startup notification |
| `challenge solved` | Per cached notification | Challenge completion notification |

### 5.8 Special Input Vectors

#### Raw Body Parsing
- **File**: `/repos/juice-shop/routes/basketItems.ts:21`
- **Property**: `(req as RequestWithRawBody).rawBody`
- **Usage**: Custom JSON parser for basket items to handle property injection
- **Validation**: Custom parsing via `utils.parseJsonCustom()`

#### JWT Token Manipulation
- **Input Vector**: Authorization header or cookie
- **Validation Points**:
  - Algorithm validation (checks for 'none', 'HS256' vs 'RS256')
  - Signature verification
  - Expiration check
- **Vulnerable Scenarios**:
  - Unsigned JWT (algorithm: 'none')
  - Algorithm confusion (RS256 → HS256)

#### MongoDB $where Injection Points
1. **Track Order**: `this.orderId === '${id}'` (`trackOrder.ts:18`)
2. **Product Reviews**: `this.product == ${id}` (`showProductReviews.ts:36`)

#### Template Injection Points
1. **Username**: Evaluated via `eval()` if matches pattern `#{(...)}` (`userProfile.ts:55-67`)
2. **Data Erasure Layout**: Custom template path in `layout` parameter (`dataErasure.ts:68-82`)

### Input Vector Summary

**Total Input Vectors Identified**:
- **URL Parameters**: 17+ endpoints with path parameters
- **Query Parameters**: 6 distinct query parameters
- **POST Body Fields**: 40+ parameters across 25+ endpoints
- **HTTP Headers**: 7 headers (including authentication)
- **Cookies**: 2 cookies
- **File Uploads**: 4 endpoints (3 upload types)
- **WebSocket Messages**: 4 client→server event types
- **Special Vectors**: Raw body, JWT manipulation, NoSQL operators, template syntax

## 6. Network & Interaction Map

**Network Surface Focus**: This section maps components within the deployed, network-accessible infrastructure. Local development environments, build CI systems, and local-only tools are excluded.

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|-------|------|------|------|------|-------|
| JuiceShopWebApp | Service | App | Node/Express + Angular | PII, Tokens, Payments, Secrets | Main application backend + frontend SPA |
| SQLite-DB | DataStore | Data | SQLite3 | PII, Tokens, Payments | Stores users, products, baskets, orders, addresses, cards |
| MongoDB-Reviews | DataStore | Data | MongoDB | Public, PII | Stores product reviews and order history |
| FileSystem-FTP | DataStore | Data | Local FS | Public, Secrets | FTP directory with downloadable files |
| FileSystem-Uploads | DataStore | Data | Local FS | PII, Public | User-uploaded complaints, photos, profile images |
| FileSystem-Logs | DataStore | Data | Local FS | PII | Application logs with potential sensitive data |
| WebSocketServer | Service | App | Socket.io | Public, Tokens | Real-time notifications and challenge tracking |
| PrometheusMetrics | AdminPlane | App | prom-client | Public | Application metrics endpoint |
| SwaggerAPI | ExternAsset | App | swagger-ui | Public | API documentation interface |
| UserBrowser | ExternAsset | Internet | Browser + WS | N/A | End-user client (Angular SPA, WebSocket client) |

### 6.2 Entity Metadata

| Title | Metadata |
|-------|----------|
| JuiceShopWebApp | Hosts: `http://localhost:3000`; Endpoints: `/rest/*`, `/api/*`, `/ftp/*`, `/profile`, `/b2b/*`, `/rest/web3/*`; Auth: JWT (RS256), Session cookies, 2FA (TOTP); Dependencies: SQLite-DB, MongoDB-Reviews, FileSystem-FTP, FileSystem-Uploads, FileSystem-Logs; Port: 3000; Framework: Express v4.21.0 + Angular v20.1.0 |
| SQLite-DB | Engine: `SQLite3`; ORM: `Sequelize v6.37.3`; Exposure: `Internal Only (in-process)`; Consumers: `JuiceShopWebApp`; Tables: Users, Products, Baskets, BasketItems, Challenges, Feedbacks, SecurityQuestions, SecurityAnswers, Cards, Addresses, Wallets, Deliverys, Captchas, ImageCaptchas, Quantities, PrivacyRequests, Memories, Complaints, Recycles |
| MongoDB-Reviews | Engine: `MongoDB`; Exposure: `Internal Only (network/local)`; Consumers: `JuiceShopWebApp`; Collections: reviewsCollection, ordersCollection; Connection: Via mongodb client library |
| FileSystem-FTP | Path: `/ftp`; Access: `Public read via GET /ftp/:file`; Contents: Legal docs, package info, incident support files, acquisition docs; Vulnerabilities: Path traversal, null byte injection |
| FileSystem-Uploads | Path: `/uploads/complaints`, `frontend/dist/frontend/assets/public/images/uploads`; Access: `Authenticated upload, public/authenticated read`; Contents: Zip extracts, user photos, profile images; Vulnerabilities: Zip slip, XXE, YAML deserialization |
| FileSystem-Logs | Path: `/logs`; Access: `Public read via GET /support/logs/:file (with access check)`; Contents: Application logs; Vulnerabilities: Directory traversal |
| WebSocketServer | Port: `3000` (same as HTTP); Protocol: `Socket.io v3.1.2`; Auth: `None for connection, JWT for some events`; Events: `notification received`, `challenge solved`, `verifyLocalXssChallenge`, `verifySvgInjectionChallenge`; CORS: `http://localhost:4200` |
| PrometheusMetrics | Endpoint: `/metrics`; Auth: `None`; Data: HTTP request metrics, response times, status codes, custom counters; Library: `prom-client` |
| SwaggerAPI | Endpoint: `/api-docs`; Auth: `None`; Spec: `/swagger.yml`; UI: `swagger-ui-express`; Coverage: REST API documentation |
| UserBrowser | Components: `Angular SPA (client-side routing)`, `Socket.io client`, `HTTP client with interceptors`; Storage: `localStorage (token, basket)`, `sessionStorage (basket ID)`, `cookies (token)`; Guards: `LoginGuard`, `AdminGuard`, `AccountingGuard`, `DeluxeGuard` |

### 6.3 Flows (Connections)

| FROM → TO | Channel | Path/Port | Guards | Touches |
|-----------|---------|-----------|--------|---------|
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /` | None | Public |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /rest/user/login` | None | PII, Tokens |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /api/Users` (POST) | None | PII |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /rest/user/*` (authenticated) | auth:user | PII, Tokens |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /api/*` (authenticated) | auth:user | PII, Payments |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /rest/basket/:id` | auth:user, ownership:weak | PII, Payments |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /rest/order-history/orders` | auth:accounting | PII, Payments |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /api/Quantitys/*` | auth:accounting, ip-allowlist | Public |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /b2b/v2/orders` | auth:user | Public |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /ftp/:file` | None | Public, Secrets |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /profile` | auth:user | PII |
| UserBrowser → JuiceShopWebApp | HTTPS/HTTP | `:3000 /file-upload` | None | Public |
| UserBrowser → WebSocketServer | WebSocket | `:3000` (Socket.io) | None | Public, Tokens |
| JuiceShopWebApp → SQLite-DB | In-Process | SQLite file | None | PII, Tokens, Payments, Secrets |
| JuiceShopWebApp → MongoDB-Reviews | TCP | MongoDB connection | None | Public, PII |
| JuiceShopWebApp → FileSystem-FTP | File I/O | Local filesystem | None | Public, Secrets |
| JuiceShopWebApp → FileSystem-Uploads | File I/O | Local filesystem | None | PII, Public |
| JuiceShopWebApp → FileSystem-Logs | File I/O | Local filesystem | None | PII |
| PrometheusMetrics ← JuiceShopWebApp | HTTP | `:3000 /metrics` | None | Public |
| SwaggerAPI ← UserBrowser | HTTP | `:3000 /api-docs` | None | Public |
| JuiceShopWebApp → ExternalURL | HTTP/HTTPS | Internet | None (SSRF vuln) | Secrets |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|------------|----------|-----------|
| auth:user | Auth | Requires a valid user session or Bearer token for authentication. Implemented via `security.isAuthorized()` middleware using express-jwt. |
| auth:accounting | Authorization | Requires accounting role in JWT payload. Implemented via `security.isAccounting()` middleware checking `decodedToken.data.role === 'accounting'`. |
| auth:admin | Authorization | Requires admin role. Primarily frontend-only guard via `AdminGuard` route protection. No backend middleware found for admin role. |
| auth:deluxe | Authorization | Requires deluxe role with valid deluxe token. Implemented via `security.isDeluxe()` checking role and deluxe token hash. |
| ownership:weak | ObjectOwnership | Attempts to verify requesting user owns target object (e.g., basket, order) but implementation is weak or missing. Example: basket access checks user.bid == basket.id but comparison is weak (line vs strict equality). |
| ownership:user | ObjectOwnership | Properly verifies requesting user owns target object via `appendUserId()` middleware + database query with UserId filter. Used for addresses, cards, wallet operations. |
| ip-allowlist | Network | Restricts access to specific IP address. Used for Quantity management endpoints with hardcoded IP `123.456.789` (invalid IP - likely intentional vuln). |
| captcha:math | RateLimit | Requires solving math CAPTCHA. Generated via `/rest/captcha` and verified on submission. |
| captcha:image | RateLimit | Requires solving image CAPTCHA. Generated via `/rest/image-captcha` and verified on submission. |
| ratelimit:password | RateLimit | Rate limiting on password reset endpoint (100 requests per 5 minutes). |
| ratelimit:2fa | RateLimit | Rate limiting on 2FA endpoints (100 requests per 5 minutes). |
| none | Auth | No authentication or authorization required. Endpoint is publicly accessible. |
| blocked | Authorization | Access denied to all users via `security.denyAll()` using random secret in express-jwt validation. Intentionally blocks certain administrative operations. |

## 7. Role & Privilege Architecture

This section maps the application's authorization model for comprehensive privilege escalation analysis.

### 7.1 Discovered Roles

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|-----------|----------------|--------------|---------------------|
| anon | 0 | Global | No authentication required, implicit role |
| customer | 1 | Global | Base authenticated user role, default for registration |
| deluxe | 2 | Global | Paying members with enhanced benefits, requires payment |
| accounting | 5 | Global | Can view all orders and manage inventory quantities |
| admin | 10 | Global | Full application administration (frontend-only enforcement) |

**Code Definitions**:
- `/repos/juice-shop/lib/insecurity.ts:144-149`
- `/repos/juice-shop/models/user.ts:80-84`
- `/repos/juice-shop/frontend/src/app/roles.ts:6-11`

### 7.2 Privilege Lattice

```
Privilege Ordering (→ means "can access resources of"):
anon → customer → deluxe
             ↓
        accounting
             ↓
           admin

Hierarchy Analysis:
- anon: No privileges, can only access public endpoints
- customer: Can manage own data (baskets, orders, addresses, cards)
- deluxe: Same as customer + lower prices, no quantity limits, special membership features
- accounting: Can view ALL orders, manage inventory quantities, view financial data
- admin: Can access admin panel (frontend route), potentially elevated privileges

Parallel Isolation:
- deluxe and accounting are parallel (not ordered relative to each other)
- deluxe focuses on shopping benefits
- accounting focuses on business operations
- admin dominates all roles
```

**Role Switching**: None implemented (no impersonation or temporary elevation)

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|------|---------------------|---------------------------|----------------------|
| anon | `/` | `/`, `/login`, `/register`, `/ftp/*`, `/api/Products`, `/api/Feedbacks`, `/rest/products/search`, `/rest/captcha`, `/api-docs` | None |
| customer | `/` or `/search` | All anon routes + `/api/BasketItems`, `/api/Cards`, `/api/Addresss`, `/rest/basket/*`, `/rest/order-history`, `/profile`, `/rest/wallet/*`, `/api/Complaints`, `/rest/chatbot/*` | JWT Bearer token in Authorization header |
| deluxe | `/` or `/search` | All customer routes + special pricing | JWT Bearer token with deluxe role and deluxe token |
| accounting | `/` or `/accounting` | All customer routes + `/rest/order-history/orders`, `/api/Quantitys/*` | JWT Bearer token with accounting role |
| admin | `/administration` | Frontend route `/administration` protected by AdminGuard | JWT Bearer token with admin role (frontend only) |

**Frontend Route Guards**:
- `/repos/juice-shop/frontend/src/app/app.routing.ts:63-71`
- LoginGuard: All authenticated routes
- AdminGuard: `/administration`
- AccountingGuard: `/accounting`
- DeluxeGuard: Deluxe-specific features

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|------|-------------------|-------------------|------------------|
| anon | None | N/A | N/A |
| customer | `requireAuth()`, `isAuthorized()` | `security.isAuthorized()` validates JWT | JWT payload field `data.role`, database Users table `role` column |
| deluxe | `isDeluxe()` | `decodedToken.data.role === 'deluxe' && decodedToken.data.deluxeToken === deluxeToken(email)` | JWT payload field `data.role` + `data.deluxeToken` |
| accounting | `isAccounting()` | `decodedToken.data.role === 'accounting'` | JWT payload field `data.role` |
| admin | `AdminGuard` (frontend only) | Frontend: `localStorage.getItem('token')` → decode → `role === 'admin'` | JWT payload field `data.role` |

**Code Locations**:
- **Middleware**: `/repos/juice-shop/lib/insecurity.ts:54-175`
- **Frontend Guards**: `/repos/juice-shop/frontend/src/app/app.guard.ts`
- **Route Protection**: `/repos/juice-shop/server.ts` (various lines)
- **Role Constants**: `/repos/juice-shop/lib/insecurity.ts:144-149`

## 8. Authorization Vulnerability Candidates

This section identifies specific endpoints prime for authorization testing, organized by vulnerability type.

### 8.1 Horizontal Privilege Escalation Candidates

Endpoints with object identifiers that may allow access to other users' resources (IDOR vulnerabilities).

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity | Reason |
|----------|-----------------|---------------------|-----------|-------------|--------|
| **High** | `GET /rest/basket/:id` | `basket_id` | shopping_cart | PII, Payments | Weak ownership check (`==` vs `===`), challenge tracks but doesn't prevent. `/repos/juice-shop/routes/basket.ts:17-24` |
| **High** | `POST /rest/basket/:id/checkout` | `basket_id` | order_financial | Payments, PII | No ownership validation, can checkout any basket. `/repos/juice-shop/routes/order.ts:36` |
| **High** | `GET /rest/track-order/:id` | `order_id` | order_tracking | PII | No authentication required, can track any order. `/repos/juice-shop/routes/trackOrder.ts:12-18` |
| **High** | `POST /rest/user/data-export` | `UserId` (body) | gdpr_export | PII, All user data | UserId from request body, not from JWT. `/repos/juice-shop/routes/dataExport.ts:53` |
| **High** | `GET /api/Recycles/:id` | `recycle_id` | recycle_request | PII | No ownership check, JSON.parse injection. `/repos/juice-shop/routes/recycles.ts:14` |
| **High** | `PUT /rest/products/:id/reviews` | `product_id`, `author` (body) | product_review | user_data | Author can be forged via body parameter. `/repos/juice-shop/routes/createProductReviews.ts:17-20,26` |
| **High** | `PATCH /rest/products/reviews` | `id` (body) | product_review | user_data | No ownership check, can update any review. `/repos/juice-shop/routes/updateProductReviews.ts:16-20` |
| **Medium** | `GET /rest/memories` | None (returns all) | user_photos | PII | Returns ALL user memories, no privacy. `/repos/juice-shop/routes/memory.ts:24` |
| **Medium** | `GET /api/Users/:id` | `user_id` | user_profile | PII | Authentication required but no ownership check. `/repos/juice-shop/server.ts:359` |
| **Medium** | `GET /api/Feedbacks/:id` | `feedback_id` | customer_feedback | user_data | Authentication required but no ownership check. `/repos/juice-shop/server.ts:355` |
| **Low** | `PUT /rest/basket/:id/coupon/:coupon` | `basket_id` | coupon_application | financial | No authentication, can apply coupons to any basket. `/repos/juice-shop/routes/coupon.ts:13` |

**Properly Protected Endpoints** (for comparison):
- `GET /api/Cards`, `GET /api/Cards/:id`, `DELETE /api/Cards/:id` - All validate UserId via `appendUserId()` middleware
- `GET /api/Addresss`, `GET /api/Addresss/:id`, `DELETE /api/Addresss/:id` - All validate UserId
- `GET /rest/wallet/balance`, `PUT /rest/wallet/balance` - Validates UserId
- `GET /profile`, `POST /profile` - Validates logged-in user from cookie token

### 8.2 Vertical Privilege Escalation Candidates

Endpoints requiring higher privileges, organized by target role.

#### Accounting Role Escalation

| Endpoint Pattern | Functionality | Risk Level | File:Line |
|-----------------|---------------|------------|-----------|
| `GET /rest/order-history/orders` | View all orders from all customers | **High** | `/repos/juice-shop/routes/orderHistory.ts:25` |
| `PUT /rest/order-history/:id/delivery-status` | Toggle delivery status for any order | **High** | `/repos/juice-shop/routes/orderHistory.ts:32` |
| `GET /api/Quantitys/:id` | View inventory quantities | **Medium** | `/repos/juice-shop/server.ts:425` |
| `PUT /api/Quantitys/:id` | Update inventory quantities | **High** | `/repos/juice-shop/server.ts:425` |

**Exploit Path**: JWT role manipulation (change `role: 'customer'` to `role: 'accounting'` if signature not verified or algorithm confusion attack)

#### Admin Role Escalation

| Endpoint Pattern | Functionality | Risk Level | File:Line |
|-----------------|---------------|------------|-----------|
| `/administration` (Frontend) | Admin panel access | **High** | Frontend route protected by AdminGuard only |

**Critical Finding**: Admin role only enforced on **frontend routes**, no backend API endpoints require admin role. Admin privileges may not be properly enforced server-side.

#### Deluxe Role Escalation

| Endpoint Pattern | Functionality | Risk Level | File:Line |
|-----------------|---------------|------------|-----------|
| Deluxe pricing | Lower product prices | **Low** | Business logic in product pricing |
| Quantity bypass | No quantity limits | **Low** | Validation in basket item operations |

**Exploit Path**:
1. JWT role manipulation (`role: 'customer'` → `role: 'deluxe'`)
2. Payment bypass via `/rest/deluxe-membership` with manipulated payment data (lines 44-45 may have payment bypass vuln)

### 8.3 Context-Based Authorization Candidates

Multi-step workflow endpoints that may assume prior steps were completed.

| Workflow | Endpoint | Expected Prior State | Bypass Potential | File:Line |
|----------|----------|---------------------|------------------|-----------|
| **Checkout** | `POST /rest/basket/:id/checkout` | Cart populated, payment method selected, delivery address added | Direct checkout with minimal data, basket ID manipulation | `/repos/juice-shop/routes/order.ts:33` |
| **Password Reset** | `POST /rest/user/reset-password` | Security question answered (via separate endpoint) | Direct call with guessed/enumerated security answer | `/repos/juice-shop/routes/resetPassword.ts:16` |
| **2FA Verification** | `POST /rest/2fa/verify` | Initial login completed, temp token obtained | Temp token manipulation or brute force TOTP codes | `/repos/juice-shop/routes/2fa.ts:22` |
| **Deluxe Upgrade** | `POST /rest/deluxe-membership` | Payment method added, sufficient balance | Payment bypass via payment mode manipulation | `/repos/juice-shop/routes/deluxe.ts:16` |
| **File Upload Processing** | `POST /file-upload` | CAPTCHA solved (in some challenge modes) | Skip validation by manipulating challenge state | `/repos/juice-shop/routes/fileUpload.ts` |
| **Data Erasure** | `POST /dataerasure` | Security question answered | Direct call with security answer bypass | `/repos/juice-shop/routes/dataErasure.ts:54` |

### 8.4 Mass Assignment / Parameter Tampering Candidates

Endpoints that may allow privilege escalation through additional parameters.

| Endpoint | Tamperable Parameter | Escalation Risk | File:Line |
|----------|---------------------|-----------------|-----------|
| `POST /api/Users` | `role` in request body | Can register as admin/accounting/deluxe | `/repos/juice-shop/server.ts:402-416` |
| `POST /api/Feedbacks` | `UserId` in request body | Submit feedback as other users | `/repos/juice-shop/server.ts:396-400` |
| `POST /api/BasketItems` | `BasketId` in request body | Add items to other users' baskets | `/repos/juice-shop/routes/basketItems.ts:19-54` |
| `POST /rest/user/data-export` | `UserId` in request body | Export other users' data | `/repos/juice-shop/routes/dataExport.ts:53` |
| `PUT /rest/products/:id/reviews` | `author` in request body | Forge reviews as other users | `/repos/juice-shop/routes/createProductReviews.ts:26` |

### 8.5 Broken Function Level Authorization

Endpoints that should be restricted but have weak/missing authorization.

| Endpoint | Expected Protection | Actual Protection | Risk | File:Line |
|----------|---------------------|-------------------|------|-----------|
| `PUT /api/Products/:id` | Admin only | **None** (commented out) | Can modify any product | `/repos/juice-shop/server.ts:364` |
| `DELETE /api/Feedbacks/:id` | User can only delete own feedback | **None** | Can delete any feedback | `/repos/juice-shop/server.ts:480` |
| `GET /api/Users` | Admin only | User auth only | List all users | `/repos/juice-shop/server.ts:357` |
| `GET /api/Users/:id` | Own profile or admin | User auth only | View any user profile | `/repos/juice-shop/server.ts:359` |
| `POST /api/Products` | Admin only | User auth only | Create products | `/repos/juice-shop/server.ts:363` |
| `GET /rest/memories` | Own memories | **None** | View all user photos | `/repos/juice-shop/routes/memory.ts:22` |

## 9. Injection Sources (Command Injection, SQL Injection, LFI/RFI, SSTI, Path Traversal, Deserialization)

**Network Surface Focus**: This section reports injection sources reachable through the target web application's network interface. Local-only scripts, build tools, and development utilities are excluded.

### 9.1 SQL Injection Sources

#### 9.1.1 Login Endpoint - Email/Password SQL Injection
- **File**: `/repos/juice-shop/routes/login.ts:34`
- **User Input**: `req.body.email`, `req.body.password`
- **Dangerous Sink**: `models.sequelize.query()` with string interpolation
- **Data Flow**:
  ```
  POST /rest/user/login {email, password}
  → req.body.email/password (no validation)
  → String interpolation: `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}'`
  → sequelize.query() execution
  ```
- **Vulnerability**: Classic SQL injection, both email and password parameters
- **Example Payloads**: `' OR '1'='1`, `' UNION SELECT ...`, `' OR 1=1--`

#### 9.1.2 Product Search - Query Parameter SQL Injection
- **File**: `/repos/juice-shop/routes/search.ts:23`
- **User Input**: `req.query.q`
- **Dangerous Sink**: `models.sequelize.query()` with string interpolation
- **Data Flow**:
  ```
  GET /rest/products/search?q=<query>
  → req.query.q (truncated to 200 chars, no sanitization)
  → String interpolation: `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') ...`
  → sequelize.query() execution
  ```
- **Vulnerability**: UNION-based SQL injection in LIKE clause
- **Example Payloads**: `'))UNION SELECT...--`, `'))OR 1=1--`

### 9.2 NoSQL Injection Sources

#### 9.2.1 Track Order - MongoDB $where Injection
- **File**: `/repos/juice-shop/routes/trackOrder.ts:18`
- **User Input**: `req.params.id`
- **Dangerous Sink**: `db.ordersCollection.find({ $where: ... })`
- **Data Flow**:
  ```
  GET /rest/track-order/:id
  → req.params.id (conditional sanitization/truncation)
  → String interpolation: `this.orderId === '${id}'`
  → MongoDB $where clause execution (JavaScript)
  ```
- **Vulnerability**: JavaScript injection in MongoDB $where, can execute arbitrary JS
- **Example Payloads**: `'; return true; var x='`, `'; return this.email; var x='`

#### 9.2.2 Product Reviews - MongoDB $where Injection with RCE
- **File**: `/repos/juice-shop/routes/showProductReviews.ts:36`
- **User Input**: `req.params.id`
- **Dangerous Sink**: `db.reviewsCollection.find({ $where: ... })`
- **Data Flow**:
  ```
  GET /rest/products/:id/reviews
  → req.params.id (conditional conversion to Number or truncation)
  → Direct concatenation: `this.product == ${id}`
  → MongoDB $where clause execution
  ```
- **Vulnerability**: JavaScript injection with global.sleep() available for DoS
- **Example Payloads**: `1; return true`, `1 || global.sleep(5000)`

#### 9.2.3 Update Reviews - NoSQL Operator Injection
- **File**: `/repos/juice-shop/routes/updateProductReviews.ts:17-20`
- **User Input**: `req.body.id`
- **Dangerous Sink**: `db.reviewsCollection.update()`
- **Data Flow**:
  ```
  PATCH /rest/products/reviews {id, message}
  → req.body.id (no validation)
  → MongoDB query: `{ _id: req.body.id }`
  → update with `{ multi: true }`
  ```
- **Vulnerability**: Can match multiple documents via operators like `{"$ne": null}`
- **Example Payloads**: `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`

#### 9.2.4 Recycle Items - Sequelize Operator Injection
- **File**: `/repos/juice-shop/routes/recycles.ts:14`
- **User Input**: `req.params.id`
- **Dangerous Sink**: `RecycleModel.findAll({ where: { id: JSON.parse(...) } })`
- **Data Flow**:
  ```
  GET /api/Recycles/:id
  → req.params.id (no validation)
  → JSON.parse(req.params.id)
  → Sequelize where clause
  ```
- **Vulnerability**: Sequelize operator injection via parsed JSON object
- **Example Payloads**: `{"$gt":0}`, `{"$ne":null}`, `{"$or":[...]}`

### 9.3 Command Injection / Code Execution Sources

#### 9.3.1 B2B Order - JavaScript eval() RCE
- **File**: `/repos/juice-shop/routes/b2bOrder.ts:19-23`
- **User Input**: `req.body.orderLinesData`
- **Dangerous Sink**: `vm.runInContext('safeEval(orderLinesData)', sandbox)`
- **Data Flow**:
  ```
  POST /b2b/v2/orders {orderLinesData}
  → req.body.orderLinesData (no validation)
  → Passed to notevil safeEval in VM context
  → vm.runInContext() execution
  ```
- **Vulnerability**: notevil sandbox escape leading to RCE
- **Example Payloads**: notevil bypass techniques, constructor access, prototype pollution

#### 9.3.2 User Profile - eval() SSTI
- **File**: `/repos/juice-shop/routes/userProfile.ts:55-62`
- **User Input**: `user.username` (from database, set via chatbot)
- **Dangerous Sink**: `eval(code)`
- **Data Flow**:
  ```
  POST /rest/chatbot/respond {action:'setname', query:'#{payload}'}
  → Username saved to database
  GET /profile
  → user.username loaded from DB
  → Pattern match: `#{(.*)}` → extract code
  → eval(code) execution
  ```
- **Vulnerability**: Direct eval() of username content, full RCE
- **Example Payloads**: `#{global.process.mainModule.require('child_process').exec('cmd')}`

### 9.4 Path Traversal / LFI Sources

#### 9.4.1 FTP File Server - Null Byte Path Traversal
- **File**: `/repos/juice-shop/routes/fileServer.ts:28-33`
- **User Input**: `req.params.file`
- **Dangerous Sink**: `res.sendFile(path.resolve('ftp/', file))`
- **Data Flow**:
  ```
  GET /ftp/:file
  → req.params.file (slash check, extension check)
  → Null byte removed AFTER extension check
  → path.resolve('ftp/', file)
  → res.sendFile()
  ```
- **Vulnerability**: Null byte injection bypasses extension check
- **Example Payloads**: `package.json.bak%00.md`, `../package.json%00.pdf`

#### 9.4.2 Data Erasure - LFI via layout Parameter
- **File**: `/repos/juice-shop/routes/dataErasure.ts:68-82`
- **User Input**: `req.body.layout`
- **Dangerous Sink**: `res.render('dataErasureResult', { ...req.body })`
- **Data Flow**:
  ```
  POST /dataerasure {layout}
  → req.body.layout (weak blacklist: ftp, ctf.key, encryptionkeys)
  → path.resolve(req.body.layout).toLowerCase()
  → res.render() with custom layout path
  → First 100 chars returned
  ```
- **Vulnerability**: LFI with weak blacklist, can read arbitrary files
- **Example Payloads**: `/etc/passwd`, `../../../etc/hosts`, `/package.json`

#### 9.4.3 Zip Upload - Zip Slip Path Traversal
- **File**: `/repos/juice-shop/routes/fileUpload.ts:27-49`
- **User Input**: Zip file entry paths (`entry.path`)
- **Dangerous Sink**: `fs.createWriteStream('uploads/complaints/' + fileName)`
- **Data Flow**:
  ```
  POST /file-upload {file: zip}
  → Zip extracted via unzipper
  → entry.path read from zip (no sanitization)
  → absolutePath = path.resolve('uploads/complaints/' + fileName)
  → Weak check: absolutePath.includes(path.resolve('.'))
  → fs.createWriteStream() with path
  ```
- **Vulnerability**: Zip slip - write arbitrary files via `../../` in zip entry names
- **Example Payloads**: Zip with entry `../../ftp/legal.md`

#### 9.4.4 Log/Quarantine/Key File Servers - Directory Traversal
- **Files**: `/repos/juice-shop/routes/logfileServer.ts:11`, `quarantineServer.ts:11`, `keyServer.ts:11`
- **User Input**: `req.params.file`
- **Dangerous Sink**: `res.sendFile(path.resolve(dir, file))`
- **Data Flow**: Same pattern as FTP server, forward slash check only
- **Vulnerability**: Limited by forward slash check but may be bypassable
- **Endpoints**: `GET /support/logs/:file`, `GET /ftp/quarantine/:file`, `GET /encryptionkeys/:file`

### 9.5 Server-Side Template Injection (SSTI)

#### 9.5.1 User Profile - Pug Template Injection
- **File**: `/repos/juice-shop/routes/userProfile.ts:26-98`
- **User Input**: `user.username` (via database)
- **Dangerous Sink**: `pug.compile(template)` after string replacement
- **Data Flow**:
  ```
  Username set via chatbot → stored in DB
  GET /profile
  → user.username loaded
  → template = template.replace(/_username_/g, username)
  → pug.compile(template)
  → fn(user) execution
  ```
- **Vulnerability**: Pug template injection + eval() RCE
- **Example Payloads**: Pug syntax with JavaScript expressions

### 9.6 Deserialization / XXE / YAML Injection

#### 9.6.1 XML Upload - XXE Injection
- **File**: `/repos/juice-shop/routes/fileUpload.ts:75-87`
- **User Input**: Uploaded XML file content
- **Dangerous Sink**: `libxml.parseXml(data, { noent: true, nocdata: true })`
- **Data Flow**:
  ```
  POST /file-upload {file: xml}
  → file.buffer.toString()
  → libxml.parseXml() with noent:true (enables entity expansion)
  → xmlDoc.toString()
  ```
- **Vulnerability**: XXE with entity expansion enabled, can read local files
- **Example Payloads**: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

#### 9.6.2 YAML Upload - YAML Deserialization
- **File**: `/repos/juice-shop/routes/fileUpload.ts:108-136`
- **User Input**: Uploaded YAML file content
- **Dangerous Sink**: `yaml.load(data)` in VM context
- **Data Flow**:
  ```
  POST /file-upload {file: yaml/yml}
  → file.buffer.toString()
  → yaml.load(data) (unsafe - allows object instantiation)
  → JSON.stringify(parsed)
  ```
- **Vulnerability**: YAML deserialization, YAML bomb DoS
- **Example Payloads**: YAML bomb (deeply nested structures), potential object injection

### 9.7 SSRF (Server-Side Request Forgery)

#### 9.7.1 Profile Image URL Upload - SSRF
- **File**: `/repos/juice-shop/routes/profileImageUrlUpload.ts:17-31`
- **User Input**: `req.body.imageUrl`
- **Dangerous Sink**: `fetch(url)`
- **Data Flow**:
  ```
  POST /profile/image/url {imageUrl}
  → req.body.imageUrl (no validation)
  → fetch(url) - arbitrary HTTP/HTTPS request
  → Response saved as profile image
  ```
- **Vulnerability**: SSRF to internal services, metadata endpoints, localhost
- **Example Payloads**: `http://localhost/solve/challenges/server-side`, `http://169.254.169.254/latest/meta-data/`

### 9.8 XSS Injection Sources (Stored)

#### 9.8.1 True-Client-IP Header - Stored XSS
- **File**: `/repos/juice-shop/routes/saveLoginIp.ts:18`
- **User Input**: `req.headers['true-client-ip']`
- **Dangerous Sink**: Database storage → later displayed
- **Data Flow**:
  ```
  Any request with True-Client-IP header
  → req.headers['true-client-ip'] (conditional sanitization)
  → Stored in database as lastLoginIp
  → Displayed in user profile (not shown in this file)
  ```
- **Vulnerability**: Stored XSS via custom header
- **Example Payload**: `<iframe src="javascript:alert('xss')">`

### Injection Source Summary

**Total Injection Sources Identified**: 20+
- **SQL Injection**: 2 sources (login, search)
- **NoSQL Injection**: 4 sources (order tracking, reviews get/update, recycles)
- **Command/Code Injection**: 2 sources (B2B order, user profile eval)
- **Path Traversal/LFI**: 5 sources (FTP, data erasure, zip upload, log/quarantine/key servers)
- **SSTI**: 1 source (user profile Pug)
- **Deserialization/XXE/YAML**: 2 sources (XML upload, YAML upload)
- **SSRF**: 1 source (profile image URL)
- **XSS (Stored)**: 1 source (True-Client-IP header)

All identified sources are in **network-accessible code paths** and can be reached through the web application's HTTP/HTTPS interface.
