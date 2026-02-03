# Security Audit Report
**Date:** 2026-01-23  
**Audited Against:** ANTI_PATTERNS_BREADTH.md  
**Project:** ArmisUpload - Firmware Upload Proxy

---

## Executive Summary

Overall, this codebase demonstrates **strong security practices** with comprehensive input validation, sanitization, and security headers. However, several **critical and high-severity issues** were identified that require immediate attention.

**Risk Level:** 🟡 MODERATE (would be HIGH without the identified strengths)

---

## ✅ Security Strengths

### 1. Input Validation & Sanitization (CWE-20)
- ✅ **Excellent server-side validation** for all user inputs
- ✅ Proper sanitization functions: `sanitizeDeviceId()`, `sanitizeName()`, `validateEmail()`, `sanitizeFilename()`
- ✅ Uses `path.basename()` to prevent path traversal
- ✅ Type checking before validation
- ✅ Length limits enforced (255 chars)
- ✅ Regex validation for device IDs and emails
- ✅ Client-side validation is supplementary, not relied upon

### 2. XSS Prevention (CWE-79)
- ✅ Uses `textContent` instead of `innerHTML` for error messages (line 821)
- ✅ Sanitizes URL parameters with `sanitizeInput()` function
- ✅ HTML encoding in client-side sanitization
- ✅ Validates device ID format from URL parameters

### 3. Security Headers (CWE-16)
- ✅ Comprehensive security headers middleware (lines 256-305)
- ✅ X-Frame-Options: DENY
- ✅ X-Content-Type-Options: nosniff
- ✅ X-XSS-Protection enabled
- ✅ Content-Security-Policy configured
- ✅ Referrer-Policy set
- ✅ Permissions-Policy configured

### 4. Rate Limiting (CWE-770)
- ✅ Rate limiting implemented (lines 326-375)
- ✅ 10 uploads per 15 minutes per IP
- ✅ Automatic cleanup of old entries

### 5. File Upload Security (CWE-434)
- ✅ File type validation with whitelist
- ✅ MIME type checking
- ✅ Extension validation
- ✅ File size limits (50GB max)
- ✅ Temporary file cleanup on error

### 6. SQL Injection Protection (CWE-89)
- ✅ No direct SQL queries in code
- ✅ Uses API calls instead of database access

---

## 🔴 CRITICAL Issues

### 1. **Hardcoded Secrets Risk** (CWE-798) - CRITICAL
**Location:** `server.js:696`

**Issue:**
```javascript
const apiKey = process.env.API_KEY;
```

While the API key is loaded from environment variables (GOOD), there's no validation that the `.env` file itself isn't committed to version control.

**Evidence of Risk:**
- `.env.example` exists (GOOD)
- No explicit check that `.env` is in `.gitignore`

**Recommendation:**
```bash
# Verify .env is gitignored
echo ".env" >> .gitignore
git rm --cached .env 2>/dev/null || true
```

**Severity:** CRITICAL  
**CVSS:** 9.8 (if leaked)

---

### 2. **TLS Certificate Validation Disabled in Non-Production** (CWE-295) - CRITICAL
**Location:** `server.js:24`

**Issue:**
```javascript
rejectUnauthorized: process.env.NODE_ENV === 'production'
```

This disables certificate verification in development/staging, creating a **man-in-the-middle vulnerability**.

**Attack Scenario:**
1. Developer runs app in dev mode
2. Attacker on network performs MITM attack
3. API key is intercepted over "HTTPS" connection
4. Attacker gains access to Finite State platform

**Recommendation:**
```javascript
// SECURE: Always reject unauthorized certificates
rejectUnauthorized: true,

// For debugging TLS in dev, use separate proxy config
// Never disable in production code
```

**Severity:** CRITICAL  
**CVSS:** 8.1  
**Reference:** ANTI_PATTERNS Section 1.3, 5.x

---

### 3. **Injection Risk in API Filter** (CWE-943) - HIGH
**Location:** `server.js:394, 450`

**Issue:**
```javascript
filter: `name=="${folderName}"`
filter: `name=="${projectName}"`
```

While `folderName` and `projectName` are sanitized (derived from `customer` and `deviceId`), there's no explicit escaping for the filter query syntax. If the API uses a query language, this could be injectable.

**Attack Vector:**
```javascript
// If deviceId = 'test" OR "1"=="1'
// Filter becomes: name=="test" OR "1"=="1"
```

**Current Protection:**
- `sanitizeDeviceId()` allows only `[a-zA-Z0-9._-]+`
- This prevents injection BUT relies on sanitization correctness

**Recommendation:**
Add explicit filter escaping:
```javascript
function escapeFilterValue(value) {
  // Escape quotes and backslashes for filter queries
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

params: {
  filter: `name=="${escapeFilterValue(folderName)}"`
}
```

**Severity:** HIGH  
**CVSS:** 7.3  
**Reference:** ANTI_PATTERNS Section 2.5 (NoSQL Injection)

---

## 🟠 HIGH Severity Issues

### 4. **Missing HTTPS Enforcement** (CWE-319) - HIGH
**Location:** `server.js:891`

**Issue:**
```javascript
app.listen(3000, () => console.log("Server running at http://localhost:3000"));
```

The application runs on HTTP without TLS. While HSTS header is commented out (line 296), there's no enforcement.

**Risk:**
- API keys transmitted in plain text over network
- Session hijacking possible
- MITM attacks trivial

**Recommendation:**
```javascript
import https from 'https';
import fs from 'fs';

// Load TLS certificates
const httpsOptions = {
  key: fs.readFileSync(process.env.TLS_KEY_PATH || './certs/key.pem'),
  cert: fs.readFileSync(process.env.TLS_CERT_PATH || './certs/cert.pem')
};

const server = https.createServer(httpsOptions, app);
server.listen(3000, () => console.log("Server running at https://localhost:3000"));

// Enable HSTS
res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
```

**Severity:** HIGH  
**CVSS:** 7.4  
**Reference:** ANTI_PATTERNS Section 1.x (Secrets in transit)

---

### 5. **CSP Allows Unsafe-Inline** (CWE-79) - HIGH
**Location:** `server.js:269`

**Issue:**
```javascript
"script-src 'self' 'unsafe-inline'; " +
"style-src 'self' 'unsafe-inline'; "
```

`'unsafe-inline'` defeats the purpose of CSP by allowing inline scripts, which are the primary XSS vector.

**Current Risk:**
If an XSS vulnerability is introduced later, CSP won't block it.

**Recommendation:**
Use CSP nonces:
```javascript
// Generate nonce per request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy', 
    `default-src 'self'; ` +
    `script-src 'self' 'nonce-${res.locals.nonce}'; ` +
    `style-src 'self' 'nonce-${res.locals.nonce}';`
  );
  next();
});

// In HTML: <script nonce="${nonce}">...</script>
```

**Severity:** HIGH  
**CVSS:** 6.5  
**Reference:** ANTI_PATTERNS Section 3.4

---

### 6. **No Session Management** (CWE-287) - HIGH
**Location:** N/A

**Issue:**
The application has no authentication or session management. Anyone with the URL can upload files.

**Risk:**
- Unauthorized users can upload malicious files
- No audit trail of who uploaded what
- Abuse potential (rate limiting helps but isn't sufficient)

**Recommendation:**
Implement authentication:
```javascript
// Option 1: API key per user
app.use('/upload', requireApiKey);

// Option 2: Session-based auth
app.use('/upload', requireSession);

// Option 3: OAuth/OIDC
app.use('/upload', passport.authenticate('oauth2'));
```

**Severity:** HIGH  
**CVSS:** 7.5  
**Reference:** ANTI_PATTERNS Section 4.1-4.7

---

### 7. **Missing Request Origin Validation** (CWE-346) - MEDIUM
**Location:** Missing

**Issue:**
No CORS configuration or origin validation. Any website can make requests to this server if accessible.

**Recommendation:**
```javascript
import cors from 'cors';

// Whitelist specific origins
const allowedOrigins = [
  'https://your-frontend.com',
  process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : null
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
```

**Severity:** MEDIUM  
**CVSS:** 5.3  
**Reference:** ANTI_PATTERNS Quick Reference Table

---

## 🟡 MEDIUM Severity Issues

### 8. **Verbose Error Messages** (CWE-209) - MEDIUM
**Location:** `server.js:808-833`

**Issue:**
```javascript
console.error("Upload error:", {
  message: error.message,
  code: error.code,
  errno: error.errno,
  syscall: error.syscall,
  cause: error.cause?.message,
  response: error.response?.data,
  status: error.response?.status,
  stack: process.env.NODE_ENV === 'development' || DEBUG_MODE ? error.stack : undefined
});
```

While errors aren't sent to the client (GOOD), detailed logs could expose sensitive information if logs are compromised.

**Recommendation:**
```javascript
// Sanitize error logs
console.error("Upload error:", {
  message: error.message,
  code: error.code,
  status: error.response?.status,
  // Never log: API responses, stack traces in production, syscall details
});
```

**Severity:** MEDIUM  
**CVSS:** 4.3  
**Reference:** ANTI_PATTERNS Section (Verbose Error Messages)

---

### 9. **No Request Size Limit for Files** (CWE-770) - MEDIUM
**Location:** `server.js:250-253`

**Issue:**
```javascript
limits: { 
  fileSize: 50 * 1024 * 1024 * 1024, // 50GB
```

50GB is extremely large and could enable DoS attacks.

**Risk:**
- Single user can consume massive bandwidth
- Disk space exhaustion
- Memory issues during processing

**Recommendation:**
```javascript
// Reduce to reasonable limit
fileSize: 5 * 1024 * 1024 * 1024, // 5GB

// Or make configurable
fileSize: parseInt(process.env.MAX_FILE_SIZE) || (5 * 1024 * 1024 * 1024)
```

**Severity:** MEDIUM  
**CVSS:** 5.3  
**Reference:** ANTI_PATTERNS Section 6.1

---

### 10. **Rate Limiting Store in Memory** (CWE-770) - MEDIUM
**Location:** `server.js:326`

**Issue:**
```javascript
const rateLimitStore = new Map();
```

In-memory rate limiting doesn't work with multiple server instances (load balancing).

**Recommendation:**
```javascript
// Use Redis for distributed rate limiting
import Redis from 'ioredis';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';

const redis = new Redis(process.env.REDIS_URL);

const limiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'upload_rl:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 10
});

app.post('/upload', limiter, ...);
```

**Severity:** MEDIUM  
**CVSS:** 4.9  
**Reference:** ANTI_PATTERNS Section 4.2

---

## 🟢 LOW Severity / Informational Issues

### 11. **No Logging/Audit Trail** - LOW
**Issue:** No structured logging or audit trail for uploads.

**Recommendation:**
Implement structured logging with user identification, timestamps, and file metadata.

---

### 12. **File Cleanup Race Condition** - LOW
**Location:** `server.js:826-834`

**Issue:** Multiple `fs.unlinkSync()` calls could race if errors occur.

**Recommendation:**
Use a single cleanup function:
```javascript
function cleanupFile(filePath) {
  if (filePath && fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (err) {
      console.error('Cleanup failed:', err.message);
    }
  }
}
```

---

### 13. **No Helmet.js Usage** - INFORMATIONAL
**Recommendation:**
Consider using `helmet.js` for automatic security header management:
```javascript
import helmet from 'helmet';
app.use(helmet());
```

---

## 📊 Summary Statistics

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 2 | 🔴 Requires immediate fix |
| High | 5 | 🟠 Fix within 1 week |
| Medium | 5 | 🟡 Fix within 1 month |
| Low | 3 | 🟢 Address as time permits |
| **Total** | **15** | |

---

## 🎯 Priority Remediation Roadmap

### Phase 1: IMMEDIATE (Critical Issues)
1. **Fix TLS certificate validation** - Set `rejectUnauthorized: true` always
2. **Verify .env is gitignored** - Ensure secrets never committed
3. **Add filter query escaping** - Prevent injection attacks

### Phase 2: SHORT-TERM (High Issues - 1 Week)
4. **Implement HTTPS** - Add TLS certificates and HTTPS server
5. **Fix CSP unsafe-inline** - Implement nonce-based CSP
6. **Add authentication** - Implement user authentication
7. **Add origin validation** - Configure CORS properly

### Phase 3: MEDIUM-TERM (Medium Issues - 1 Month)
8. **Sanitize error logging** - Remove sensitive data from logs
9. **Reduce file size limit** - Set reasonable upload limits
10. **Implement Redis rate limiting** - For multi-instance support

### Phase 4: ONGOING (Low/Informational)
11. **Add structured logging** - Implement audit trail
12. **Fix race conditions** - Refactor file cleanup
13. **Consider Helmet.js** - Simplify header management

---

## 🔍 Testing Recommendations

### Security Tests to Add:
1. **XSS Testing**: Attempt to inject scripts via all input fields
2. **Injection Testing**: Test filter queries with special characters
3. **File Upload Testing**: Attempt path traversal with filenames
4. **Rate Limit Testing**: Verify rate limiting works as expected
5. **HTTPS Testing**: Verify all traffic is encrypted in production
6. **Authentication Testing**: Attempt unauthorized access

### Tools to Use:
- OWASP ZAP for automated vulnerability scanning
- Burp Suite for manual penetration testing
- npm audit for dependency vulnerabilities
- Snyk for continuous security monitoring

---

## 📚 References

1. OWASP Top 10 2021: https://owasp.org/Top10/
2. CWE Top 25: https://cwe.mitre.org/top25/
3. ANTI_PATTERNS_BREADTH.md (provided)
4. Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/

---

## ✅ Conclusion

This codebase demonstrates **strong defensive programming** with comprehensive input validation and security headers. The main concerns are:

1. **TLS certificate validation disabled in non-production**
2. **No HTTPS enforcement**
3. **No authentication/authorization**
4. **CSP allows unsafe-inline**

Addressing the Critical and High issues will significantly improve the security posture. The codebase shows awareness of security principles; the issues identified are primarily configuration and deployment concerns rather than fundamental design flaws.

**Overall Grade: B-** (Would be A- after addressing Critical/High issues)
