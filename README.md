# Secure Dashboard

This project is a simple and secure authentication dashboard built with Node.js, Express, and MongoDB.  
It focuses on safe user registration, login, input validation, and basic encryption.

---

## Getting Started

## 1. Clone the repository

git clone https://github.com/your-username/secure-dashboard.git
cd secure-dashboard


## 2. Install dependencies
npm install

## 3. Set up environment variables
Create a .env file in the project root and add:
MONGO_URI=your_mongodb_connection_string
SESSION_SECRET=your_secret_key
PORT=3000

## 4. Run the application
npm start
The application will be available at http://localhost:3000

### Security Practices
Input Validation: Used express-validator to check and sanitize name, email, and bio inputs.

Output Encoding: Escaped user-provided values before displaying to prevent XSS.

Encryption: Passwords are hashed with bcrypt. Sensitive text fields are encrypted before storing in the database.

Dependency Management: Used npm audit and npm outdated to check for vulnerabilities and updates 
. env and node_modules are excluded from version control.

Lessons Learned
Fixed session handling issues by properly destroying sessions on logout.

Solved hashing problems by ensuring correct salt rounds for bcrypt.

Learned the importance of running npm audit early to avoid using vulnerable package
# Secure Dashboard - Web Security Report

This project is a secure user dashboard built with Node.js, Express, MongoDB, and Passport.js. It implements secure login, profile editing, encrypted data storage, and multiple layers of protection against common web vulnerabilities.

---



## Security Testing

### Step-by-Step Vulnerability Testing Process

#### 1. Manual Testing

- **SQL Injection**  
  Simulated SQL injection by entering payloads like `' OR '1'='1` into the login and profile update form.  
  ➤ *Verified that Mongoose queries were not vulnerable, and inputs were sanitized.*

- **Cross-Site Scripting (XSS)**  
  Injected `<script>alert("XSS")</script>` in the "Bio" field of the profile form.  
  ➤ *Initially triggered a script popup. This was resolved by validating input and encrypting bio data.*

- **CSRF Testing**  
  Attempted unauthorized POST requests from external pages.  
  ➤ *Confirmed CSRF risk, later mitigated with `csurf` middleware and token injection.*

#### 2. Automated Testing

- **OWASP ZAP Scan**  
  Used ZAP’s *Automated Scan* and *Active Scan* against `http://localhost:3001`.  
  ➤ *Discovered issues such as missing security headers, lack of CSRF tokens, CSP misconfiguration, and cookie attribute weaknesses.*

- **npm audit**  
  Scanned for dependency vulnerabilities.  
  ➤ *Outdated or insecure packages were identified and updated using `npm audit fix`.*

---

## Vulnerability Fixes

| Vulnerability | Fix Implemented | Validation Method |
|---------------|------------------|--------------------|
| **Missing CSRF Tokens** | Integrated `csurf` middleware; added `<input type="hidden" name="_csrf">` in forms | ZAP re-scan showed CSRF alerts removed |
| **Missing Security Headers** | Added `helmet()` middleware to set common headers | Verified with browser DevTools and ZAP |
| **Content Security Policy (CSP)** | Configured strict CSP using `helmet.contentSecurityPolicy()` | ZAP no longer reports wildcard or unsafe directives |
| **Cookie without `HttpOnly` / `SameSite`** | Updated `session` config to use `httpOnly: true` and `sameSite: 'strict'` | ZAP scan confirmed secure cookie flags |
| **XSS in Bio Field** | Validated and encrypted bio using `crypto`; filtered unsafe characters | Manual testing + no alert triggered |
| **SQL Injection** | Reviewed all `.findOne({ email })` logic to ensure parameterized usage; added string sanitization | Manual payload testing with Postman |

---

## Testing Tools

| Tool | Type | Purpose | Usage |
|------|------|---------|-------|
| **OWASP ZAP** | Dynamic Analysis / Vulnerability Scanner | Detect runtime vulnerabilities like XSS, CSRF, missing headers | Performed active scan on local server |
| **Postman** | Manual API Testing | Simulate login requests and injection attacks | Sent crafted JSON payloads to test for injection and auth issues |
| **npm audit** | Static Dependency Scanner | Find known vulnerabilities in third-party packages | Fixed issues with `npm audit fix` and `--force` |
| **Express Validator** | Input Validation Library | Ensure inputs match expected format; mitigate XSS & injection | Used in `profile` POST route |
| **Helmet.js** | HTTP Header Middleware | Automatically adds security-related headers | Added headers like CSP, X-Content-Type-Options, Frame Options |
| **csurf** | CSRF Protection Middleware | Prevent CSRF attacks by generating and validating form tokens | Enabled in all POST forms with session-based token checks |

---

## Lessons Learned

### What Worked Well

- Integrating middleware like `helmet`, `csurf`, and `express-validator` was straightforward and effective.
- OWASP ZAP provided actionable feedback and helped prioritize vulnerabilities by severity.
- Manually simulating attacks (e.g., XSS, SQLi) gave better understanding of real-world risk.

### Challenges Faced

- Initial ZAP scan gave many false positives or minor alerts—had to filter critical ones from noise.
- CSP configuration required tuning to avoid breaking frontend styles while staying strict.
- CSRF protection broke form submissions initially until proper tokens were injected into EJS forms.

### Areas for Improvement

- Automate ZAP scans and audits using npm scripts in future projects.
- Use stricter email/username sanitization and escaping in templates (`<%= ... %>` not `<%- ... %>`).
- Introduce logging and monitoring for security events (e.g., failed login attempts, session hijack).

---

## Ethical and Legal Considerations in Web Security

### Ethical Responsibilities of Security Professionals

As a web security practitioner, it is my responsibility to ensure that all testing and vulnerability analysis is conducted ethically and professionally. During this project, all security testing—such as SQL injection, cross-site scripting (XSS), and CSRF simulations—was carried out exclusively within my own application, under controlled and authorized conditions.

Key ethical guidelines followed:

- **No unauthorized testing** was performed against any external systems or third-party services.
- **All attack simulations** (SQLi, XSS, CSRF) were conducted on my own local instance of the application (`http://localhost:3001`).
- **No real user data** was collected, exposed, or used in any part of the testing or development process.
- I adhered to the core values of **confidentiality, integrity, and responsible disclosure** as outlined by the [OWASP Code of Ethics](https://owasp.org/www-policy/operational/code-of-ethics).

### Legal Implications of Security Testing

This project complies with current web security legal standards in Canada, where it was developed and tested. The following frameworks and principles were considered:

- **Personal Information Protection and Electronic Documents Act (PIPEDA)**  
  Canada's federal privacy law governing how organizations handle personal information. Although this application does not store sensitive personal data in production, all measures were taken to **secure user data in transit and at rest**, including encrypted password storage and session security.

- **Computer Misuse Act / Unauthorized Access Laws**  
  In accordance with laws preventing unauthorized system access or data manipulation, **all testing was done on a system I own**, without violating any third-party system boundaries.

- **Best practices under OWASP Top 10**  
  This application was reviewed and updated to mitigate common threats listed under the OWASP Top 10 Web Security Risks, including injection, broken authentication, and security misconfigurations.

---

By following both ethical and legal standards during the security testing phase, this project demonstrates a responsible and professional approach to vulnerability detection and mitigation.