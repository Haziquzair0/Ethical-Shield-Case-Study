# Web Application Security Report

---

## i. Group Name
**Ethical Shield**

---

## ii. Group Member Details

| Name                | Matric No   |
|---------------------|-------------|
| Haziquzair          | 2021123456  |
| Izzulamirr          | 2021654321  |
| Aisyah Rahman       | 2021543210  |
| Amirul Hakim        | 2021765432  |

---

## iii. Assigned Tasks for Each Group Member

| Member         | Task Assignment                                                                 |
|----------------|---------------------------------------------------------------------------------|
| Haziq uzair    |21xxx | Project Lead, Report Compilation, Vulnerability Identification                   |
| Izzul amirr    |2118091 | Web Application Testing, Vulnerability Evaluation, Screenshots & Evidence        |


---

## iv. Table of Contents

1. [Group Name](#i-group-name)
2. [Group Member Details](#ii-group-member-details)
3. [Assigned Tasks for Each Group Member](#iii-assigned-tasks-for-each-group-member)
4. [Table of Contents, List of Figures, List of Tables & References](#iv-table-of-contents)
    - [List of Figures](#list-of-figures)
    - [List of Tables](#list-of-tables)
    - [References](#references)
5. [Brief Description & Objectives](#v-brief-description-of-the-assigned-web-application-and-objectives-of-the-case-study)
6. [Identified Vulnerabilities](#vi-identify-vulnerabilities)
7. [Evaluation of Vulnerabilities](#vii-evaluate-vulnerabilities)
8. [Prevention & Recommendations](#viii-prevent-vulnerabilities)

### List of Figures
- **Figure 1:** Example ZAP Scan Summary Screenshot
- **Figure 2:** Application Error Disclosure Evidence

### List of Tables
- **Table 1:** Group Members and Assigned Tasks
- **Table 2:** Vulnerability Summary Table

### References
See [References Section](#references) below.

---

## v. Brief Description of the Assigned Web Application and Objectives of the Case Study

The assigned web application is [_Travelling Admin Portal_](https://ifisonline.iium.edu.my/travellingadmin/), a Yii-based PHP web application designed to manage travel requests and administration for IIUM staff and students. The objective of this case study is to systematically assess the security posture of the web application using automated tools (such as ZAP by Checkmarx), identify vulnerabilities, evaluate their impact and likelihood, and propose practical mitigation strategies to enhance the application's security.

---

## vi. Identify Vulnerabilities

The following vulnerabilities were identified during the ZAP automated security scan:

| Vulnerability                                      | Risk Level    | Confidence | Affected URL/Asset                                  |
|----------------------------------------------------|--------------|------------|-----------------------------------------------------|
| Content Security Policy (CSP) Header Not Set       | Medium       | High       | `https://ifisonline.iium.edu.my/sitemap.xml`        |
| Missing Anti-clickjacking Header                   | Medium       | Medium     | `http://ifisonline.iium.edu.my/travellingadmin`     |
| Absence of Anti-CSRF Tokens                        | Medium       | Low        | `https://ifisonline.iium.edu.my/travellingadmin/site/login` |
| Strict-Transport-Security Header Not Set           | Low          | High       | `https://ifisonline.iium.edu.my/travellingadmin/css/site.css` |
| Application Error Disclosure                       | Low          | Medium     | `https://ifisonline.iium.edu.my/travellingadmin/site/contact` |
| X-Content-Type-Options Header Missing              | Low          | Medium     | `https://ifisonline.iium.edu.my/travellingadmin/css/site.css` |
| Information Disclosure - Suspicious Comments       | Informational| Low        | `https://ifisonline.iium.edu.my/travellingadmin/assets/af19f097/yii.js` |
| Session Management Response Identified             | Informational| Medium     | `http://ifisonline.iium.edu.my/travellingadmin`     |
| Authentication Request Identified                  | Informational| High       | `https://ifisonline.iium.edu.my/travellingadmin/site/login` |

_See Table 2 for a summary and the ZAP Report for full details._

---

## vii. Evaluate Vulnerabilities

### 1. Content Security Policy (CSP) Header Not Set
- **Impact:** Exposes the application to XSS and data injection attacks.
- **Likelihood:** High, as the header is missing in several responses.
- **Evidence:** See ZAP alert for `sitemap.xml`.

### 2. Missing Anti-clickjacking Header
- **Impact:** Allows the site to be framed and vulnerable to clickjacking.
- **Likelihood:** Medium.
- **Evidence:** No `X-Frame-Options` or CSP `frame-ancestors` directive.

### 3. Absence of Anti-CSRF Tokens
- **Impact:** Allows attackers to perform actions on behalf of authenticated users.
- **Likelihood:** Low to Medium.
- **Evidence:** Login form missing CSRF tokens.

### 4. Strict-Transport-Security Header Not Set
- **Impact:** Users may be vulnerable to SSL stripping attacks.
- **Likelihood:** High if users access via non-HTTPS.
- **Evidence:** No `Strict-Transport-Security` header in CSS asset.

### 5. Application Error Disclosure
- **Impact:** Reveals sensitive stack traces and file paths.
- **Likelihood:** Medium.
- **Evidence:** `/site/contact` page shows Yii stacktrace.

### 6. X-Content-Type-Options Header Missing
- **Impact:** Allows MIME sniffing, could lead to content type confusion attacks.
- **Likelihood:** Medium.
- **Evidence:** CSS asset response headers.

### 7. Information Disclosure - Suspicious Comments
- **Impact:** May leak sensitive logic or information useful for attackers.
- **Likelihood:** Low.
- **Evidence:** JavaScript comments containing keywords.

### 8. Session Management Response Identified
- **Impact:** Informational; session tokens are visible.
- **Likelihood:** N/A.

### 9. Authentication Request Identified
- **Impact:** Informational; for tracking login requests.
- **Likelihood:** N/A.

---

## viii. Prevent Vulnerabilities

### 1. Set a Content-Security-Policy (CSP) Header
- Configure the web server or application to send a strong CSP header. Example:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
  ```

### 2. Set Anti-clickjacking Headers
- Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'` in all responses.

### 3. Implement CSRF Protection
- Use a vetted CSRF library/framework (Yii has built-in CSRF support).
- Ensure all forms include a unique, unpredictable CSRF token.

### 4. Enable Strict Transport Security
- Add the following header:
  ```http
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

### 5. Suppress Error Details in Production
- Configure the application to display generic error messages to users.
- Log detailed errors server-side only.

### 6. Set X-Content-Type-Options Header
- Add the following header to all responses:
  ```http
  X-Content-Type-Options: nosniff
  ```

### 7. Remove or Sanitize Sensitive Comments
- Review and remove all non-essential comments from client-side JavaScript and HTML.

### 8 & 9. Session & Authentication Alerts
- No action needed; for information only.

---

## References

1. [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
2. [ZAP by Checkmarx](https://www.zaproxy.org/)
3. [OWASP Top 10: A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
4. [Yii2 Security Guide](https://www.yiiframework.com/doc/guide/2.0/en/security-authorization)
5. [RFC 6797: HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)
6. [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
7. [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---

## Appendix

**Table 2: Vulnerability Summary Table**

| Vulnerability                                  | Risk    | Recommendation                              |
|------------------------------------------------|---------|----------------------------------------------|
| CSP Header Not Set                             | Medium  | Add CSP header                              |
| Anti-clickjacking Header Missing               | Medium  | Add X-Frame-Options                         |
| Absence of Anti-CSRF Tokens                    | Medium  | Implement CSRF tokens in all forms          |
| Strict-Transport-Security Header Not Set       | Low     | Enable HSTS                                 |
| Application Error Disclosure                   | Low     | Generic error pages, suppress stack traces   |
| X-Content-Type-Options Header Missing          | Low     | Add X-Content-Type-Options: nosniff         |
| Suspicious Comments                            | Info    | Clean sensitive comments from code           |
| Session Management/Authentication (Info)       | Info    | No action required                          |

---

**_End of Report_**
