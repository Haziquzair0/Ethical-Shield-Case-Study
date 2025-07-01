# Web Application Security Case Study Report

---

## i. Group Name
**Ethical Shield**

---

## ii. Group Member and Assigned Task

| Member         | Matric No | Task Assignment                                                                 |
|----------------|-----------|-------------------------------------------------------------------------------|
| Haziq Uzair    | 21xxx     | Project Lead, Report Compilation, Vulnerability Identification                |
| Izzul Amirr    | 2118091   | Web Application Testing, Vulnerability Evaluation, Screenshots & Evidence     |
| Johan Adam     | 2116387   | Web Application Testing, Vulnerability Evaluation, Weekly Progress Report     |

---

## iii. Scan Details

| Field                  | Value                                                        |
|------------------------|-------------------------------------------------------------|
| **Prepared By**        | Ethical Shield Group                                        |
| **Date of Scan**       | 2025-06-28                                                  |
| **Scan Type**          | Automated Security Assessment (ZAP)                         |
| **Scan Duration**      | 1 hour 15 minutes                                           |

---

## iv. Table of Contents

1. [Group Name](#i-group-name)
2. [Group Member Details](#ii-group-member-and-assigned-task)
3. [Scan Details](#iii-scan-details)
4. [Table of Contents, List of Figures, List of Tables & References](#iv-table-of-contents)
    - [List of Figures](#list-of-figures)
    - [List of Tables](#list-of-tables)
    - [References](#references)
5. [Executive Summary](#v-executive-summary)
6. [Brief Description & Objectives](#vi-brief-description-of-the-assigned-web-application-and-objectives-of-the-case-study)
7. [Identified Vulnerabilities](#vii-identify-vulnerabilities)
8. [Evaluation of Vulnerabilities](#viii-evaluate-vulnerabilities)
9. [Prevention & Recommendations](#ix-prevent-vulnerabilities)
10. [Appendices](#x-appendices)

### List of Figures
- **Figure 1:** ZAP Scan Summary Screenshot
- **Figure 2:** Application Error Disclosure Evidence

### List of Tables
- **Table 1:** Group Members and Assigned Tasks
- **Table 2:** Vulnerability Summary Table
- **Table 3:** Risk Level Metrics Overview

### References
See [References Section](#references) below.

---

## v. Executive Summary

### Metric Values

| Risk Level   | Issues Found | Example Vulnerability                    |
|--------------|-------------|------------------------------------------|
| Critical     | 0           | N/A                                      |
| High         | 0           | N/A                                      |
| Medium       | 3           | CSP Header Not Set                       |
| Low          | 3           | Strict-Transport-Security Header Not Set |
| Info         | 3           | Suspicious Comments                      |

**Key Takeaway:**  
The security scan of the Travelling Admin Portal revealed several medium and low-severity vulnerabilities, including missing security headers, absence of CSRF protection, and information disclosure. No critical or high-risk issues were detected. Immediate remediation should focus on implementing missing security headers and CSRF protections, while regular reviews and developer training are recommended to maintain a robust security posture. All findings are supported by evidence and mapped to OWASP standards.

---

## vi. Brief Description of the Assigned Web Application and Objectives of the Case Study

The assigned web application is [_Travelling Admin Portal_](https://ifisonline.iium.edu.my/travellingadmin/), a Yii-based PHP web application designed to manage travel requests and administration for IIUM staff. The objective of this security assessment is to identify vulnerabilities, evaluate their risks and potential business impact, and recommend actionable mitigation strategies.

---

## vii. Identify Vulnerabilities

| Vulnerability                                      | Risk Level    | Confidence | Affected URL/Asset                                  | Example Evidence                                   |
|----------------------------------------------------|--------------|------------|-----------------------------------------------------|---------------------------------------------------|
| Content Security Policy (CSP) Header Not Set       | Medium       | High       | `https://ifisonline.iium.edu.my/sitemap.xml`        | ZAP alert, missing CSP header in response         |
| Missing Anti-clickjacking Header                   | Medium       | Medium     | `http://ifisonline.iium.edu.my/travellingadmin`     | No X-Frame-Options or CSP frame-ancestors present |
| Absence of Anti-CSRF Tokens                        | Medium       | Low        | `https://ifisonline.iium.edu.my/travellingadmin/site/login` | Missing CSRF token in login form                  |
| Strict-Transport-Security Header Not Set           | Low          | High       | `https://ifisonline.iium.edu.my/travellingadmin/css/site.css` | No HSTS header in response                        |
| Application Error Disclosure                       | Low          | Medium     | `https://ifisonline.iium.edu.my/travellingadmin/site/contact` | Stack trace visible on error page                 |
| X-Content-Type-Options Header Missing              | Low          | Medium     | `https://ifisonline.iium.edu.my/travellingadmin/css/site.css` | Header missing in response                        |
| Information Disclosure - Suspicious Comments       | Info         | Low        | `https://ifisonline.iium.edu.my/travellingadmin/assets/af19f097/yii.js` | Sensitive comments in JS file                     |
| Session Management Response Exposed                | Info         | Medium     | `http://ifisonline.iium.edu.my/travellingadmin`     | Session tokens visible in responses               |
| Authentication Request Identified                  | Info         | High       | `https://ifisonline.iium.edu.my/travellingadmin/site/login` | Login request visible in network trace            |

_See Table 2 and Appendix for full evidence and screenshots._

---

## viii. Evaluate Vulnerabilities

### 1. Content Security Policy (CSP) Header Not Set
- **Severity:** Medium  
- **Description:** Absence of CSP header increases risk of XSS and data injection.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/sitemap.xml` and others  
- **Business Impact:** Attackers could inject scripts, potentially compromising user data and trust.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:** Add a strong CSP header.  
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
  ```

### 2. Missing Anti-clickjacking Header
- **Severity:** Medium  
- **Description:** Allows framing, making the site vulnerable to clickjacking attacks.  
- **Affected URLs:** `http://ifisonline.iium.edu.my/travellingadmin`  
- **Business Impact:** Attackers could trick users into clicking on hidden UI elements, leading to unauthorized actions.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:** Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.

### 3. Absence of Anti-CSRF Tokens
- **Severity:** Medium  
- **Description:** Enables attackers to perform actions as authenticated users via CSRF.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/site/login`  
- **Business Impact:** Unauthorized transactions, potential data loss or corruption.  
- **OWASP Reference:** [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:** Implement CSRF tokens in all forms.

### 4. Strict-Transport-Security Header Not Set
- **Severity:** Low  
- **Description:** No HSTS header, exposing users to SSL stripping.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/css/site.css`  
- **Business Impact:** Users might be redirected to insecure (HTTP) versions of the site.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  ```http
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

### 5. Application Error Disclosure
- **Severity:** Low  
- **Description:** Reveals stack traces and internal paths to users.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/site/contact`  
- **Business Impact:** Leaked technical details can be used for further attacks.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:** Display generic errors; log details server-side only.

### 6. X-Content-Type-Options Header Missing
- **Severity:** Low  
- **Description:** Lack of this header allows MIME sniffing.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/css/site.css`  
- **Business Impact:** Potential for content type confusion attacks.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  ```http
  X-Content-Type-Options: nosniff
  ```

### 7. Information Disclosure - Suspicious Comments
- **Severity:** Info  
- **Description:** Client-side code contains comments that may leak sensitive logic.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/assets/af19f097/yii.js`  
- **Business Impact:** Attackers may gain insight into application logic or hidden features.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:** Remove or sanitize sensitive comments.

### 8. Session Management Response Exposed
- **Severity:** Info  
- **Description:** Session tokens visible in some HTTP responses.  
- **Affected URLs:** `http://ifisonline.iium.edu.my/travellingadmin`  
- **Business Impact:** Informational only; may assist attackers in identifying session handling.  
- **OWASP Reference:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:** Monitor and ensure proper use of secure cookies.

### 9. Authentication Request Identified
- **Severity:** Info  
- **Description:** Authentication requests visible in network trace.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/site/login`  
- **Business Impact:** Informational only.  
- **OWASP Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:** No immediate action required.

---

## ix. Prevention & Recommendations

### Prioritized Action Plan

1. **Immediate Remediation (Within 1 week):**
   - Add CSP, X-Frame-Options, and X-Content-Type-Options headers.
   - Implement CSRF protection for all forms.
2. **Short-Term (Within 1 month):**
   - Enable Strict-Transport-Security (HSTS).
   - Configure the application to suppress detailed error messages.
   - Remove or sanitize all comments from client-side code.
3. **Ongoing:**
   - Conduct regular automated and manual security scans.
   - Provide developer security training focused on secure coding and configuration.
   - Review application configuration after each major update or deployment.

---

## x. Appendices

### Appendix A: Scan Settings

- **Tool:** OWASP ZAP  
- **Scan Profile:** Standard  
- **Scan Date:** 2025-06-28  
- **Scope:** All accessible URLs of the Travelling Admin Portal

### Appendix B: Vulnerability Summary Table

| Risk Level   | # Issues | Example Vulnerability                    | Recommendation                                   |
|--------------|----------|------------------------------------------|--------------------------------------------------|
| Critical     | 0        | N/A                                      | N/A                                              |
| High         | 0        | N/A                                      | N/A                                              |
| Medium       | 3        | CSP Header Not Set                       | Add CSP, X-Frame-Options, Implement CSRF tokens  |
| Low          | 3        | Application Error Disclosure             | Enable HSTS, generic error pages, nosniff header |
| Info         | 3        | Suspicious Comments                      | Remove sensitive comments                        |

### Appendix C: Screenshots & Evidence

- **Figure 1:** ZAP Scan Summary (see attached screenshot)
![image](https://github.com/user-attachments/assets/3c0e9c4a-e587-4c55-bd28-983e1d457da7)

- **Figure 2:** Application Error Stack Trace (see attached screenshot)
- **Additional:** Raw ZAP report (see attached file)

### Appendix D: Raw Data and Metadata

- Full ZAP scan output and log files (available upon request)
- Metadata: Scan timestamp, tool version, configuration files

---

## References

1. [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
2. [ZAP by Checkmarx](https://www.zaproxy.org/)
3. [OWASP Top 10: A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
4. [Yii2 Security Guide](https://www.yiiframework.com/doc/guide/2.0/en/security-authorization)
5. [RFC 6797: HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)
6. [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
7. [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
8. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
9. [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

**_End of Report_**

---
