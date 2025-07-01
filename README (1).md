# Web Application Security Case Study Report

---

## Group Name
**Ethical Shield**

---

## Group Member and Assigned Task

| Member         | Matric No | Task Assignment                                                                 |
|----------------|-----------|-------------------------------------------------------------------------------|
| Haziq Uzair    | 21xxx     | Project Lead, Report Compilation, Vulnerability Identification                |
| Izzul Amirr    | 2118091   | Web Application Testing, Vulnerability Evaluation, Screenshots & Evidence     |
| Johan Adam     | 2116387   | Web Application Testing, Vulnerability Evaluation, Weekly Progress Report     |

---

## Scan Details

| Field                  | Value                                                        |
|------------------------|-------------------------------------------------------------|
| **Website**            | Traveling page                                         |
| **Prepared By**        | Ethical Shield Group                                        |
| **Date of Scan**       | 2025-06-29                                                 |
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

## Executive Summary

### Metric Values

| Risk Level   | Issues Found | Example Vulnerability                    |
|--------------|-------------|------------------------------------------|
| Critical     | 0           | N/A                                      |
| High         | 0           | N/A                                      |
| Medium       | 3           | Missing Anti-clickjacking Header                       |
| Low          | 6          | Application Error Disclosure |
| Info         | 5           | Information Disclosure                    |

**Key Takeaway:**  
The scan identified 3 medium-risk issues that required attention before the risk became bigger. The scan also identified 11 low/informational risk that shows an overlook on security practices .

---


## Identify Vulnerabilities

| Vulnerability                                      | Risk Level    | Confidence | Affected URL/Asset                                  | Example Evidence                                   | CWE ID  | WASC ID |
|----------------------------------------------------|--------------|------------|-----------------------------------------------------|---------------------------------------------------|---------|---------|
| Content Security Policy (CSP) Header Not Set       | Medium       | High       | `https://ifisonline.iium.edu.my/hr-api`        | ZAP alert, missing CSP header in response         | CWE-693 | WASC-15 |
| Missing Anti-clickjacking Header                   | Medium       | Medium     | `http://ifisonline.iium.edu.my/travelling`     | No X-Frame-Options or CSP frame-ancestors present | CWE-1021| WASC-15 |
| Cross-Domain Misconfiguration                     | Medium       | Medium        | `https://style.iium.edu.my/css/iium.css` | The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain                 | CWE-352 | WASC-9  |
| Strict-Transport-Security Header Not Set           | Low          | High       | `https://ifisonline.iium.edu.my/travellingadmin/css/site.css` | No HSTS header in response                        | CWE-319 | WASC-15 |
| Application Error Disclosure                       | Low          | Medium     | `https://ifisonline.iium.edu.my/travellingadmin/site/contact` | Stack trace visible on error page                 | CWE-209 | WASC-13 |
| X-Content-Type-Options Header Missing              | Low          | Medium     | `https://ifisonline.iium.edu.my/travellingadmin/css/site.css` | Header missing in response                        | CWE-16  | WASC-15 |
| Information Disclosure - Suspicious Comments       | Info         | Low        | `https://ifisonline.iium.edu.my/travellingadmin/assets/af19f097/yii.js` | Sensitive comments in JS file                     | CWE-615 | WASC-13 |
| Session Management Response Exposed                | Info         | Medium     | `http://ifisonline.iium.edu.my/travellingadmin`     | Session tokens visible in responses               | CWE-384 | WASC-38 |
| Authentication Request Identified                  | Info         | High       | `https://ifisonline.iium.edu.my/travellingadmin/site/login` | Login request visible in network trace            | CWE-287 | WASC-1  |

_See Table 2 and Appendix for full evidence and screenshots._

---

## Evaluate Vulnerabilities

### 1. Content Security Policy (CSP) Header Not Set
- **Severity:** Medium  
- **CWE ID:** CWE-693  
- **WASC ID:** WASC-15  
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
- **CWE ID:** CWE-1021  
- **WASC ID:** WASC-15  
- **Description:** Allows framing, making the site vulnerable to clickjacking attacks.  
- **Affected URLs:** `http://ifisonline.iium.edu.my/travellingadmin`  
- **Business Impact:** Attackers could trick users into clicking on hidden UI elements, leading to unauthorized actions.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:** Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.

### 3. Absence of Anti-CSRF Tokens
- **Severity:** Medium  
- **CWE ID:** CWE-352  
- **WASC ID:** WASC-9  
- **Description:** Cross-Site Request Forgery (CSRF) is a type of attack that tricks authenticated users into submitting a request to a web application they are currently logged into, without their consent. The absence of anti-CSRF tokens in forms means that attackers can craft malicious requests that are executed with the victim's privileges. This can result in unauthorized actions such as changing account details, making transactions, or altering sensitive data. CSRF attacks exploit the trust a site has in the user's browser, and are particularly dangerous for applications that perform sensitive operations based on user authentication cookies or sessions.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/site/login`  
- **Business Impact:** Attackers may perform unauthorized transactions, data modification, or privilege escalation, leading to financial loss, data breaches, or reputational damage.  
- **OWASP Reference:** [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:**  
  - Implement anti-CSRF tokens in all forms that perform state-changing operations. Each token should be unique per user session and validated on the server side for every request.  
  - Use secure frameworks or libraries that provide built-in CSRF protection.  
  - Ensure that cookies are set with the `SameSite` attribute to restrict cross-origin requests.  
  - Avoid using GET requests for actions that change state; use POST, PUT, or DELETE instead.  
  - Educate developers about CSRF risks and best practices.  
  - Regularly test forms for CSRF vulnerabilities using automated tools and manual review.

### 4. Strict-Transport-Security Header Not Set
- **Severity:** Low  
- **CWE ID:** CWE-319  
- **WASC ID:** WASC-15  
- **Description:** HTTP Strict Transport Security (HSTS) is a security feature that instructs browsers to only interact with the website using HTTPS, preventing protocol downgrade attacks and cookie hijacking. Without the HSTS header, users may be vulnerable to man-in-the-middle (MITM) attacks, where attackers intercept or modify traffic by forcing users to connect over insecure HTTP. This is especially risky on public Wi-Fi or untrusted networks.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/css/site.css`  
- **Business Impact:** Users may be redirected to insecure (HTTP) versions of the site, exposing sensitive data such as authentication cookies or personal information to attackers. This can result in session hijacking, data theft, or loss of user trust.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  - Configure the web server to include the following header in all HTTPS responses:  
    ```http
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    ```
  - Set a long `max-age` (at least one year) to ensure browsers remember to use HTTPS.  
  - Use the `includeSubDomains` directive to enforce HSTS on all subdomains.  
  - Submit your domain to the [HSTS preload list](https://hstspreload.org/) for additional protection.  
  - Regularly test your site using security scanners to verify the HSTS header is present and correctly configured.  
  - Educate developers and administrators about the importance of HSTS and secure transport.

### 5. Application Error Disclosure
- **Severity:** Low  
- **CWE ID:** CWE-209  
- **WASC ID:** WASC-13  
- **Description:** Application error disclosure occurs when detailed error messages, stack traces, or internal server information are revealed to end users. These messages may include sensitive information such as file paths, database queries, software versions, or configuration details. Attackers can use this information to craft more targeted attacks, exploit known vulnerabilities, or map the application's internal structure.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/site/contact`  
- **Business Impact:** Leaked technical details can be used for further attacks, such as SQL injection, remote code execution, or privilege escalation. This can lead to data breaches, service disruption, or reputational damage.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Configure the application to display only generic error messages to end users, avoiding exposure of stack traces or internal details.  
  - Log detailed error information on the server side for troubleshooting by authorized personnel only.  
  - Regularly review and sanitize error handling code to ensure no sensitive data is leaked.  
  - Implement custom error pages for common HTTP errors (e.g., 404, 500) that do not reveal system information.  
  - Educate developers about secure error handling practices and conduct code reviews focused on error disclosure risks.

### 6. X-Content-Type-Options Header Missing
- **Severity:** Low  
- **CWE ID:** CWE-16  
- **WASC ID:** WASC-15  
- **Description:** The X-Content-Type-Options HTTP header prevents browsers from MIME-sniffing a response away from the declared content-type. Without this header, browsers may interpret files as a different MIME type, potentially allowing attackers to execute malicious scripts or content. This can lead to content type confusion attacks, where a file intended as plain text is executed as HTML or JavaScript.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/css/site.css`  
- **Business Impact:** Attackers may exploit MIME type confusion to execute scripts, bypass security controls, or deliver malware to users. This can result in XSS attacks, data theft, or compromise of user sessions.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  - Add the following header to all HTTP responses to instruct browsers not to perform MIME sniffing:  
    ```http
    X-Content-Type-Options: nosniff
    ```
  - Ensure that all files are served with the correct Content-Type header.  
  - Regularly test your application using security scanners to verify the presence of this header.  
  - Educate developers and administrators about the risks of MIME sniffing and the importance of secure headers.

### 7. Information Disclosure - Suspicious Comments
- **Severity:** Info  
- **CWE ID:** CWE-615  
- **WASC ID:** WASC-13  
- **Description:** Suspicious or sensitive comments in client-side code (such as JavaScript files) may reveal information about application logic, hidden features, or security mechanisms. Attackers can analyze these comments to discover vulnerabilities, bypass controls, or exploit undocumented functionality.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/assets/af19f097/yii.js`  
- **Business Impact:** Attackers may gain insight into application logic, discover hidden endpoints, or identify weak security controls, increasing the risk of targeted attacks.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Remove all comments from production code that may reveal sensitive information or implementation details.  
  - Review and sanitize code before deployment to ensure no internal notes, TODOs, or debug information remain.  
  - Use automated tools to scan for and flag suspicious comments in source files.  
  - Educate developers about the risks of leaving sensitive comments in client-side code.

### 8. Session Management Response Exposed
- **Severity:** Info  
- **CWE ID:** CWE-384  
- **WASC ID:** WASC-38  
- **Description:** Session management response exposure occurs when session tokens or identifiers are visible in HTTP responses, URLs, or client-side scripts. Exposed session tokens can be intercepted by attackers through network sniffing, browser history, or logs, leading to session hijacking or impersonation.  
- **Affected URLs:** `http://ifisonline.iium.edu.my/travellingadmin`  
- **Business Impact:** Attackers may use exposed session tokens to gain unauthorized access to user accounts, perform actions as the victim, or maintain persistent access. This can result in data breaches, account takeover, or regulatory violations.  
- **OWASP Reference:** [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:**  
  - Ensure session tokens are only transmitted over secure (HTTPS) channels.  
  - Do not expose session tokens in URLs, client-side scripts, or logs.  
  - Use secure, random, and unpredictable session identifiers.  
  - Implement session expiration and automatic logout after periods of inactivity.  
  - Regularly review session management implementation and test for exposure risks.

### 9. Authentication Request Identified
- **Severity:** Info  
- **CWE ID:** CWE-287  
- **WASC ID:** WASC-1  
- **Description:** Authentication requests visible in network traces may reveal login endpoints, authentication mechanisms, or user credentials if not properly protected. While this is often informational, it can assist attackers in mapping authentication flows or targeting brute-force attacks.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/site/login`  
- **Business Impact:** Informational only, but may increase the risk of targeted attacks if authentication endpoints are not properly secured.  
- **OWASP Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:**  
  - Ensure all authentication requests are sent over HTTPS.  
  - Implement account lockout and rate limiting to prevent brute-force attacks.  
  - Monitor authentication endpoints for suspicious activity.  
  - Educate users and administrators about secure authentication practices.

---

## Prevention & Recommendations

### Prioritized Action Plan

1. **Immediate Remediation (Within 1 week):**
   - Add a strict Content-Security-Policy (CSP) header to all HTTP responses to restrict the sources of scripts, styles, images, and other resources to trusted domains only. Example:
     ```http
     Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
     ```
     - Test the policy in report-only mode first to identify violations without breaking functionality.
     - Avoid using wildcards (`*`) in CSP directives, and update the policy as new features or third-party integrations are added.
   - Add the X-Frame-Options header (preferably `DENY` or `SAMEORIGIN`) to prevent clickjacking attacks by blocking the site from being embedded in iframes on other domains. Example:
     ```http
     X-Frame-Options: DENY
     ```
     - Alternatively, use the CSP directive `frame-ancestors 'none'` for more granular control.
   - Add the X-Content-Type-Options header to all HTTP responses to prevent browsers from MIME-sniffing a response away from the declared content-type. Example:
     ```http
     X-Content-Type-Options: nosniff
     ```
     - Ensure all files are served with the correct Content-Type header.
   - Implement CSRF protection for all forms that perform state-changing operations by using anti-CSRF tokens, secure frameworks, and setting cookies with the `SameSite` attribute. Regularly test forms for CSRF vulnerabilities using automated tools and manual review.

2. **Short-Term (Within 1 month):**
   - Enable HTTP Strict-Transport-Security (HSTS) by configuring the web server to include the following header in all HTTPS responses:
     ```http
     Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
     ```
     - Set a long `max-age` (at least one year) and use `includeSubDomains` to enforce HSTS on all subdomains.
     - Submit your domain to the [HSTS preload list](https://hstspreload.org/) for additional protection.
     - Regularly test your site using security scanners to verify the HSTS header is present and correctly configured.
   - Configure the application to suppress detailed error messages by displaying only generic error messages to end users and logging detailed errors server-side for authorized personnel only. Implement custom error pages for common HTTP errors (e.g., 404, 500) that do not reveal system information.
   - Remove or sanitize all comments from client-side code before deployment to prevent information disclosure. Use automated tools to scan for and flag suspicious comments in source files.

3. **Ongoing:**
   - Conduct regular automated and manual security scans to identify new vulnerabilities and verify the effectiveness of implemented controls.
   - Provide ongoing developer security training focused on secure coding, secure configuration, and awareness of the latest threats and best practices.
   - Review application configuration and security controls after each major update or deployment to ensure new features or changes do not introduce vulnerabilities.
   - Maintain a process for timely patching and updating of all software components, libraries, and dependencies.
   - Foster a security-first culture within the development and operations teams, encouraging proactive identification and mitigation of risks.

---

## Appendices

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

- **Additional:** Raw ZAP report (see attached file)
[2025-05-24-ZAP-Report-TravellingAdminpage.html](2025-05-24-ZAP-Report-TravellingAdminpage.html)



## References

1. [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
2. [ZAP by Checkmarx](https://www.zaproxy.org/)
3. [OWASP Top 10: A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
4. [RFC 6797: HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)
5. [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
6. [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
7. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
8. [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

**_End of Report_**

---
