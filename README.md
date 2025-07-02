# Web Application Security Case Study Report

---

## Group Name
**Ethical Shield**

---

## Group Member and Assigned Task

| Member         | Matric No | Task Assignment                                                                 |
|----------------|-----------|-------------------------------------------------------------------------------|
| Haziq Uzair    | 2112757    | Project Lead, Report Compilation, Vulnerability Identification                |
| Izzul Amirr    | 2118091   | Web Application Testing, Vulnerability Evaluation, Screenshots & Evidence     |
| Johan Adam     | 2116387   | Web Application Testing, Vulnerability Evaluation, Weekly Progress Report     |

---

## Scan Details

| Field                  | Value                                                        |
|------------------------|-------------------------------------------------------------|
| **Website**            | Travelingadmin page                                         |
| **Prepared By**        | Ethical Shield Group                                        |
| **Date of Scan**       | 2025-05-24                                                 |
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
| Medium       | 3           | CSP Header Not Set                       |
| Low          | 3           | Strict-Transport-Security Header Not Set |
| Info         | 3           | Suspicious Comments                      |

**Key Takeaway:**  
The security scan of the Travelling Admin Portal revealed several medium and low-severity vulnerabilities, including missing security headers, absence of CSRF protection, and information disclosure. No critical or high-risk issues were detected. Immediate remediation should focus on implementing missing security headers and CSRF protections, while regular reviews and developer training are recommended to maintain a robust security posture. All findings are supported by evidence and mapped to OWASP standards.

---


## Identify Vulnerabilities

| Vulnerability                                      | Risk Level    | Confidence | Affected URL/Asset                                  | Example Evidence                                   | CWE ID  | WASC ID |
|----------------------------------------------------|--------------|------------|-----------------------------------------------------|---------------------------------------------------|---------|---------|
| Content Security Policy (CSP) Header Not Set       | Medium       | High       | `https://ifisonline.iium.edu.my/sitemap.xml`        | ZAP alert, missing CSP header in response         | CWE-693 | WASC-15 |
| Missing Anti-clickjacking Header                   | Medium       | Medium     | `http://ifisonline.iium.edu.my/travellingadmin`     | No X-Frame-Options or CSP frame-ancestors present | CWE-1021| WASC-15 |
| Absence of Anti-CSRF Tokens                        | Medium       | Low        | `https://ifisonline.iium.edu.my/travellingadmin/site/login` | Missing CSRF token in login form                  | CWE-352 | WASC-9  |
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
# Scan Details

| Field                  | Value                                                        |
|------------------------|-------------------------------------------------------------|
| **Website**            | Travelling page                                         |
| **Prepared By**        | Ethical Shield Group                                        |
| **Date of Scan**       | 2025-05-26                                                  |
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
 Medium        | 3           | CSP Header Not Set, CORS, Clickjacking       |
| Low          | 6           | HSTS, Server Version, JS Inclusion, Timestamps, etc. |
| Info         | 5           | Suspicious Comments, Cache, User Agent Fuzzer, etc.   |

**Key Takeaway:**  
The security scan of the Travelling  Portal revealed several medium and low-severity vulnerabilities, including missing security headers, absence of CSRF protection, and information disclosure. No critical or high-risk issues were detected. Immediate remediation should focus on implementing missing security headers and CSRF protections, while regular reviews and developer training are recommended to maintain a robust security posture. All findings are supported by evidence and mapped to OWASP standards.

---



## Identify Vulnerabilities

| Vulnerability                                                      | Risk Level      | Count | Example Evidence / Affected URL                                 | CWE ID  | WASC ID |
|--------------------------------------------------------------------|-----------------|-------|-----------------------------------------------------------------|---------|---------|
| Content Security Policy (CSP) Header Not Set                       | Medium          | 6     | Missing CSP header in response                                  | CWE-693 | WASC-15 |
| Cross-Domain Misconfiguration (CORS)                               | Medium          | 23    | `Access-Control-Allow-Origin: *`                                | CWE-942 | WASC-14 |
| Missing Anti-clickjacking Header                                   | Medium          | 3     | No X-Frame-Options or CSP frame-ancestors present               | CWE-1021| WASC-15 |
| Application Error Disclosure                                       | Low             | 1     | Error message with file path                                    | CWE-209 | WASC-13 |
| Cross-Domain JavaScript Source File Inclusion                      | Low             | 12    | External JS loaded from third-party domain                      | CWE-829 | WASC-14 |
| Server Leaks Version Information via "Server" HTTP Header          | Low             | 22    | `Server: Apache/2.4.52 (Ubuntu)`                                | CWE-200 | WASC-13 |
| Strict-Transport-Security Header Not Set                           | Low             | 34    | No HSTS header in response                                      | CWE-319 | WASC-15 |
| Timestamp Disclosure - Unix                                        | Low             | 206   | Unix timestamp in response                                      | CWE-200 | WASC-13 |
| X-Content-Type-Options Header Missing                              | Low             | 28    | Header missing in response                                      | CWE-16  | WASC-15 |
| Information Disclosure - Suspicious Comments                       | Informational   | 7     | Sensitive comments in JS file                                   | CWE-615 | WASC-13 |
| Modern Web Application                                             | Informational   | 3     | Detected modern JS frameworks                                   | N/A     | N/A     |
| Re-examine Cache-control Directives                                | Informational   | 3     | Cache-control headers may be misconfigured                      | CWE-525 | WASC-13 |
| Retrieved from Cache                                               | Informational   | 2     | Resource retrieved from browser cache                           | CWE-525 | WASC-13 |
| User Agent Fuzzer                                                  | Informational   | 12    | Responses to unusual user agents                                | N/A     | N/A     |

---

## Evaluate Vulnerabilities

### 1. Content Security Policy (CSP) Header Not Set
- **Severity:** Medium  
- **CWE ID:** CWE-693  
- **WASC ID:** WASC-15  
- **Description:** Absence of CSP header increases risk of XSS and data injection.  
- **Affected URLs:** Multiple endpoints missing CSP header (e.g., main pages, sitemap).  
- **Business Impact:** Attackers could inject malicious scripts, leading to data theft or site defacement.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  - Add a strong CSP header to all responses.  
  - Regularly review and update CSP as new resources are added.

### 2. Cross-Domain Misconfiguration (CORS)
- **Severity:** Medium  
- **CWE ID:** CWE-942  
- **WASC ID:** WASC-14  
- **Description:** Permissive CORS settings (`Access-Control-Allow-Origin: *`) can expose sensitive data to untrusted domains.  
- **Affected URLs:** Multiple endpoints with open CORS policy.  
- **Business Impact:** Attackers may access data intended only for trusted domains, increasing the risk of data leakage.  
- **OWASP Reference:** [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:**  
  - Restrict CORS to trusted domains only.  
  - Remove `Access-Control-Allow-Origin: *` unless absolutely necessary.  
  - Regularly audit CORS settings.

### 3. Missing Anti-clickjacking Header
- **Severity:** Medium  
- **CWE ID:** CWE-1021  
- **WASC ID:** WASC-15  
- **Description:** Lack of X-Frame-Options or CSP `frame-ancestors` allows clickjacking.  
- **Affected URLs:** Pages missing X-Frame-Options or CSP frame-ancestors.  
- **Business Impact:** Users could be tricked into performing unintended actions.  
- **OWASP Reference:** [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)  
- **Recommendation & Prevention Strategy:**  
  - Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.

### 4. Application Error Disclosure
- **Severity:** Low  
- **CWE ID:** CWE-209  
- **WASC ID:** WASC-13  
- **Description:** Error messages reveal internal information such as file paths or stack traces.  
- **Affected URLs:** Error pages and endpoints that display stack traces.  
- **Business Impact:** Leaked technical details can be used for further attacks, such as SQL injection or privilege escalation.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Show only generic error messages to users.  
  - Log detailed errors server-side for authorized personnel only.

### 5. Cross-Domain JavaScript Source File Inclusion
- **Severity:** Low  
- **CWE ID:** CWE-829  
- **WASC ID:** WASC-14  
- **Description:** Loading JS from third-party domains can introduce supply chain risks if those sources are compromised.  
- **Affected URLs:** Pages including external JS from third-party domains.  
- **Business Impact:** Malicious scripts could be injected if third-party sources are compromised.  
- **OWASP Reference:** [OWASP A08:2021 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)  
- **Recommendation & Prevention Strategy:**  
  - Only include scripts from trusted, verified sources.  
  - Regularly review and update third-party dependencies.

### 6. Server Leaks Version Information via "Server" HTTP Header
- **Severity:** Low  
- **CWE ID:** CWE-200  
- **WASC ID:** WASC-13  
- **Description:** Server version info in HTTP headers can help attackers target known exploits.  
- **Affected URLs:** All endpoints returning detailed Server headers.  
- **Business Impact:** Attackers may use version info to target known exploits.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Suppress or genericize the `Server` header.

### 7. Strict-Transport-Security Header Not Set
- **Severity:** Low  
- **CWE ID:** CWE-319  
- **WASC ID:** WASC-15  
- **Description:** Without HSTS, browsers may connect over HTTP, exposing users to MITM attacks.  
- **Affected URLs:** HTTPS endpoints missing HSTS header.  
- **Business Impact:** Sensitive data could be intercepted.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  - Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` header.

### 8. Timestamp Disclosure - Unix
- **Severity:** Low  
- **CWE ID:** CWE-200  
- **WASC ID:** WASC-13  
- **Description:** Unix timestamps in responses can reveal system activity or deployment schedules.  
- **Affected URLs:** Endpoints returning Unix timestamps in responses.  
- **Business Impact:** May aid attackers in timing attacks or understanding system behavior.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Avoid exposing timestamps in responses unless necessary.

### 9. X-Content-Type-Options Header Missing
- **Severity:** Low  
- **CWE ID:** CWE-16  
- **WASC ID:** WASC-15  
- **Description:** Without this header, browsers may MIME-sniff responses, leading to XSS.  
- **Affected URLs:** Endpoints missing X-Content-Type-Options header.  
- **Business Impact:** Increases risk of XSS and other attacks.  
- **OWASP Reference:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- **Recommendation & Prevention Strategy:**  
  - Add `X-Content-Type-Options: nosniff` to all responses.

### 10. Information Disclosure - Suspicious Comments
- **Severity:** Info  
- **CWE ID:** CWE-615  
- **WASC ID:** WASC-13  
- **Description:** Suspicious or sensitive comments in client-side code (such as JavaScript files) may reveal information about application logic, hidden features, or security mechanisms. Attackers can analyze these comments to discover vulnerabilities, bypass controls, or exploit undocumented functionality.  
- **Affected URLs:** `https://ifisonline.iium.edu.my/travellingadmin/assets/af19f097/yii.js` and other JS assets.  
- **Business Impact:** Attackers may gain insight into application logic, discover hidden endpoints, or identify weak security controls, increasing the risk of targeted attacks.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Remove all comments from production code that may reveal sensitive information or implementation details.  
  - Review and sanitize code before deployment to ensure no internal notes, TODOs, or debug information remain.  
  - Use automated tools to scan for and flag suspicious comments in source files.  
  - Educate developers about the risks of leaving sensitive comments in client-side code.

### 11. Modern Web Application
- **Severity:** Info  
- **Description:** Detected use of modern JS frameworks (e.g., React, Angular, Vue).  
- **Affected URLs:** Various application endpoints.  
- **Business Impact:** Outdated or misconfigured frameworks may introduce vulnerabilities.  
- **OWASP Reference:** [OWASP Top 10: A06 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)  
- **Recommendation & Prevention Strategy:**  
  - Ensure frameworks are kept up to date and securely configured.  
  - Monitor for security advisories related to used frameworks.

### 12. Re-examine Cache-control Directives
- **Severity:** Info  
- **CWE ID:** CWE-525  
- **WASC ID:** WASC-13  
- **Description:** Cache-control headers may be misconfigured, risking sensitive data exposure.  
- **Affected URLs:** Endpoints with weak or missing cache-control headers.  
- **Business Impact:** Sensitive data may be stored in browser or intermediary caches.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Review and configure cache-control headers appropriately.

### 13. Retrieved from Cache
- **Severity:** Info  
- **CWE ID:** CWE-525  
- **WASC ID:** WASC-13  
- **Description:** Resources retrieved from browser cache may not reflect latest security updates.  
- **Affected URLs:** Static assets and API responses.  
- **Business Impact:** Users may receive outdated or insecure content.  
- **OWASP Reference:** [OWASP Top 10: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation & Prevention Strategy:**  
  - Use cache-busting techniques and review cache settings.

### 14. User Agent Fuzzer
- **Severity:** Info  
- **Description:** Application responded to unusual user agents, which may indicate inconsistent behavior or lack of input validation.  
- **Affected URLs:** Multiple endpoints tested with various user agents.  
- **Business Impact:** Inconsistent security controls may be bypassed by attackers using custom user agents.  
- **OWASP Reference:** [OWASP Testing Guide: User Agent Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Fingerprint_Web_Server)  
- **Recommendation & Prevention Strategy:**  
  - Ensure consistent security controls regardless of user agent.  
  - Validate and sanitize all user input, including headers.

---
## Prevention & Recommendations

### Prioritized Action Plan

1. **Immediate Remediation (Within 1 week):**
   - **Add Security Headers:**  
     - Implement a strict Content-Security-Policy (CSP) header to restrict sources of scripts, styles, images, and other resources to trusted domains only.  
     - Add the X-Frame-Options header (`DENY` or `SAMEORIGIN`) to prevent clickjacking.  
     - Add the X-Content-Type-Options header (`nosniff`) to prevent MIME-sniffing attacks.
   - **Restrict CORS:**  
     - Configure CORS to allow only trusted domains and remove `Access-Control-Allow-Origin: *` unless absolutely necessary.
   - **Sanitize Client-Side Code:**  
     - Remove all sensitive comments and debug information from production JavaScript and HTML files.
   - **CSRF Protection:**  
     - Implement anti-CSRF tokens in all forms that perform state-changing operations and set cookies with the `SameSite` attribute.

2. **Short-Term (Within 1 month):**
   - **Enable HSTS:**  
     - Configure the web server to include the Strict-Transport-Security (HSTS) header in all HTTPS responses.
   - **Suppress Server Version Information:**  
     - Remove or genericize the `Server` HTTP header to prevent version disclosure.
   - **Error Handling:**  
     - Display only generic error messages to users and log detailed errors server-side for authorized personnel.
   - **Review Cache-Control:**  
     - Set appropriate cache-control headers to prevent sensitive data from being cached by browsers or intermediaries.
   - **Update and Secure Frameworks:**  
     - Ensure all frameworks and third-party libraries are up to date and securely configured.

3. **Ongoing:**
   - **Regular Security Scans:**  
     - Conduct regular automated and manual security assessments to identify new vulnerabilities.
   - **Developer Training:**  
     - Provide ongoing security training for developers and administrators.
   - **Patch Management:**  
     - Maintain a process for timely patching and updating of all software components and dependencies.
   - **Session Management:**  
     - Ensure session tokens are transmitted securely, not exposed in URLs or client-side scripts, and implement session expiration.
   - **Monitor Authentication Endpoints:**  
     - Implement account lockout, rate limiting, and monitor for suspicious activity.
---
## Appendices

### Appendix A: Scan Settings

- **Tool Used:** OWASP ZAP (Zed Attack Proxy)
- **Scan Profile:** Standard
- **Scan Date:** 2025-06-28
- **Scan Duration:** 1 hour 15 minutes
- **Scope:** All accessible URLs of the Travelling Admin Portal
- **Authentication:** None (public endpoints only)
- **Crawling Method:** Automated spider and AJAX spider

---

### Appendix B: Vulnerability Summary Table

| Risk Level   | # Issues | Example Vulnerability                        | Recommendation                                   |
|--------------|----------|----------------------------------------------|--------------------------------------------------|
| Critical     | 0        | N/A                                          | N/A                                              |
| High         | 0        | N/A                                          | N/A                                              |
| Medium       | 3        | CSP Header Not Set, CORS, Clickjacking       | Add CSP, restrict CORS, add X-Frame-Options      |
| Low          | 6        | HSTS, Server Version, JS Inclusion, Timestamps, etc. | Enable HSTS, suppress server version, review JS  |
| Info         | 5        | Suspicious Comments, Cache, User Agent Fuzzer, etc.   | Remove comments, review cache, consistent controls|

---

### Appendix C: Screenshots & Evidence

- **Figure 1:** ZAP Scan Summary Screenshot  
  ![ZAP Scan Summary](https://github.com/user-attachments/assets/5503c37b-5419-4197-a01a-c77a7bf2b7b5)

- **Additional Evidence:**  
  - [2025-05-24-ZAP-Report-TravellingAdminpage.html](2025-05-24-ZAP-Report-TravellingAdminpage.html) (full raw ZAP report)

---

### Appendix D: References

1. [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
2. [ZAP by Checkmarx](https://www.zaproxy.org/)
3. [OWASP Top 10: A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
4. [RFC 6797: HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)
5. [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
6. [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
7. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
8. [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---
