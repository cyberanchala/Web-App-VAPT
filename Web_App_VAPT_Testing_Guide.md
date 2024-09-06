
# Web Application VAPT (Vulnerability Assessment and Penetration Testing) Reference Guide

This document outlines the key areas of testing during a Web Application Vulnerability Assessment and Penetration Testing (VAPT). The testing methodologies, techniques, and areas covered help assess and secure web applications by identifying security vulnerabilities and potential attack vectors.

## 1. Information Gathering
The initial phase focuses on collecting information about the target application and its environment.
- Manually explore the site
- Spider/crawl for missed or hidden content
- Check for files that expose content (e.g., `robots.txt`, `sitemap.xml`, `.DS_Store`)
- Check caches of major search engines for publicly accessible sites
- Check for content differences based on User Agent (e.g., Mobile sites, Search engine Crawler access)
- Perform Web Application Fingerprinting
- Identify:
  - Technologies used
  - User roles
  - Application entry points
  - Client-side code
  - Multiple versions/channels (e.g., web, mobile web, mobile app, web services)
  - Co-hosted and related applications
  - Hostnames and ports
  - Third-party hosted content

## 2. Configuration Management
Testing focuses on identifying configuration weaknesses that could expose sensitive information or functionality.
- Check for commonly used application and administrative URLs
- Test for old, backup, and unreferenced files
- Test HTTP methods supported and Cross-Site Tracing (XST)
- Test file extensions handling
- Test for security HTTP headers (e.g., CSP, X-Frame-Options, HSTS)
- Test for policies (e.g., Flash, Silverlight, robots)
- Check for non-production data in a live environment (and vice-versa)
- Check for sensitive data in client-side code (e.g., API keys, credentials)

## 3. Secure Transmission
Evaluate the security of data transmission, ensuring sensitive information is properly encrypted.
- Check SSL versions, algorithms, and key lengths
- Validate digital certificate duration, signature, and CN
- Ensure credentials are delivered only over HTTPS
- Ensure login forms are delivered over HTTPS
- Ensure session tokens are delivered only over HTTPS
- Check for HTTP Strict Transport Security (HSTS) usage

## 4. Authentication
Assess authentication mechanisms for weaknesses that could lead to unauthorized access.
- Test for:
  - User enumeration
  - Authentication bypass
  - Brute-force protection
  - Password quality rules
  - "Remember Me" functionality
  - Autocomplete on password forms/inputs
  - Password reset and recovery processes
  - Password change process
  - CAPTCHA
  - Multi-factor authentication (MFA)
  - Logout functionality presence
  - Cache management on HTTP (e.g., `Pragma`, `Expires`, `Max-age`)
  - Default logins
  - User-accessible authentication history
  - Out-of-channel notifications for account lockouts and successful password changes
- Test for consistent authentication across applications using shared authentication schema (SSO)

## 5. Session Management
Analyze session handling to ensure secure user sessions.
- Establish session management mechanisms (e.g., tokens in cookies, tokens in URLs)
- Check session tokens for cookie flags (`httpOnly`, `secure`)
- Check session cookie scope (path and domain)
- Check session cookie duration (`expires`, `max-age`)
- Ensure session termination after:
  - A maximum lifetime
  - A relative timeout
  - Logout
- Test for:
  - Multiple simultaneous sessions per user
  - Session cookie randomness
  - New session tokens issued on login, role change, and logout
  - Consistent session management across applications with shared session management
  - Session puzzling
  - Cross-Site Request Forgery (CSRF) and clickjacking vulnerabilities

## 6. Authorization
Test access control mechanisms to prevent unauthorized access to resources.
- Test for:
  - Path Traversal : Test for access to directories or files outside of the intended directory.
  - Authorization schema bypass
  - Vertical Access Control : Check for privilege escalation vulnerabilities.
  - Horizontal Access Control : Ensure users cannot access other users' data at the same privilege level.
  - Missing Authorization : Verify that access to all sensitive resources is properly controlled.

## 7. Data Validation
Ensure that user inputs are validated correctly to prevent various injection attacks.
- Test for various injection vulnerabilities:
  - Cross-site Scripting (XSS): Test for reflected, stored, and DOM-based XSS.
  - Cross-Site Flashing
  - HTML, SQL, LDAP, ORM, XML, XXE, SSI, XPath, and XQuery Injection
  - IMAP/SMTP Injection
  - Code and Expression Language Injection
  - Command Injection
  - Overflow vulnerabilities (Stack, Heap, Integer)
  - Format string vulnerabilities
  - HTTP Splitting/Smuggling
  - HTTP Verb Tampering
  - Open Redirection
  - Local and Remote File Inclusion (LFI, RFI)
  - Client-side and server-side validation inconsistencies
  - NoSQL Injection
  - HTTP Parameter Pollution
  - Auto-binding and Mass Assignment vulnerabilities
  - NULL/Invalid session cookies

## 8. Denial of Service (DoS)
Identify weaknesses that could be exploited to deny legitimate users access to the application.
- Test for:
  - Anti-automation
  - Account Lockout : Test if automated attempts can lock out legitimate users.
  - HTTP Protocol DoS : Test for potential vulnerabilities within the HTTP protocol that can be exploited for DoS attacks.
  - SQL Wildcard DoS : Evaluate the impact of complex SQL queries on server performance.

## 9. Business Logic
Ensure that the business logic of the application cannot be exploited for malicious purposes.
- Test for:
  - Feature Misuse : Test for misuse of features in unintended ways.
  - Non-repudiation : Check for the integrity of actions performed in the application.
  - Trust Relationships : Test the application’s reliance on external systems or users.
  - Data Integrity : Verify the integrity and consistency of business-critical data.
  - Segregation of Duties : Ensure proper segregation of duties among users.

## 10. Cryptography
Evaluate the application’s use of cryptography to ensure data is securely encrypted.
- Check for:
  - Data Encryption : Verify that sensitive data is properly encrypted.
  - Appropriate algorithm usage based on context.
  - Algorithm Strength : Check for the use of weak or deprecated algorithms.
  - Salting : Ensure that proper salting techniques are used to secure hashes.
  - Randomness : Test for the proper use of cryptographically secure randomness functions.

## 11. Risk Functionality - File Uploads
Test for vulnerabilities in file upload functionalities that could lead to malicious file execution or information disclosure.
- Ensure:
  - File Type Whitelisting : Ensure only acceptable file types are allowed for upload.
  - File Size and Frequency Limits : File size limits, upload frequency, and total file count are enforced.
  - Content Validation : Ensure file contents match the defined file type.
  - Antivirus Scanning : Confirm that all uploads are scanned for malicious content.
  - Filename Sanitization : Ensure unsafe filenames are properly sanitized.
  - File Access Control : 
    - Uploaded files are not directly accessible within the web root
    - Files are served on a different hostname/port
    - Uploaded files are integrated with authentication and authorization schemas

## 12. Risk Functionality
Test for other high-risk vulnerabilities that could compromise the web application.
- Test for:
  - Known Vulnerabilities : Check for known vulnerabilities using the Common Vulnerability Scoring System (CVSS).
  - Default Passwords : Ensure no default credentials or guessable passwords are in use. 
  - Non-production data in the live environment (and vice-versa)
  - Injection Vulnerabilities : Test for SQL, code, and other injection attacks.
  - Buffer Overflows : Assess for buffer overflow vulnerabilities.
  - Insecure cryptographic storage
  - Insufficient transport layer protection
  - Improper Error Handling : Ensure sensitive error messages are not exposed to users.
  - All vulnerabilities with a CVSS v2 score > 4.0
  - Authentication and authorization issues
  - CSRF    

## 13. HTML5 Security Testing
Evaluate the use of HTML5 technologies for potential security issues.
- Test:
  - Web messaging : Check for security issues in HTML5 web messaging.
  - Web storage SQL Injection: : Test for SQL injection vulnerabilities in web storage.
  - Cross-Origin Resource Sharing (CORS) implementation : Ensure CORS policies are properly configured.
  - Offline web application behavior : Assess the security of offline functionality.

## 14. Error Handling
Ensure that error messages do not leak sensitive information.
- Check for:
  - Error codes : Verify that detailed error messages do not reveal internal information.
  - Stack traces : Ensure stack traces are not exposed to end users.

## 15. Unknown Error and Vulnerability Testing
Identify unknown or undocumented vulnerabilities through creative and exploratory testing methods.
- Test for unknown vulnerabilities

---
