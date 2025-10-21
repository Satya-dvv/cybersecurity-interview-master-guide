# VAPT Interview Questions and Answers

A comprehensive, subject-based set of 120 unique, non-repetitive interview questions and thorough answers covering Vulnerability Assessment and Penetration Testing (VAPT). Organized by categories for clarity.

---

## 1) Fundamentals and Concepts

1. What is VAPT?
Answer: VAPT stands for Vulnerability Assessment and Penetration Testing. Vulnerability Assessment identifies and prioritizes weaknesses using scanning and configuration reviews, while Penetration Testing attempts to exploit those weaknesses to demonstrate real-world impact and validate risk. Combining both provides breadth (VA) and depth (PT) to guide remediation and risk reduction.

2. Why do organizations perform VAPT?
Answer: VAPT helps identify security gaps, validate the effectiveness of controls, prevent breaches, support compliance requirements, quantify risk, and prioritize remediation by demonstrating exploitability and potential business impact.

3. What is the difference between a vulnerability and an exploit?
Answer: A vulnerability is a weakness in a system, configuration, or process that could be abused. An exploit is a method or code that leverages that vulnerability to achieve unauthorized actions like data access, code execution, or privilege escalation.

4. Explain Threat, Vulnerability, and Risk.
Answer: Threat is a potential cause of an unwanted incident (e.g., attacker, malware). Vulnerability is a weakness that can be exploited. Risk is the likelihood a threat exploits a vulnerability and the resulting impact on the organization.

5. What is the difference between an authenticated and unauthenticated test?
Answer: Authenticated testing uses valid credentials to assess controls and security from an insider or logged-in perspective, revealing deeper issues like privilege escalation and sensitive data exposures. Unauthenticated testing simulates an external attacker without credentials, focusing on perimeter and public-facing exposures.

6. Define black-box, white-box, and gray-box testing.
Answer: Black-box: no internal knowledge; tests from an external perspective. White-box: full knowledge, including source and design; deeper coverage. Gray-box: partial knowledge or limited credentials; balances realism and depth.

7. What is scope in a VAPT engagement?
Answer: Scope defines which systems, applications, networks, environments, and user roles are permitted for testing, including IP ranges, URLs, in-scope functionalities, time windows, and constraints. Clear scope prevents unauthorized testing and aligns expectations.

8. What is a Rules of Engagement (RoE) document?
Answer: RoE outlines objectives, scope, contact points, testing windows, allowed tools and techniques, data handling, notification/stop conditions, and reporting expectations. It governs how the test is conducted and ensures safety and compliance.

9. What are common VAPT deliverables?
Answer: Deliverables typically include an executive summary, detailed findings with CVSS/CWE/OWASP references, evidence and PoCs, risk ratings, business impact, remediation steps, a remediation roadmap, and optionally a retest report.

10. What is the difference between vulnerability scanning and vulnerability assessment?
Answer: Scanning is the automated discovery step that identifies potential issues. Assessment adds analyst validation, contextual risk analysis, false positive reduction, and prioritization, resulting in actionable findings.

---

## 2) VA vs PT Differences and Use Cases

11. When would you choose VA over PT?
Answer: Choose VA for broad coverage, routine hygiene, inventory of weaknesses, and compliance checks across many assets, especially when resources are limited or prior to a targeted PT.

12. When is PT preferred over VA?
Answer: PT is preferred when validating exploitability, demonstrating business impact, assessing defense-in-depth, testing incident response, or meeting requirements for simulated attacks on critical systems.

13. Can VA and PT be performed independently?
Answer: Yes, but they are complementary. VA without PT may overestimate risk due to lack of exploit validation, while PT without VA may miss breadth and recurring hygiene issues.

14. How do you prioritize vulnerabilities found in VA for PT?
Answer: Prioritize by exposure (internet-facing), privilege reach, data sensitivity, exploit availability, ease of exploitation, business criticality, and chaining potential with other weaknesses.

15. What are typical false positives in VA and how does PT help?
Answer: False positives include misidentified versions, benign open ports, or mitigated CVEs. PT helps by verifying exploitability, testing compensating controls, and validating whether the vulnerability is reachable and impactful.

---

## 3) Process, Planning, and Methodology

16. Describe a typical VAPT lifecycle.
Answer: Lifecycle includes scoping and RoE, asset discovery, threat modeling, information gathering, scanning, manual verification, exploitation (PT), post-exploitation, impact analysis, risk rating, reporting, remediation support, and optional retesting.

17. What is threat modeling in VAPT?
Answer: Threat modeling identifies assets, trust boundaries, attacker profiles, attack surfaces, and abuse cases to focus testing on likely paths with the highest business impact. Techniques include STRIDE, attack trees, and data flow diagrams.

18. Why is asset inventory important?
Answer: Asset inventory ensures complete coverage, identifies shadow IT, informs prioritization by business value, and prevents testing of out-of-scope systems.

19. How do maintenance windows affect testing?
Answer: They reduce operational risk, coordinate with stakeholders, and permit tests that might be disruptive (e.g., DoS-safe checks, credential brute force) within agreed limits.

20. What pre-engagement checks are essential?
Answer: Confirm scope, change approvals, legal authorization, data handling agreements, backup/rollback plans, contacts/war room, and monitoring/IR readiness to respond to alarms.

21. What is non-destructive testing?
Answer: Techniques designed to avoid service disruption or data loss, such as avoiding destructive payloads, not deleting data, rate-limiting brute force attempts, and using safe exploit flags when available.

22. How do you handle production vs staging testing?
Answer: Prefer staging for aggressive tests; in production, limit high-risk actions, coordinate closely, monitor health, and have rollback and stop conditions defined in RoE.

23. What is evidence collection?
Answer: Capturing screenshots, request/response samples, payloads, timestamps, hashes, and network traces to substantiate findings, reproduce issues, and support remediation.

24. Explain post-exploitation.
Answer: Activities after successful compromise: privilege escalation, lateral movement, persistence checks (without installing persistence in ethical tests), data access validation, and controlled cleanup.

25. What is a retest and why is it important?
Answer: A retest validates that remediation is effective, confirms vulnerabilities are resolved, ensures no regressions, and updates risk posture, often a separate deliverable.

---

## 4) Web Application Security

26. What is SQL Injection and how do you test for it?
Answer: SQLi is manipulation of queries via unsanitized input, enabling data extraction or modification. Test by using payloads (' OR 1=1--), UNION-based probes, boolean/time-based blind techniques, and parameterized queries verification. Tools include Burp, sqlmap; mitigations include prepared statements and least privilege DB accounts.

27. Explain Cross-Site Scripting (XSS) types.
Answer: Reflected XSS occurs when user input is immediately echoed, stored XSS is saved and served to others, and DOM XSS arises from client-side JS manipulating the DOM unsafely. Prevent with output encoding, input validation, CSP, and secure frameworks.

28. What is Cross-Site Request Forgery (CSRF)?
Answer: CSRF tricks a victim’s browser into sending authenticated requests. Mitigate with anti-CSRF tokens, SameSite cookies, re-authentication for sensitive actions, and checking Origin/Referer headers.

29. What is IDOR and how do you detect it?
Answer: Insecure Direct Object Reference allows access to resources by manipulating identifiers (e.g., /user/123). Test by changing IDs, guessing patterns, and checking server-side authorization. Fix with server-side ACLs and indirect references.

30. Explain SSRF and its risks.
Answer: Server-Side Request Forgery forces the server to request internal or external resources. Risks include cloud metadata access, internal port scanning, and pivoting. Mitigate with allowlists, blocking internal ranges, and metadata protections.

31. What is command injection vs code injection?
Answer: Command injection executes OS commands via unsanitized input; code injection executes application code (e.g., eval). Prevent with strict input validation, parameterization, safe APIs, and least privilege.

32. What is authentication security best practice?
Answer: Use MFA, secure password storage (bcrypt/Argon2), lockout and rate limiting, session rotation on login, secure cookie flags, and modern protocols (OIDC/OAuth2).

33. How do you test session management?
Answer: Check session fixation, secure/HttpOnly/SameSite flags, predictable IDs, timeout, remember-me tokens, logout invalidation, and session rotation after privilege changes.

34. What are common file upload risks?
Answer: RCE via executable files, storage consumption, malware uploads, and path traversal. Mitigate with extension and MIME allowlists, AV scanning, random paths, and storing outside webroot with indirect retrieval.

35. Explain business logic vulnerabilities.
Answer: Flaws in workflows and assumptions (e.g., bypassing payment, abusing discounts, race conditions) not easily found by scanners. Test via understanding flows, negative testing, and edge cases.

36. What is clickjacking and mitigation?
Answer: UI redressing tricks clicks on hidden iframes. Mitigate with X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors and visual defenses for critical actions.

37. What is mass assignment?
Answer: Automatically binding user input to object fields can overwrite sensitive attributes. Prevent with allowlists, DTOs, and server-side validation.

38. Explain rate limiting and its importance.
Answer: Controls request frequency to deter brute force, scraping, enumeration, and DoS. Implement per-user/IP quotas, backoff, and CAPTCHA where appropriate.

39. How do you assess API security?
Answer: Review authentication (OAuth2/JWT), authorization, input validation, excessive data exposure, pagination, rate limits, and error handling. Test for IDOR, injection, TLS, and improper CORS.

40. What is CORS and common misconfigurations?
Answer: CORS defines cross-origin access rules. Misconfigs include wildcard origins with credentials, reflecting Origin headers, or trusting untrusted subdomains. Configure strict allowlists and avoid credentials with wildcards.

41. What is path traversal and how to test it?
Answer: Path traversal uses sequences like ../ to access unintended files. Test with crafted paths, URL encoding, and observe response differences. Mitigate by normalizing paths, using allowlists, and enforcing sandboxed directories.

42. How do you test for insecure deserialization?
Answer: Identify serialized data in cookies/requests, tamper with fields, replay, and observe behavior. Use gadgets knowledge; mitigate with signed tokens, avoid native serialization, and perform integrity checks.

43. What is open redirect and why is it risky?
Answer: Allows redirecting users to attacker-controlled URLs via parameters. Risks include phishing and token theft. Mitigate with strict allowlists and absolute URL validation.

44. How do you validate input securely?
Answer: Combine server-side validation, allowlists, length/type checks, canonicalization, and output encoding. Avoid relying on client-side checks alone.

45. What is security misconfiguration?
Answer: Insecure defaults, verbose errors, directory listings, missing headers, unnecessary services. Fix by hardening, patching, minimal services, and secure headers.

---

## 5) Network and Infrastructure Security

46. How do you perform network reconnaissance safely?
Answer: Use passive discovery (OSINT, DNS records), safe scanning (Nmap with conservative flags), coordinate times, throttle rates, and avoid disruptive checks unless approved.

47. What is the difference between TCP and UDP scanning?
Answer: TCP scans establish connections (SYN/Connect), providing reliable results; UDP scans are connectionless and slower with more false negatives; combine with service discovery and banner grabbing.

48. Explain common network ports and services relevant to VAPT.
Answer: Examples: 22/SSH, 80/HTTP, 443/HTTPS, 3306/MySQL, 3389/RDP, 389/LDAP, 445/SMB. Each has typical misconfigurations and known CVEs; prioritize exposed high-value services.

49. What are typical network misconfigurations?
Answer: Default credentials, open management interfaces, outdated protocols (Telnet/FTP), weak ciphers, exposed admin panels, anonymous SMB shares, and overly permissive firewall rules.

50. How do you assess TLS/SSL security?
Answer: Check protocol versions, cipher suites, certificate validity, HSTS, key exchange strength, and vulnerabilities like BEAST/POODLE/Heartbleed using tools like testssl.sh and sslyze.

51. What is SMB signing and why does it matter?
Answer: SMB signing protects against man-in-the-middle attacks by verifying message integrity. Lack of signing enables relay attacks and tampering in Windows networks.

52. Explain VLAN hopping and mitigation.
Answer: Exploits switch misconfigs to access other VLANs (switch spoofing/double tagging). Mitigate by disabling DTP, using access ports, and proper trunk configurations.

53. What is ARP spoofing?
Answer: An attacker poisons ARP cache to intercept or redirect traffic. Mitigate with dynamic ARP inspection, static ARP for critical hosts, and network segmentation.

54. How do you test wireless security?
Answer: Assess encryption (WPA2/WPA3), weak passphrases, rogue AP detection, client isolation, captive portal bypass, and enterprise 802.1X configurations.

55. Explain network lateral movement techniques.
Answer: After foothold, attackers use credential dumping, pass-the-hash/ticket, remote execution (WMI/PSExec), and pivoting through tunnels to reach high-value targets.

56. What is network segmentation and why is it important?
Answer: Segmentation limits blast radius by isolating systems by trust level. It reduces lateral movement and confines sensitive workloads. Validate with ACLs and firewall rules.

57. How do you assess firewall rules effectively?
Answer: Review rule base for shadowed rules, overly permissive any-any, unnecessary services, weak zones, and missing logging. Validate with targeted scans and packet captures.

58. What are risks of exposed management interfaces?
Answer: Unauthenticated access, credential brute force, and exploitation of admin panels (e.g., SSH, RDP, web consoles). Restrict by VPN, IP allowlists, MFA, and jump hosts.

59. What is DNS security testing?
Answer: Check for zone transfers, DNSSEC, cache poisoning protections, wildcard records, and subdomain takeover risks via dangling DNS entries.

60. How do you evaluate network time services (NTP) risks?
Answer: Open NTP can be abused for reflection attacks and time tampering. Restrict to internal servers, authenticate, and limit commands.

---

## 6) Host, OS, and Active Directory

61. What are common Windows hardening gaps?
Answer: Local admin reuse, SMB signing disabled, weak NTLMv1, missing patching, lax UAC, insecure service permissions, and writable PATH directories. Apply CIS benchmarks and LAPS.

62. How do you assess Linux server security?
Answer: Review SSH configs, sudoers, file permissions, kernel/sysctl settings, outdated packages, service exposure, and logs. Use Lynis, Bash scripts, and manual checks.

63. What is privilege escalation?
Answer: Gaining higher permissions using misconfigurations, unpatched flaws, weak service configs, SUID binaries, kernel exploits, or credential reuse. Enumerate systematically and exploit safely with proof-of-concept only.

64. Explain Pass-the-Hash and mitigation.
Answer: Using captured NTLM hashes for authentication without cracking. Mitigate with strong isolation of privileged accounts, SMB signing, restricting lateral movement, and enforcing Kerberos with protections like AES and Credential Guard.

65. How do you evaluate AD security posture?
Answer: Enumerate users/groups, ACLs, delegation, GPOs, trust relationships, and tiering. Use BloodHound/SharpHound, check Kerberoasting, AS-REP roasting, unconstrained delegation, and misconfigurations.

66. What is Kerberoasting?
Answer: Requesting service tickets for SPNs to obtain crackable hashes offline. Mitigate with strong service account passwords, Managed Service Accounts, and monitoring for abnormal TGS requests.

67. What are common Linux privilege escalation vectors?
Answer: Sudo misconfigs (NOPASSWD), writable scripts executed by root, SUID binaries, world-writable cron jobs, kernel exploits, and credentials in config files.

68. How do you safely collect credentials during PT?
Answer: Only as permitted by scope, use memory-safe tools, avoid storing plaintext, hash evidence securely, redact sensitive content in reports, and follow data sanitization policies.

69. What is persistence and why is it avoided in ethical tests?
Answer: Persistence maintains access across reboots. Ethical tests avoid installing persistence unless explicitly authorized because it alters systems and may introduce risk.

70. How to assess endpoint EDR/AV effectiveness without disruption?
Answer: Use benign test files (EICAR), observe telemetry, test alerting on known behaviors, and coordinate with SOC to validate detection, avoiding destructive payloads.

71. What is AS-REP roasting?
Answer: Attacking Kerberos accounts without pre-auth by requesting AS-REP and cracking returned hashes. Mitigate by requiring pre-auth for all accounts and using strong passwords.

72. Explain constrained vs unconstrained delegation risks.
Answer: Unconstrained delegation lets a server impersonate any user to any service, enabling domain compromise if server is breached. Constrained limits delegation to specified services; use it for least privilege.

73.
