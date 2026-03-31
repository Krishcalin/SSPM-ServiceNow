#!/usr/bin/env python3
"""Generate synthetic ServiceNow SSPM reports without live API connections."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from servicenow_scanner import ServiceNowScanner, Finding

def main():
    # Create scanner instance bypassing __init__ (no API connection needed)
    scanner = ServiceNowScanner.__new__(ServiceNowScanner)
    scanner.base_url = "https://demo-corp.service-now.com"
    scanner.auth = None
    scanner.verbose = False
    scanner.findings = []
    scanner._props_cache = {}
    scanner._api_errors = []

    # Inject synthetic findings across all ServiceNow SSPM categories
    synthetic_findings = [
        # XSS Prevention
        Finding("SN-XSS-001", "HTML escaping disabled (glide.ui.escape_text)",
                "XSS Prevention", "CRITICAL",
                "sys_properties", None,
                "glide.ui.escape_text = false",
                "HTML output escaping is disabled, allowing stored/reflected XSS attacks.",
                "Set glide.ui.escape_text to true to enable global HTML output escaping."),
        Finding("SN-XSS-002", "Jelly HTML escaping disabled",
                "XSS Prevention", "CRITICAL",
                "sys_properties", None,
                "glide.ui.escape_all_script = false",
                "Jelly template HTML escaping is disabled, allowing XSS through server-side templates.",
                "Set glide.ui.escape_all_script to true."),
        Finding("SN-XSS-003", "Strict Content-Security-Policy header missing",
                "XSS Prevention", "MEDIUM",
                "sys_properties", None,
                "glide.http.content_security_policy = not set",
                "No Content-Security-Policy header is configured, reducing defense-in-depth against XSS.",
                "Configure a strict CSP header via glide.http.content_security_policy."),

        # Session Management
        Finding("SN-SESS-001", "Session timeout too long",
                "Session Management", "HIGH",
                "sys_properties", None,
                "glide.ui.session_timeout = 480 (minutes)",
                "Session timeout of 8 hours exceeds best practice of 30 minutes for idle sessions.",
                "Set glide.ui.session_timeout to 30 or less."),
        Finding("SN-SESS-002", "Absolute session timeout not enforced",
                "Session Management", "MEDIUM",
                "sys_properties", None,
                "glide.ui.session_absolute_timeout = not set",
                "No absolute session timeout forces re-authentication regardless of activity.",
                "Set glide.ui.session_absolute_timeout to 480 (8 hours)."),
        Finding("SN-SESS-003", "Session cookies lack Secure flag",
                "Session Management", "HIGH",
                "sys_properties", None,
                "glide.cookies.secure = false",
                "Session cookies transmitted over HTTP can be intercepted.",
                "Set glide.cookies.secure to true to enforce HTTPS-only cookies."),
        Finding("SN-SESS-004", "Session fixation protection disabled",
                "Session Management", "HIGH",
                "sys_properties", None,
                "glide.security.session.regenerate_on_login = false",
                "Session IDs not regenerated on login enables session fixation attacks.",
                "Set glide.security.session.regenerate_on_login to true."),

        # Authentication
        Finding("SN-AUTH-001", "SSO not enabled",
                "Authentication", "HIGH",
                "sys_properties", None,
                "glide.authenticate.multisso.enabled = false",
                "Single Sign-On is not configured, users authenticate with local passwords only.",
                "Enable SSO integration with your corporate IdP (Okta, Azure AD, etc.)."),
        Finding("SN-AUTH-002", "Password complexity requirements too weak",
                "Authentication", "HIGH",
                "sys_properties", None,
                "glide.security.password.min_length = 6",
                "Minimum password length of 6 is below the recommended 12+ characters.",
                "Set glide.security.password.min_length to at least 12."),
        Finding("SN-AUTH-003", "Account lockout threshold too high",
                "Authentication", "MEDIUM",
                "sys_properties", None,
                "glide.security.lockout.threshold = 20",
                "Account lockout after 20 failed attempts allows extensive brute-force attempts.",
                "Set lockout threshold to 5 or fewer attempts."),
        Finding("SN-AUTH-004", "Failed login lockout duration too short",
                "Authentication", "MEDIUM",
                "sys_properties", None,
                "glide.security.lockout.duration = 60 (seconds)",
                "1-minute lockout is too short to deter automated attacks.",
                "Set lockout duration to at least 15 minutes (900 seconds)."),

        # Access Control
        Finding("SN-ACL-001", "ACL enforcement disabled for specific tables",
                "Access Control", "CRITICAL",
                "sys_security_acl", None,
                "3 ACLs with active=false on sensitive tables (sys_user, sys_user_has_role)",
                "Disabled ACLs on user/role tables allow unauthorized data access.",
                "Re-enable ACLs on all sensitive tables and verify rule logic."),
        Finding("SN-ACL-002", "Excessive admin role assignments",
                "Access Control", "HIGH",
                "sys_user_has_role", None,
                "Users with admin role: 47 (recommended: < 10)",
                "Too many users have the admin role, increasing blast radius of compromised accounts.",
                "Review admin role assignments. Implement least-privilege with custom roles."),
        Finding("SN-ACL-003", "Elevated roles assigned to integration users",
                "Access Control", "MEDIUM",
                "sys_user_has_role", None,
                "Integration users with admin: svc_integration, svc_ldap_sync",
                "Service accounts with admin roles can be exploited if credentials are compromised.",
                "Create dedicated roles for integrations with minimum required permissions."),

        # Data Protection
        Finding("SN-DATA-001", "Encryption at rest not enabled",
                "Data Protection", "HIGH",
                "sys_properties", None,
                "glide.db.encryption.enabled = false",
                "Database encryption at rest is not enabled, risking data exposure if storage is compromised.",
                "Enable column-level encryption for sensitive fields and full database encryption."),
        Finding("SN-DATA-002", "Attachment download unrestricted",
                "Data Protection", "MEDIUM",
                "sys_properties", None,
                "glide.security.file.mime_type_validation = false",
                "No MIME type validation on file downloads allows serving of malicious content.",
                "Enable MIME type validation and restrict allowed file types."),

        # Instance Security
        Finding("SN-INST-001", "Debug mode enabled in production",
                "Instance Security", "MEDIUM",
                "sys_properties", None,
                "glide.debug.active = true",
                "Debug mode exposes internal details that assist attackers in reconnaissance.",
                "Disable debug mode (glide.debug.active = false) in production."),
        Finding("SN-INST-002", "HTTP Strict Transport Security missing",
                "Instance Security", "MEDIUM",
                "sys_properties", None,
                "glide.security.hsts.enabled = false",
                "Without HSTS, users may connect over HTTP and be susceptible to MITM attacks.",
                "Enable HSTS with glide.security.hsts.enabled = true."),

        # Audit & Logging
        Finding("SN-AUDIT-001", "Audit logging not enabled for all tables",
                "Audit & Logging", "HIGH",
                "sys_audit", None,
                "Audited tables: 12 of 45 sensitive tables",
                "Many sensitive tables are not audited, making incident investigation incomplete.",
                "Enable audit logging on all tables containing PII, credentials, or security settings."),
        Finding("SN-AUDIT-002", "Login audit trail retention too short",
                "Audit & Logging", "MEDIUM",
                "sys_properties", None,
                "glide.security.audit.retention_days = 30",
                "30-day audit retention may not meet compliance requirements (typically 90+ days).",
                "Set audit log retention to at least 90 days, or forward to SIEM for long-term storage."),

        # CSRF Protection
        Finding("SN-CSRF-001", "CSRF protection not enforced",
                "CSRF Protection", "HIGH",
                "sys_properties", None,
                "glide.security.csrf.enabled = false",
                "CSRF tokens not required, allowing cross-site request forgery attacks.",
                "Enable CSRF protection with glide.security.csrf.enabled = true."),

        # API Security
        Finding("SN-API-001", "REST API rate limiting not configured",
                "API Security", "MEDIUM",
                "sys_properties", None,
                "glide.rest.rate_limit.enabled = false",
                "No rate limiting on REST API allows abuse and potential denial of service.",
                "Configure REST API rate limiting per user/IP."),
        Finding("SN-API-002", "SOAP API endpoints publicly accessible",
                "API Security", "MEDIUM",
                "sys_properties", None,
                "glide.security.soap.require_authentication = false",
                "Unauthenticated SOAP API access exposes instance data.",
                "Require authentication for all SOAP API endpoints."),

        # Stale Users
        Finding("SN-USER-001", "Stale user accounts detected",
                "User Lifecycle", "MEDIUM",
                "sys_user", None,
                "Stale users: john.ex@corp.com, old.vendor@partner.com (+3 more)",
                "5 users have not logged in for over 90 days and still have active accounts.",
                "Disable or deactivate stale accounts. Implement automated user lifecycle management."),
    ]

    scanner.findings = synthetic_findings

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "servicenow_sspm_report.json")
    html_path = os.path.join(out_dir, "servicenow_sspm_report.html")

    scanner.print_report()
    scanner.save_json(json_path)
    scanner.save_html(html_path)

    print(f"\n[+] Total findings: {len(scanner.findings)}")
    counts = scanner.summary()
    for sev, count in counts.items():
        print(f"    {sev}: {count}")

if __name__ == "__main__":
    main()
