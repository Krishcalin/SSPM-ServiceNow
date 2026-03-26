#!/usr/bin/env python3
"""
ServiceNow SSPM Scanner v1.0.0
SaaS Security Posture Management scanner for ServiceNow instances.

Performs live REST API checks against a ServiceNow instance to identify
security misconfigurations aligned with:
  - Palo Alto Networks SSPM for ServiceNow
  - CIS ServiceNow Security Best Practices
  - OWASP Session Management, XSS, CSRF guidelines

No agent or plugin installation required — uses the standard ServiceNow
Table REST API with read-only credentials.

Usage:
  python servicenow_scanner.py --instance <name> --username <u> --password <p>
  python servicenow_scanner.py --instance https://myco.service-now.com ...

Env var fallback:  SNOW_INSTANCE  SNOW_USERNAME  SNOW_PASSWORD
"""

import os
import re
import sys
import json
import html as html_mod
import argparse
from datetime import datetime, timezone, timedelta

try:
    import requests
    from requests.auth import HTTPBasicAuth
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "1.0.0"

# ============================================================
# SYSTEM PROPERTY RULES
# Each dict describes one sys_properties check.
#
# Operators:
#   eq_true          value (case-insensitive) in ("true","yes","1")
#   eq_false         value in ("false","no","0")
#   lte_int          int(value) <= threshold
#   gte_int          int(value) >= threshold
#   not_empty        value is set and non-blank
#
# missing_is_fail:
#   True  → if property absent from sys_properties → raise finding
#   False → absent means ServiceNow safe default applies → skip
# ============================================================
PROPERTY_RULES = [

    # ── XSS Prevention ───────────────────────────────────────
    {
        "id": "SN-XSS-001",
        "category": "XSS Prevention",
        "name": "HTML escaping disabled (glide.ui.escape_text)",
        "severity": "CRITICAL",
        "property": "glide.ui.escape_text",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "When glide.ui.escape_text is false, user-supplied content is rendered as raw HTML, "
            "enabling stored and reflected Cross-Site Scripting attacks that can steal session "
            "tokens, redirect users, or execute arbitrary browser-side code."
        ),
        "recommendation": (
            "Navigate to System Properties > Security and set 'Escape HTML' (glide.ui.escape_text) "
            "to true. This is a platform default that should never be disabled."
        ),
        "cwe": "CWE-79",
    },
    {
        "id": "SN-XSS-002",
        "category": "XSS Prevention",
        "name": "HTML text-area escaping disabled (glide.ui.escape_html_text_area)",
        "severity": "HIGH",
        "property": "glide.ui.escape_html_text_area",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": (
            "glide.ui.escape_html_text_area=false allows unescaped HTML in multi-line text "
            "area fields, creating an XSS vector in journal and comment fields."
        ),
        "recommendation": "Set glide.ui.escape_html_text_area to true in System Properties.",
        "cwe": "CWE-79",
    },
    {
        "id": "SN-XSS-003",
        "category": "XSS Prevention",
        "name": "AntiSamy HTML sanitization disabled (glide.security.anti_samy.enabled)",
        "severity": "HIGH",
        "property": "glide.security.anti_samy.enabled",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "AntiSamy sanitizes HTML input before storage. Disabling it allows malicious "
            "HTML and script tags to be persisted in rich-text fields, leading to stored XSS."
        ),
        "recommendation": (
            "Set glide.security.anti_samy.enabled to true. Customize the AntiSamy policy "
            "to allow only the HTML tags required by your business."
        ),
        "cwe": "CWE-79",
    },
    {
        "id": "SN-XSS-004",
        "category": "XSS Prevention",
        "name": "Content Security Policy (CSP) not active (glide.security.csp.active)",
        "severity": "HIGH",
        "property": "glide.security.csp.active",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Without a Content Security Policy header, browsers cannot restrict which "
            "scripts and resources can execute, making XSS exploitation significantly easier."
        ),
        "recommendation": (
            "Set glide.security.csp.active to true and configure a strict CSP that limits "
            "script-src to your own domain. Test thoroughly before applying in production."
        ),
        "cwe": "CWE-1021",
    },

    # ── CSRF Protection ──────────────────────────────────────
    {
        "id": "SN-CSRF-001",
        "category": "CSRF Protection",
        "name": "CSRF token validation disabled (glide.security.use_csrf_token)",
        "severity": "HIGH",
        "property": "glide.security.use_csrf_token",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Disabling CSRF token validation exposes ServiceNow forms to Cross-Site Request "
            "Forgery attacks where a malicious site can trigger state-changing actions "
            "(create/update/delete records) on behalf of an authenticated user."
        ),
        "recommendation": (
            "Set glide.security.use_csrf_token to true. Ensure all custom integrations "
            "pass the correct CSRF token in form submissions."
        ),
        "cwe": "CWE-352",
    },

    # ── Session Management ────────────────────────────────────
    {
        "id": "SN-SESS-001",
        "category": "Session Management",
        "name": "Session inactivity timeout too long (glide.ui.session_timeout)",
        "severity": "HIGH",
        "property": "glide.ui.session_timeout",
        "operator": "lte_int",
        "threshold": 30,
        "missing_is_fail": True,
        "description": (
            "A session inactivity timeout greater than 30 minutes keeps authenticated "
            "sessions alive longer than necessary, increasing the window of opportunity "
            "for session hijacking or unauthorized access to unattended workstations."
        ),
        "recommendation": (
            "Set glide.ui.session_timeout to 30 (minutes) or less. "
            "For highly privileged admin sessions, consider 15 minutes."
        ),
        "cwe": "CWE-613",
    },
    {
        "id": "SN-SESS-002",
        "category": "Session Management",
        "name": "Maximum active session lifetime too long (glide.ui.active.session.life_span)",
        "severity": "MEDIUM",
        "property": "glide.ui.active.session.life_span",
        "operator": "lte_int",
        "threshold": 480,
        "missing_is_fail": False,
        "description": (
            "An active session lifespan greater than 8 hours (480 minutes) means a user "
            "who authenticates at the start of their workday never needs to re-authenticate, "
            "leaving long-lived tokens susceptible to theft and replay."
        ),
        "recommendation": (
            "Set glide.ui.active.session.life_span to 480 or less. "
            "Require re-authentication for high-risk operations regardless of session age."
        ),
        "cwe": "CWE-613",
    },
    {
        "id": "SN-SESS-003",
        "category": "Session Management",
        "name": "Guest session timeout too long (glide.guest.session_timeout)",
        "severity": "MEDIUM",
        "property": "glide.guest.session_timeout",
        "operator": "lte_int",
        "threshold": 15,
        "missing_is_fail": False,
        "description": (
            "Unauthenticated (guest) sessions with long timeouts consume server resources "
            "and extend the exposure window for unauthenticated portal pages to automated bots."
        ),
        "recommendation": "Set glide.guest.session_timeout to 15 minutes or less.",
        "cwe": "CWE-613",
    },
    {
        "id": "SN-SESS-004",
        "category": "Session Management",
        "name": "Session ID rotation after login disabled (glide.ui.rotate_sessions)",
        "severity": "HIGH",
        "property": "glide.ui.rotate_sessions",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Without session ID rotation after authentication, a session fixation attack "
            "allows an attacker to pre-set a victim's session token and hijack the session "
            "once the victim logs in."
        ),
        "recommendation": "Set glide.ui.rotate_sessions to true.",
        "cwe": "CWE-384",
    },
    {
        "id": "SN-SESS-005",
        "category": "Session Management",
        "name": "Concurrent session control disabled (glide.ui.concurrency_control)",
        "severity": "LOW",
        "property": "glide.ui.concurrency_control",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": (
            "Without concurrency control, the same credentials can be used to log in "
            "simultaneously from multiple locations, making it harder to detect "
            "account compromise."
        ),
        "recommendation": "Set glide.ui.concurrency_control to true to allow only one active session per user.",
        "cwe": "CWE-613",
    },

    # ── Authentication ────────────────────────────────────────
    {
        "id": "SN-AUTH-001",
        "category": "Authentication: Lockout",
        "name": "Login lockout threshold too high (glide.login.max_failed)",
        "severity": "HIGH",
        "property": "glide.login.max_failed",
        "operator": "lte_int",
        "threshold": 10,
        "missing_is_fail": False,
        "description": (
            "A lockout threshold greater than 10 failed attempts allows excessive "
            "brute-force login attempts before an account is locked, significantly "
            "increasing the risk of credential-stuffing attacks succeeding."
        ),
        "recommendation": (
            "Set glide.login.max_failed to 5 or fewer. Consider combining with "
            "IP-based rate limiting and alerting on repeated failures."
        ),
        "cwe": "CWE-307",
    },
    {
        "id": "SN-AUTH-002",
        "category": "Authentication: Password",
        "name": "Blank passwords permitted (glide.login.no_blank_password)",
        "severity": "CRITICAL",
        "property": "glide.login.no_blank_password",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "When glide.login.no_blank_password is false, accounts can be created or "
            "remain active with an empty password, allowing trivial authentication bypass."
        ),
        "recommendation": "Set glide.login.no_blank_password to true and audit all existing accounts for empty passwords.",
        "cwe": "CWE-521",
    },
    {
        "id": "SN-AUTH-003",
        "category": "Authentication: Basic Auth",
        "name": "Basic authentication required for scripted APIs (glide.basicauth.required.script)",
        "severity": "HIGH",
        "property": "glide.basicauth.required.script",
        "operator": "eq_false",
        "missing_is_fail": False,
        "description": (
            "Requiring basic auth for all scripted REST/SOAP API calls means credentials "
            "are transmitted with every request in a reversibly encoded form, increasing "
            "the risk of credential capture. Prefer OAuth 2.0 token-based authentication."
        ),
        "recommendation": (
            "Migrate API consumers to OAuth 2.0. If basic auth is unavoidable, "
            "ensure HTTPS is enforced and rotate credentials frequently."
        ),
        "cwe": "CWE-523",
    },
    {
        "id": "SN-AUTH-004",
        "category": "Authentication: SSO",
        "name": "SSO not enforced (glide.sso.required)",
        "severity": "MEDIUM",
        "property": "glide.sso.required",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": (
            "When SSO is not enforced, users can bypass your identity provider's MFA and "
            "conditional access policies by authenticating directly with local ServiceNow "
            "credentials."
        ),
        "recommendation": (
            "Set glide.sso.required to true once SSO is fully configured. "
            "Maintain a break-glass local admin account under strict controls."
        ),
        "cwe": "CWE-287",
    },
    {
        "id": "SN-AUTH-005",
        "category": "Authentication: MFA",
        "name": "Multi-factor authentication not enabled (com.snc.login.mfa_enabled)",
        "severity": "HIGH",
        "property": "com.snc.login.mfa_enabled",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Without MFA, a stolen or phished password alone is sufficient to fully "
            "compromise a ServiceNow account, including privileged admin accounts with "
            "access to all records and configuration."
        ),
        "recommendation": (
            "Enable MFA via System Properties or your SSO identity provider. "
            "Enforce MFA for all users and require step-up authentication for "
            "administrative actions."
        ),
        "cwe": "CWE-308",
    },

    # ── Password Policy ───────────────────────────────────────
    {
        "id": "SN-PWD-001",
        "category": "Password Policy",
        "name": "Minimum password length below 8 characters (glide.sys.pw_min_length)",
        "severity": "HIGH",
        "property": "glide.sys.pw_min_length",
        "operator": "gte_int",
        "threshold": 8,
        "missing_is_fail": False,
        "description": (
            "Passwords shorter than 8 characters are trivially brute-forced. "
            "NIST SP 800-63B recommends a minimum of 8 characters and ideally 12+."
        ),
        "recommendation": "Set glide.sys.pw_min_length to at least 12 for all user accounts.",
        "cwe": "CWE-521",
    },
    {
        "id": "SN-PWD-002",
        "category": "Password Policy",
        "name": "Uppercase characters not required in passwords (glide.sys.pw_upper_case)",
        "severity": "MEDIUM",
        "property": "glide.sys.pw_upper_case",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": "Requiring uppercase characters increases password entropy, making brute-force harder.",
        "recommendation": "Set glide.sys.pw_upper_case to true.",
        "cwe": "CWE-521",
    },
    {
        "id": "SN-PWD-003",
        "category": "Password Policy",
        "name": "Lowercase characters not required in passwords (glide.sys.pw_lower_case)",
        "severity": "MEDIUM",
        "property": "glide.sys.pw_lower_case",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": "Requiring lowercase characters adds to password complexity.",
        "recommendation": "Set glide.sys.pw_lower_case to true.",
        "cwe": "CWE-521",
    },
    {
        "id": "SN-PWD-004",
        "category": "Password Policy",
        "name": "Special characters not required in passwords (glide.sys.pw_special)",
        "severity": "MEDIUM",
        "property": "glide.sys.pw_special",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": "Special characters significantly increase password entropy.",
        "recommendation": "Set glide.sys.pw_special to true.",
        "cwe": "CWE-521",
    },
    {
        "id": "SN-PWD-005",
        "category": "Password Policy",
        "name": "Numeric digits not required in passwords (glide.sys.pw_digits)",
        "severity": "MEDIUM",
        "property": "glide.sys.pw_digits",
        "operator": "eq_true",
        "missing_is_fail": False,
        "description": "Numeric digits are a basic component of a strong password policy.",
        "recommendation": "Set glide.sys.pw_digits to true.",
        "cwe": "CWE-521",
    },
    {
        "id": "SN-PWD-006",
        "category": "Password Policy",
        "name": "Password lockout count too high (glide.sys.pw_lock_count)",
        "severity": "HIGH",
        "property": "glide.sys.pw_lock_count",
        "operator": "lte_int",
        "threshold": 10,
        "missing_is_fail": False,
        "description": (
            "A high lock count (>10) allows extensive brute-force attempts. "
            "This is the application-level companion to glide.login.max_failed."
        ),
        "recommendation": "Set glide.sys.pw_lock_count to 5 or fewer.",
        "cwe": "CWE-307",
    },
    {
        "id": "SN-PWD-007",
        "category": "Password Policy",
        "name": "Password history policy too short (glide.sys.pw_history)",
        "severity": "LOW",
        "property": "glide.sys.pw_history",
        "operator": "gte_int",
        "threshold": 5,
        "missing_is_fail": False,
        "description": (
            "A short password history allows users to cycle through a small set of "
            "passwords, negating the security benefit of forced rotation."
        ),
        "recommendation": "Set glide.sys.pw_history to at least 10.",
        "cwe": "CWE-521",
    },

    # ── File Attachment Security ──────────────────────────────
    {
        "id": "SN-FILE-001",
        "category": "File Upload Security",
        "name": "MIME type validation on file uploads disabled (glide.security.file.mime_type.validation)",
        "severity": "HIGH",
        "property": "glide.security.file.mime_type.validation",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Without MIME type validation, attackers can upload malicious files "
            "(e.g., JavaScript disguised as images) that are later served and executed "
            "by the browser, enabling stored XSS and malware delivery."
        ),
        "recommendation": "Set glide.security.file.mime_type.validation to true.",
        "cwe": "CWE-434",
    },

    # ── Transport Security ────────────────────────────────────
    {
        "id": "SN-TLS-001",
        "category": "Transport Security",
        "name": "HTTPS redirect not enforced (glide.ui.https_redirect)",
        "severity": "CRITICAL",
        "property": "glide.ui.https_redirect",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Without HTTPS redirect, users who access ServiceNow over plain HTTP have "
            "their session tokens and credentials transmitted in cleartext, enabling "
            "network interception attacks."
        ),
        "recommendation": (
            "Set glide.ui.https_redirect to true. Additionally, configure an HSTS "
            "header via glide.security.strict_transport_security."
        ),
        "cwe": "CWE-319",
    },
    {
        "id": "SN-TLS-002",
        "category": "Transport Security",
        "name": "SameSite cookie attribute not configured (glide.cookies.same_site)",
        "severity": "MEDIUM",
        "property": "glide.cookies.same_site",
        "operator": "not_empty",
        "missing_is_fail": True,
        "description": (
            "Without the SameSite cookie attribute, ServiceNow session cookies are sent "
            "with cross-site requests, weakening CSRF protection and enabling login "
            "CSRF attacks."
        ),
        "recommendation": (
            "Set glide.cookies.same_site to 'Strict' or 'Lax'. "
            "'Strict' is most secure but may break some SSO flows."
        ),
        "cwe": "CWE-1275",
    },

    # ── Script / Execution Security ───────────────────────────
    {
        "id": "SN-SCRIPT-001",
        "category": "Script Security",
        "name": "Server-side script sandbox disabled (glide.script.use.sandbox)",
        "severity": "HIGH",
        "property": "glide.script.use.sandbox",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "The sandbox restricts server-side scripts from accessing Java classes, "
            "file system, and network resources. Disabling it allows business rules, "
            "Script Includes, and scheduled jobs to perform arbitrary system operations."
        ),
        "recommendation": "Set glide.script.use.sandbox to true and audit all existing server-side scripts.",
        "cwe": "CWE-250",
    },
    {
        "id": "SN-SCRIPT-002",
        "category": "Script Security",
        "name": "Dynamic form generation allowed (glide.security.allow_dynamic_forms)",
        "severity": "MEDIUM",
        "property": "glide.security.allow_dynamic_forms",
        "operator": "eq_false",
        "missing_is_fail": False,
        "description": (
            "Allowing dynamic form generation enables UI pages and portals to inject "
            "arbitrary form fields, which can be used to manipulate business rule "
            "processing or bypass field-level access controls."
        ),
        "recommendation": "Set glide.security.allow_dynamic_forms to false unless required by a validated use case.",
        "cwe": "CWE-20",
    },

    # ── Audit / Logging ───────────────────────────────────────
    {
        "id": "SN-LOG-001",
        "category": "Audit Logging",
        "name": "Platform audit logging disabled (com.glide.audit.enabled)",
        "severity": "HIGH",
        "property": "com.glide.audit.enabled",
        "operator": "eq_true",
        "missing_is_fail": True,
        "description": (
            "Without audit logging, changes to records, configurations, and security "
            "settings are not tracked. This eliminates the ability to detect breaches, "
            "investigate incidents, or demonstrate compliance."
        ),
        "recommendation": (
            "Set com.glide.audit.enabled to true. Enable auditing on all sensitive tables "
            "via the Dictionary Editor (sys_dictionary) by setting the 'Audit' flag."
        ),
        "cwe": "CWE-778",
    },
]

# Extensions that MUST be in ServiceNow's blocked attachment list
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msc", ".jar", ".war", ".ps1", ".psc1",
    ".msh", ".msh1", ".msh2", ".scr", ".com", ".pif", ".reg",
}

# ============================================================
# Finding data class  (identical schema to all other scanners)
# ============================================================
class Finding:
    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = file_path       # repurposed: ServiceNow table name
        self.line_num = line_num         # always None for API checks
        self.line_content = line_content # repurposed: "property = current_value"
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe or ""
        self.cve = cve or ""

    def to_dict(self):
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_num,
            "code": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cve": self.cve,
        }


# ============================================================
# ServiceNow SSPM Scanner
# ============================================================
class ServiceNowScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def __init__(self, instance_url: str, username: str, password: str, verbose: bool = False):
        # Normalise instance URL
        if not instance_url.startswith("http"):
            instance_url = f"https://{instance_url}.service-now.com"
        self.base_url = instance_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.verbose = verbose
        self.findings: list[Finding] = []
        self._props_cache: dict[str, str] = {}   # name → value
        self._api_errors: list[str] = []

    # ----------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------
    def scan(self):
        """Run all SSPM check groups against the instance."""
        print(f"[*] ServiceNow SSPM Scanner v{VERSION}")
        print(f"[*] Target: {self.base_url}")
        print("[*] Fetching system properties …")

        # Pre-fetch all properties referenced in PROPERTY_RULES in one API call
        prop_names = [r["property"] for r in PROPERTY_RULES]
        self._props_cache = self._fetch_properties(prop_names)

        print("[*] Running checks …")
        self._check_system_properties()
        self._check_file_attachments()
        self._check_users()
        self._check_oauth_apps()
        self._check_acls()
        self._check_audit_logging()
        self._check_email_security()

    # ----------------------------------------------------------
    # REST API helpers
    # ----------------------------------------------------------
    def _api_get(self, table: str, params: dict = None) -> list[dict]:
        """
        Fetch all records from a ServiceNow table via the Table REST API.
        Handles pagination automatically (sysparm_limit=500 per page).
        Returns list of record dicts, or [] on error.
        """
        url = f"{self.base_url}/api/now/table/{table}"
        base_params = {
            "sysparm_limit": 500,
            "sysparm_offset": 0,
            "sysparm_display_value": "false",
            "sysparm_exclude_reference_link": "true",
        }
        if params:
            base_params.update(params)

        results = []
        while True:
            try:
                resp = requests.get(
                    url, auth=self.auth, params=base_params,
                    timeout=30,
                    headers={"Accept": "application/json"},
                )
            except requests.exceptions.ConnectionError as e:
                self._warn(f"Cannot connect to {self.base_url}: {e}")
                return []
            except requests.exceptions.Timeout:
                self._warn(f"Timeout fetching {table}")
                return []

            if resp.status_code == 401:
                self._warn("Authentication failed — check username/password.")
                return []
            if resp.status_code == 403:
                self._warn(f"Access denied to table '{table}' — ensure the account has read access.")
                return []
            if resp.status_code == 404:
                self._vprint(f"  [skip] Table '{table}' not found (plugin may not be active).")
                return []
            if resp.status_code != 200:
                self._warn(f"Unexpected {resp.status_code} for {table}: {resp.text[:200]}")
                return []

            try:
                data = resp.json()
            except ValueError:
                self._warn(f"Non-JSON response from {table}")
                return []

            page = data.get("result", [])
            results.extend(page)

            if len(page) < base_params["sysparm_limit"]:
                break   # last page
            base_params["sysparm_offset"] += base_params["sysparm_limit"]

        self._vprint(f"  [api] {table}: {len(results)} record(s)")
        return results

    def _fetch_properties(self, names: list[str]) -> dict[str, str]:
        """
        Batch-fetch sys_properties for a list of property names.
        Returns {name: value} for found properties.
        """
        if not names:
            return {}
        # Build an OR query: nameLIKEprop1^ORnameLIKEprop2 is slow;
        # use IN query which ServiceNow Table API supports.
        query = "nameIN" + ",".join(names)
        records = self._api_get("sys_properties", {
            "sysparm_query": query,
            "sysparm_fields": "name,value",
        })
        return {r["name"]: r.get("value", "") for r in records}

    # ----------------------------------------------------------
    # System Property Checks
    # ----------------------------------------------------------
    def _check_system_properties(self):
        """Evaluate all PROPERTY_RULES against the cached property values."""
        for rule in PROPERTY_RULES:
            prop_name = rule["property"]
            if prop_name in self._props_cache:
                value = self._props_cache[prop_name]
                if not self._evaluate_property(rule, value, found=True):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        file_path="sys_properties",
                        line_num=None,
                        line_content=f"{prop_name} = {value!r}",
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe", ""),
                    ))
            else:
                # Property not explicitly set — use missing_is_fail flag
                if rule.get("missing_is_fail", False):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        file_path="sys_properties",
                        line_num=None,
                        line_content=f"{prop_name} = <not set — unsafe default>",
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe", ""),
                    ))

    def _evaluate_property(self, rule: dict, value: str, found: bool) -> bool:
        """
        Return True if the property value passes the rule (no finding needed).
        Return False if the value violates the rule.
        """
        op = rule["operator"]
        v = (value or "").strip()

        if op == "eq_true":
            return v.lower() in ("true", "yes", "1")
        if op == "eq_false":
            return v.lower() in ("false", "no", "0", "")
        if op == "not_empty":
            return bool(v)
        if op == "lte_int":
            try:
                return int(v) <= rule["threshold"]
            except (ValueError, TypeError):
                return True  # non-numeric → skip
        if op == "gte_int":
            try:
                return int(v) >= rule["threshold"]
            except (ValueError, TypeError):
                return True
        return True  # unknown operator → pass

    # ----------------------------------------------------------
    # File Attachment Security
    # ----------------------------------------------------------
    def _check_file_attachments(self):
        """
        Check glide.attachment.extensions (blocked extension list) to ensure
        all known-dangerous file types are in the blocklist.
        """
        blocked_raw = self._props_cache.get("glide.attachment.extensions", "")
        if not blocked_raw:
            self._add(Finding(
                rule_id="SN-FILE-002",
                name="Attachment blocked-extension list is empty or not configured",
                category="File Upload Security",
                severity="HIGH",
                file_path="sys_properties",
                line_num=None,
                line_content="glide.attachment.extensions = <not set>",
                description=(
                    "The glide.attachment.extensions property controls which file "
                    "extensions are blocked from being uploaded. An empty or missing "
                    "list means no file type restrictions are enforced, allowing upload "
                    "of executables, scripts, and other malicious payloads."
                ),
                recommendation=(
                    "Set glide.attachment.extensions to a comma-separated list of "
                    "dangerous extensions: exe,bat,cmd,vbs,js,ps1,jar,war,scr,com,pif"
                ),
                cwe="CWE-434",
            ))
            return

        # Normalise: split on comma/semicolon, lowercase, add leading dot
        blocked_set = set()
        for token in re.split(r"[,;\s]+", blocked_raw.lower()):
            token = token.strip()
            if token:
                blocked_set.add(token if token.startswith(".") else f".{token}")

        missing = DANGEROUS_EXTENSIONS - blocked_set
        if missing:
            self._add(Finding(
                rule_id="SN-FILE-003",
                name="Dangerous file extensions not blocked in attachment policy",
                category="File Upload Security",
                severity="HIGH",
                file_path="sys_properties",
                line_num=None,
                line_content=f"glide.attachment.extensions = {blocked_raw!r}",
                description=(
                    f"The following dangerous file extensions are not in the blocked list "
                    f"and can be uploaded: {', '.join(sorted(missing))}. "
                    "Uploaded executables or scripts can be used for malware delivery or "
                    "social engineering attacks against ServiceNow users."
                ),
                recommendation=(
                    f"Add these extensions to glide.attachment.extensions: "
                    f"{', '.join(sorted(missing))}"
                ),
                cwe="CWE-434",
            ))

    # ----------------------------------------------------------
    # User Checks
    # ----------------------------------------------------------
    def _check_users(self):
        self._vprint("  [check] User management …")

        # 1. Default 'admin' account active
        admin_users = self._api_get("sys_user", {
            "sysparm_query": "active=true^user_name=admin",
            "sysparm_fields": "sys_id,user_name,name,email,last_login_time",
        })
        if admin_users:
            self._add(Finding(
                rule_id="SN-USER-001",
                name="Default 'admin' account is active",
                category="User Management",
                severity="HIGH",
                file_path="sys_user",
                line_num=None,
                line_content="user_name = admin, active = true",
                description=(
                    "The default 'admin' account is a well-known target for brute-force "
                    "and credential-stuffing attacks. Keeping it active with a predictable "
                    "username significantly increases the risk of account compromise."
                ),
                recommendation=(
                    "Create a named administrator account, transfer all admin roles to it, "
                    "then disable or delete the default 'admin' account."
                ),
                cwe="CWE-798",
            ))

        # 2. Users inactive > 90 days still active
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        stale_users = self._api_get("sys_user", {
            "sysparm_query": f"active=true^last_login_timeBEFORE{cutoff}^user_nameNOT INadmin,guest",
            "sysparm_fields": "sys_id,user_name,name,last_login_time",
        })
        if stale_users:
            sample = ", ".join(u.get("user_name", "?") for u in stale_users[:5])
            suffix = f" (+{len(stale_users)-5} more)" if len(stale_users) > 5 else ""
            self._add(Finding(
                rule_id="SN-USER-002",
                name=f"Active accounts inactive for >90 days ({len(stale_users)} found)",
                category="User Management",
                severity="MEDIUM",
                file_path="sys_user",
                line_num=None,
                line_content=f"Stale users: {sample}{suffix}",
                description=(
                    f"{len(stale_users)} active user account(s) have not logged in for over "
                    "90 days. Stale accounts that are not deprovisioned represent dormant "
                    "access vectors that may be compromised without detection."
                ),
                recommendation=(
                    "Implement an automated account review process. Disable or delete "
                    "accounts that have not been used for 90 days. Integrate with your "
                    "HR system to deactivate accounts immediately upon employee departure."
                ),
                cwe="CWE-613",
            ))

        # 3. Users with 'maint' role (ServiceNow maintenance backdoor)
        maint_roles = self._api_get("sys_user_has_role", {
            "sysparm_query": "role.name=maint^user.active=true",
            "sysparm_fields": "user.user_name,user.name",
        })
        if maint_roles:
            holders = ", ".join(r.get("user.user_name", "?") for r in maint_roles[:5])
            self._add(Finding(
                rule_id="SN-USER-003",
                name=f"Users with 'maint' role detected ({len(maint_roles)} found)",
                category="User Management",
                severity="HIGH",
                file_path="sys_user_has_role",
                line_num=None,
                line_content=f"maint role holders: {holders}",
                description=(
                    "The 'maint' role is a ServiceNow maintenance role that bypasses many "
                    "access controls and is intended only for emergency platform maintenance. "
                    "Users permanently assigned this role have effectively unrestricted access."
                ),
                recommendation=(
                    "Remove the maint role from all non-emergency accounts. "
                    "Grant it only temporarily during maintenance windows and revoke immediately after."
                ),
                cwe="CWE-269",
            ))

        # 4. Count of security_admin role holders
        sec_admin_roles = self._api_get("sys_user_has_role", {
            "sysparm_query": "role.name=security_admin^user.active=true",
            "sysparm_fields": "user.user_name",
        })
        if len(sec_admin_roles) > 5:
            self._add(Finding(
                rule_id="SN-USER-004",
                name=f"Too many security_admin role holders ({len(sec_admin_roles)})",
                category="User Management",
                severity="MEDIUM",
                file_path="sys_user_has_role",
                line_num=None,
                line_content=f"security_admin count = {len(sec_admin_roles)}",
                description=(
                    f"{len(sec_admin_roles)} users hold the security_admin role, which grants "
                    "access to security policies, ACLs, and encryption keys. "
                    "Excessive privileged users increase the blast radius of a compromise."
                ),
                recommendation=(
                    "Limit security_admin to at most 3-5 named individuals. "
                    "Implement a PAM (Privileged Access Management) workflow for "
                    "just-in-time access to this role."
                ),
                cwe="CWE-269",
            ))

        # 5. Admin users without MFA enrolled
        admin_role_users = self._api_get("sys_user_has_role", {
            "sysparm_query": "role.name=admin^user.active=true",
            "sysparm_fields": "user.user_name,user.sys_id,user.mfa_enabled",
        })
        no_mfa_admins = [
            r.get("user.user_name", "?")
            for r in admin_role_users
            if r.get("user.mfa_enabled", "").lower() not in ("true", "yes", "1")
        ]
        if no_mfa_admins:
            sample = ", ".join(no_mfa_admins[:5])
            suffix = f" (+{len(no_mfa_admins)-5} more)" if len(no_mfa_admins) > 5 else ""
            self._add(Finding(
                rule_id="SN-USER-005",
                name=f"Admin users without MFA enrolled ({len(no_mfa_admins)} found)",
                category="User Management",
                severity="CRITICAL",
                file_path="sys_user_has_role",
                line_num=None,
                line_content=f"Admins without MFA: {sample}{suffix}",
                description=(
                    f"{len(no_mfa_admins)} admin user(s) do not have MFA enrolled. "
                    "A compromised admin account without MFA allows an attacker full "
                    "control over the ServiceNow instance: all data, workflows, and "
                    "integrations."
                ),
                recommendation=(
                    "Require MFA enrollment for all admin accounts immediately. "
                    "Block logins for admin accounts without an MFA device registered."
                ),
                cwe="CWE-308",
            ))

        # 6. Service accounts (names ending in _svc, _service, _api, _int) with admin role
        svc_admins = [
            r.get("user.user_name", "?")
            for r in admin_role_users
            if re.search(r"(_svc|_service|_api|_int|svc_|service_|api_)$",
                         r.get("user.user_name", ""), re.IGNORECASE)
        ]
        if svc_admins:
            self._add(Finding(
                rule_id="SN-USER-006",
                name=f"Service accounts with admin role ({len(svc_admins)} found)",
                category="User Management",
                severity="HIGH",
                file_path="sys_user_has_role",
                line_num=None,
                line_content=f"Service accounts with admin: {', '.join(svc_admins[:5])}",
                description=(
                    "Service accounts should never hold admin roles. If a service account "
                    "is compromised (e.g., via API key leak), the attacker gains full "
                    "administrative access to the instance."
                ),
                recommendation=(
                    "Replace admin role on service accounts with the minimum set of "
                    "roles required for the integration. Use dedicated REST API roles "
                    "or granular ACLs instead."
                ),
                cwe="CWE-269",
            ))

    # ----------------------------------------------------------
    # OAuth Checks
    # ----------------------------------------------------------
    def _check_oauth_apps(self):
        self._vprint("  [check] OAuth applications …")

        clients = self._api_get("oauth_entity", {
            "sysparm_fields": (
                "name,client_id,type,access_token_lifespan,"
                "refresh_token_lifespan,active,sys_created_on,last_used_on,scope"
            ),
        })

        if not clients:
            return

        # SN-OAUTH-003: Too many OAuth clients
        active_clients = [c for c in clients if c.get("active", "").lower() in ("true", "1", "yes")]
        if len(active_clients) > 10:
            self._add(Finding(
                rule_id="SN-OAUTH-003",
                name=f"High number of active OAuth clients ({len(active_clients)})",
                category="OAuth: Client Sprawl",
                severity="LOW",
                file_path="oauth_entity",
                line_num=None,
                line_content=f"active OAuth clients = {len(active_clients)}",
                description=(
                    f"{len(active_clients)} active OAuth clients are registered. "
                    "OAuth sprawl makes it difficult to track all third-party integrations, "
                    "identify stale or over-privileged clients, and respond quickly to a "
                    "compromised client credential."
                ),
                recommendation=(
                    "Audit all OAuth clients. Remove those that are no longer in use. "
                    "Maintain a registry of all approved integrations."
                ),
                cwe="CWE-284",
            ))

        cutoff_180 = (datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%d %H:%M:%S")

        for client in active_clients:
            name = client.get("name", client.get("client_id", "unknown"))
            scope = client.get("scope", "")
            token_life = client.get("access_token_lifespan", "")
            last_used = client.get("last_used_on", "")
            created = client.get("sys_created_on", "")

            # SN-OAUTH-001: Wildcard or admin scope
            if scope and re.search(r"\*|admin|security_admin|itil_admin", scope, re.IGNORECASE):
                self._add(Finding(
                    rule_id="SN-OAUTH-001",
                    name=f"OAuth client '{name}' has admin or wildcard scope",
                    category="OAuth: Excessive Scope",
                    severity="HIGH",
                    file_path="oauth_entity",
                    line_num=None,
                    line_content=f"client = {name}, scope = {scope!r}",
                    description=(
                        f"The OAuth client '{name}' has been granted an admin or wildcard "
                        "scope, giving it (and any token it issues) the same level of access "
                        "as an admin user. A compromised client secret or token leads to "
                        "full instance compromise."
                    ),
                    recommendation=(
                        "Reduce the scope to the minimum set of roles required. "
                        "If admin scope is truly needed, document and justify the exception "
                        "and rotate the client secret immediately."
                    ),
                    cwe="CWE-269",
                ))

            # SN-OAUTH-004: Token lifetime > 1 hour (3600 seconds)
            try:
                if token_life and int(token_life) > 3600:
                    self._add(Finding(
                        rule_id="SN-OAUTH-004",
                        name=f"OAuth client '{name}' access token lifetime exceeds 1 hour",
                        category="OAuth: Token Lifetime",
                        severity="MEDIUM",
                        file_path="oauth_entity",
                        line_num=None,
                        line_content=f"client = {name}, access_token_lifespan = {token_life}s",
                        description=(
                            f"The access token for OAuth client '{name}' is valid for "
                            f"{int(token_life)//3600}h {(int(token_life)%3600)//60}m. "
                            "Long-lived access tokens extend the window of opportunity "
                            "for a stolen token to be replayed by an attacker."
                        ),
                        recommendation=(
                            "Set access_token_lifespan to 3600 seconds (1 hour) or less. "
                            "Use refresh tokens with rotation for long-running integrations."
                        ),
                        cwe="CWE-613",
                    ))
            except (ValueError, TypeError):
                pass

            # SN-OAUTH-002: Active client never used (or unused for >180 days)
            if not last_used and created and created < cutoff_180:
                self._add(Finding(
                    rule_id="SN-OAUTH-002",
                    name=f"OAuth client '{name}' is active but has never been used",
                    category="OAuth: Stale Clients",
                    severity="MEDIUM",
                    file_path="oauth_entity",
                    line_num=None,
                    line_content=f"client = {name}, created = {created}, last_used_on = never",
                    description=(
                        f"OAuth client '{name}' was created on {created} and has never been "
                        "used. Unused clients represent unnecessary attack surface — their "
                        "credentials may have been committed to source code or shared "
                        "without tracking."
                    ),
                    recommendation=(
                        "Deactivate or delete OAuth clients that have never been used or "
                        "have not been used in over 90 days."
                    ),
                    cwe="CWE-284",
                ))

    # ----------------------------------------------------------
    # ACL Checks
    # ----------------------------------------------------------
    def _check_acls(self):
        self._vprint("  [check] Access Control Lists …")

        # SN-ACL-001: Public read ACL on sys_user
        public_user_read = self._api_get("sys_acl", {
            "sysparm_query": (
                "name=sys_user^operation=read^active=true"
                "^roleLENGTH0"  # role field is empty = no role required = public
            ),
            "sysparm_fields": "name,operation,type,role,condition",
        })
        if public_user_read:
            self._add(Finding(
                rule_id="SN-ACL-001",
                name="Public read ACL exists on sys_user table",
                category="Access Control",
                severity="CRITICAL",
                file_path="sys_acl",
                line_num=None,
                line_content="table = sys_user, operation = read, role = (none)",
                description=(
                    "An ACL with no role restriction on the sys_user table allows any "
                    "authenticated (or possibly unauthenticated) user to read all user "
                    "records, including email addresses, phone numbers, manager details, "
                    "and potentially hashed passwords."
                ),
                recommendation=(
                    "Add a role requirement (at minimum 'itil') to the sys_user read ACL. "
                    "Enable field-level ACLs to further restrict sensitive columns "
                    "(password, mobile_phone) to HR and admin roles only."
                ),
                cwe="CWE-284",
            ))

        # SN-ACL-002: Public write ACL on any sys_* core table
        public_core_write = self._api_get("sys_acl", {
            "sysparm_query": (
                "nameLIKEsys_^operation=write^active=true^roleLENGTH0"
            ),
            "sysparm_fields": "name,operation,type,role",
        })
        if public_core_write:
            tables = list({r.get("name", "?") for r in public_core_write})[:5]
            self._add(Finding(
                rule_id="SN-ACL-002",
                name=f"Public write ACL on core sys_ table(s): {', '.join(tables)}",
                category="Access Control",
                severity="CRITICAL",
                file_path="sys_acl",
                line_num=None,
                line_content=f"tables with public write: {', '.join(tables)}",
                description=(
                    "Write ACLs with no role restriction on platform tables allow any "
                    "user (or attacker with any valid session) to modify core configuration, "
                    "audit logs, system properties, or user records."
                ),
                recommendation=(
                    "Add role requirements to all write ACLs on sys_ tables. "
                    "Audit ACL configuration using the Security Centre module."
                ),
                cwe="CWE-284",
            ))

        # SN-ACL-003: No role restriction on syslog/sys_log read
        public_log_read = self._api_get("sys_acl", {
            "sysparm_query": (
                "nameLIKEsyslog^operation=read^active=true^roleLENGTH0"
            ),
            "sysparm_fields": "name,operation,role",
        })
        if public_log_read:
            self._add(Finding(
                rule_id="SN-ACL-003",
                name="Log table readable without role restriction",
                category="Access Control",
                severity="HIGH",
                file_path="sys_acl",
                line_num=None,
                line_content="table = syslog/sys_log, operation = read, role = (none)",
                description=(
                    "System and transaction logs often contain sensitive information: "
                    "user actions, integration credentials, error stack traces with internal "
                    "hostnames, and query details. Unrestricted read access enables "
                    "information disclosure."
                ),
                recommendation=(
                    "Restrict log table read access to 'admin' and 'security_admin' roles. "
                    "Forward logs to a SIEM and restrict direct table access."
                ),
                cwe="CWE-532",
            ))

    # ----------------------------------------------------------
    # Audit Logging Checks
    # ----------------------------------------------------------
    def _check_audit_logging(self):
        self._vprint("  [check] Audit logging and SIEM …")

        # SN-LOG-002: Syslog probe / SIEM integration configured
        syslog_probes = self._api_get("sys_syslog_config", {
            "sysparm_query": "active=true",
            "sysparm_fields": "name,active",
        })
        if not syslog_probes:
            # Try alternate ECC queue / MID Server probe table
            syslog_probes = self._api_get("ecc_queue", {
                "sysparm_query": "topic=Syslog^active=true",
                "sysparm_fields": "name,topic",
            })
        if not syslog_probes:
            self._add(Finding(
                rule_id="SN-LOG-002",
                name="No active syslog/SIEM probe configured",
                category="Audit Logging",
                severity="MEDIUM",
                file_path="sys_syslog_config",
                line_num=None,
                line_content="active syslog probes = 0",
                description=(
                    "Without a syslog or SIEM integration, security events from "
                    "ServiceNow (failed logins, ACL violations, admin changes) are not "
                    "forwarded to your central monitoring platform, leaving blind spots "
                    "in threat detection."
                ),
                recommendation=(
                    "Configure a syslog probe or MID Server to forward ServiceNow "
                    "events to your SIEM. At minimum, forward sys_log and "
                    "sysevent records."
                ),
                cwe="CWE-778",
            ))

        # SN-LOG-003: Audit retention — check log_rotate property
        log_retention = self._props_cache.get("glide.log.max_file_date", "")
        if log_retention:
            try:
                days = int(log_retention)
                if days < 30:
                    self._add(Finding(
                        rule_id="SN-LOG-003",
                        name=f"Log retention too short ({days} days)",
                        category="Audit Logging",
                        severity="LOW",
                        file_path="sys_properties",
                        line_num=None,
                        line_content=f"glide.log.max_file_date = {days}",
                        description=(
                            f"Log files are retained for only {days} day(s). Short retention "
                            "periods limit the ability to investigate incidents that are "
                            "discovered days or weeks after they occur."
                        ),
                        recommendation=(
                            "Set glide.log.max_file_date to at least 90 days. "
                            "For regulated industries (PCI DSS, HIPAA), retain for 365+ days. "
                            "Archive to an immutable storage destination."
                        ),
                        cwe="CWE-778",
                    ))
            except (ValueError, TypeError):
                pass

    # ----------------------------------------------------------
    # Email Security Checks
    # ----------------------------------------------------------
    def _check_email_security(self):
        self._vprint("  [check] Email security …")

        # SN-EMAIL-001: Email allow/deny list
        email_filter = self._props_cache.get("glide.email.filter.address.list", "")
        if not email_filter:
            self._add(Finding(
                rule_id="SN-EMAIL-001",
                name="No email allow/deny address list configured",
                category="Email Security",
                severity="LOW",
                file_path="sys_properties",
                line_num=None,
                line_content="glide.email.filter.address.list = <not set>",
                description=(
                    "Without an email filter list, ServiceNow may send automated "
                    "notifications to unintended recipients (e.g., in non-production "
                    "environments) or process emails from unauthorised senders, "
                    "increasing phishing and data leakage risk."
                ),
                recommendation=(
                    "Configure glide.email.filter.address.list to restrict outbound "
                    "email recipients in non-production environments, and "
                    "configure inbound filtering to accept emails only from trusted domains."
                ),
                cwe="CWE-200",
            ))

        # SN-EMAIL-002: Antivirus scanning on incoming email attachments
        av_enabled = self._props_cache.get("glide.email.antivirus.scan", "")
        if av_enabled.lower() not in ("true", "yes", "1"):
            self._add(Finding(
                rule_id="SN-EMAIL-002",
                name="Antivirus scanning on incoming email attachments disabled",
                category="Email Security",
                severity="MEDIUM",
                file_path="sys_properties",
                line_num=None,
                line_content=f"glide.email.antivirus.scan = {av_enabled!r}",
                description=(
                    "Without antivirus scanning, malicious file attachments received "
                    "via email (inbound actions) are stored in ServiceNow and may be "
                    "downloaded and executed by unsuspecting users."
                ),
                recommendation=(
                    "Enable glide.email.antivirus.scan and configure a scanning endpoint. "
                    "Consider integrating with an external AV API for up-to-date signatures."
                ),
                cwe="CWE-434",
            ))

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _vprint(self, msg: str):
        if self.verbose:
            print(msg)

    def _warn(self, msg: str):
        print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    def summary(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  ServiceNow SSPM Scanner v{VERSION}  --  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Instance  : {self.base_url}")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        for f in sorted_findings:
            sev_color = self.SEVERITY_COLOR.get(f.severity, "")
            print(f"{sev_color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Location : {f.file_path}")
            print(f"  Context  : {f.line_content}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        # Summary table
        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev, order in sorted(self.SEVERITY_ORDER.items(), key=lambda x: x[1]):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    def save_json(self, path: str):
        report = {
            "scanner": "servicenow_scanner",
            "version": VERSION,
            "generated": datetime.now().isoformat(),
            "instance": self.base_url,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    def save_html(self, path: str):
        esc = html_mod.escape
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_style = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
        }
        row_style = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        # Chip summary
        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        # Table rows
        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;font-size:0.8em;font-weight:bold">'
                f'{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.9em">'
                f'{esc(f.rule_id)}</td>'
                f'<td style="padding:10px 14px;color:#a9b1d6">{esc(f.category)}</td>'
                f'<td style="padding:10px 14px;font-weight:bold;color:#cdd6f4">{esc(f.name)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.85em;color:#89b4fa">'
                f'{esc(f.file_path)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.82em;color:#a6e3a1">'
                f'{esc(f.line_content or "")}</td>'
                f'<td style="padding:10px 14px;color:#cdd6f4">{esc(f.cwe)}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="7" style="padding:6px 14px 14px 14px">'
                f'<div style="color:#bac2de;font-size:0.88em;margin-bottom:4px">'
                f'<b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#89dceb;font-size:0.88em">'
                f'<b>Fix:</b> {esc(f.recommendation)}</div>'
                f'</td></tr>'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ServiceNow SSPM Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1b2e; color: #cdd6f4; min-height: 100vh; }}
  header {{ background: linear-gradient(135deg,#1e3a5f,#2d1b4e); padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #89b4fa; margin-bottom: 8px; }}
  header p {{ color: #a6adc8; font-size: 0.95em; margin: 2px 0; }}
  .chips {{ padding: 20px 36px; background: #181825; border-bottom: 1px solid #313244; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e; display: flex; gap: 12px; flex-wrap: wrap; border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{ background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 6px; padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #313244; color: #89b4fa; padding: 12px 14px; text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.12); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px; color: #a6e3a1; font-size: 1.2em; }}
</style>
</head>
<body>
<header>
  <h1>ServiceNow SSPM Scan Report</h1>
  <p>Scanner: ServiceNow SSPM Scanner v{esc(VERSION)}</p>
  <p>Instance: {esc(self.base_url)}</p>
  <p>Generated: {esc(now)}</p>
  <p>Total Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
  <label>Severity:</label>
  {chip_html}
</div>
<div class="filters">
  <select id="sevFilter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option value="CRITICAL">CRITICAL</option>
    <option value="HIGH">HIGH</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="LOW">LOW</option>
  </select>
  <select id="catFilter" onchange="applyFilters()">
    <option value="">All Categories</option>
    {''.join(f'<option value="{esc(c)}">{esc(c)}</option>' for c in sorted({{f.category for f in self.findings}})) }
  </select>
  <input type="text" id="textFilter" placeholder="Search name / ID …" oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
{f'<div class="no-findings">No findings — instance is clean!</div>' if not self.findings else f"""
<table id="findings-table">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Name</th>
  <th>Table</th><th>Context</th><th>CWE</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>"""}
</div>
<script>
function applyFilters() {{
  var sev = document.getElementById('sevFilter').value.toUpperCase();
  var cat = document.getElementById('catFilter').value.toLowerCase();
  var txt = document.getElementById('textFilter').value.toLowerCase();
  var rows = document.querySelectorAll('#findings-table tbody tr');
  rows.forEach(function(row) {{
    var rs = (row.getAttribute('data-severity') || '').toUpperCase();
    var rc = (row.getAttribute('data-category') || '').toLowerCase();
    var rt = row.textContent.toLowerCase();
    var show = (!sev || rs === sev) && (!cat || rc.includes(cat)) && (!txt || rt.includes(txt));
    row.style.display = show ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ============================================================
# CLI entry point
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        prog="servicenow_scanner",
        description=(
            f"ServiceNow SSPM Scanner v{VERSION} — "
            "SaaS Security Posture Management checks via REST API"
        ),
    )
    parser.add_argument(
        "--instance", "-i",
        default=os.environ.get("SNOW_INSTANCE", ""),
        metavar="INSTANCE",
        help=(
            "ServiceNow instance name (e.g. 'myco') or full URL "
            "(e.g. 'https://myco.service-now.com'). "
            "Env: SNOW_INSTANCE"
        ),
    )
    parser.add_argument(
        "--username", "-u",
        default=os.environ.get("SNOW_USERNAME", ""),
        metavar="USERNAME",
        help="ServiceNow username with read access. Env: SNOW_USERNAME",
    )
    parser.add_argument(
        "--password", "-p",
        default=os.environ.get("SNOW_PASSWORD", ""),
        metavar="PASSWORD",
        help="ServiceNow password. Env: SNOW_PASSWORD",
    )
    parser.add_argument(
        "--severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings as JSON to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as a self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (API calls, skipped tables, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"servicenow_scanner v{VERSION}",
    )

    args = parser.parse_args()

    # Requests check comes after parse_args so --version/--help work without requests installed
    if not HAS_REQUESTS:
        parser.error(
            "The 'requests' library is required.\n"
            "  Install with:  pip install requests"
        )

    # Validate required credentials
    missing = []
    if not args.instance:
        missing.append("--instance (or SNOW_INSTANCE env var)")
    if not args.username:
        missing.append("--username (or SNOW_USERNAME env var)")
    if not args.password:
        missing.append("--password (or SNOW_PASSWORD env var)")
    if missing:
        parser.error("Missing required arguments:\n  " + "\n  ".join(missing))

    scanner = ServiceNowScanner(
        instance_url=args.instance,
        username=args.username,
        password=args.password,
        verbose=args.verbose,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    # Exit code: 1 if any CRITICAL or HIGH findings remain
    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()
