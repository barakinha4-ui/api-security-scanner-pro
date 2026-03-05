"""
core/models.py — Core data models for API Security Scanner v2
Includes CVSS 3.1 calculator, Finding, ScanResult, and all enums.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, cast


# ─── Severity Enum ────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def weight(self) -> int:
        val = str(self.value)
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(val, 1)

    @property
    def emoji(self) -> str:
        val = str(self.value)
        return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(val, "⚪")

    @property
    def color_hex(self) -> str:
        val = str(self.value)
        return {
            "CRITICAL": "#dc2626",
            "HIGH":     "#ea580c",
            "MEDIUM":   "#d97706",
            "LOW":      "#2563eb",
            "INFO":     "#6b7280",
        }.get(val, "#6b7280")


# ─── CVSS 3.1 Calculator ──────────────────────────────────────────────────────

class CVSS:
    """
    CVSS v3.1 Base Score Calculator.
    """

    _AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC  = {"L": 0.77, "H": 0.44}
    _UI  = {"N": 0.85, "R": 0.62}
    _CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
    _PR  = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }

    @classmethod
    def score(cls,
              AV="N", AC="L", PR="N", UI="N",
              S="U", C="H", I="H", A="H") -> Dict[str, Any]:
        """Returns {'score': float, 'severity': str, 'vector': str}"""
        try:
            av_w = cls._AV.get(AV, 0.85)
            ac_w = cls._AC.get(AC, 0.77)
            pr_w = cls._PR.get(S, cls._PR["U"]).get(PR, 0.85)
            ui_w = cls._UI.get(UI, 0.85)
            c_w  = cls._CIA.get(C, 0.56)
            i_w  = cls._CIA.get(I, 0.56)
            a_w  = cls._CIA.get(A, 0.56)

            iss = 1 - (1 - c_w) * (1 - i_w) * (1 - a_w)

            if S == "U":
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

            exploit = 8.22 * av_w * ac_w * pr_w * ui_w

            if impact <= 0:
                base = 0.0
            elif S == "U":
                base = min(impact + exploit, 10.0)
            else:
                base = min(1.08 * (impact + exploit), 10.0)

            base = float("%.1f" % base)

            if   base == 0:  sev = "NONE"
            elif base < 4:   sev = "LOW"
            elif base < 7:   sev = "MEDIUM"
            elif base < 9:   sev = "HIGH"
            else:             sev = "CRITICAL"

            return {
                "score":    base,
                "severity": sev,
                "vector":   f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}",
            }
        except Exception:
            return {"score": 0.0, "severity": "NONE",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}


# Pre-computed CVSS profiles keyed by vulnerability class
CVSS_PROFILES: Dict[str, Dict] = {
    "SQLI":               CVSS.score("N","L","N","N","C","H","H","H"),   # 10.0
    "SQLI_AUTH":          CVSS.score("N","L","L","N","C","H","H","H"),   # 9.9
    "NOSQLI":             CVSS.score("N","L","N","N","C","H","H","N"),   # 9.4
    "XSS_REFLECTED":      CVSS.score("N","L","N","R","C","L","L","N"),   # 6.1
    "XSS_STORED":         CVSS.score("N","L","L","R","C","L","L","N"),   # 5.4
    "SSTI":               CVSS.score("N","L","N","N","C","H","H","H"),   # 10.0
    "SSRF":               CVSS.score("N","L","N","N","C","H","L","N"),   # 8.6
    "SSRF_CRITICAL":      CVSS.score("N","L","N","N","C","H","H","H"),   # 10.0
    "IDOR":               CVSS.score("N","L","L","N","U","H","H","N"),   # 8.1
    "BFLA":               CVSS.score("N","L","L","N","U","H","H","N"),   # 8.1
    "BROKEN_AUTH":        CVSS.score("N","L","N","N","C","H","H","H"),   # 10.0
    "DEFAULT_CREDS":      CVSS.score("N","L","N","N","C","H","H","H"),   # 10.0
    "JWT_NONE":           CVSS.score("N","L","N","N","C","H","H","N"),   # 9.4
    "JWT_WEAK_SECRET":    CVSS.score("N","H","N","N","U","H","H","N"),   # 7.5
    "JWT_NO_EXP":         CVSS.score("N","L","L","N","U","L","L","N"),   # 5.4
    "GQL_INTROSPECTION":  CVSS.score("N","L","N","N","U","L","N","N"),   # 5.3
    "GQL_DOS":            CVSS.score("N","L","N","N","U","N","N","H"),   # 7.5
    "GQL_INJECTION":      CVSS.score("N","L","N","N","C","H","H","H"),   # 10.0
    "CORS_WILDCARD":      CVSS.score("N","L","N","R","C","H","L","N"),   # 7.6
    "CORS_REFLECT":       CVSS.score("N","L","N","R","C","H","L","N"),   # 7.6
    "MISSING_HEADER":     CVSS.score("N","L","N","R","U","L","L","N"),   # 5.4
    "RATE_LIMIT":         CVSS.score("N","L","N","N","U","N","N","H"),   # 7.5
    "SENSITIVE_DATA":     CVSS.score("N","L","N","N","U","H","N","N"),   # 7.5
    "MASS_ASSIGNMENT":    CVSS.score("N","L","L","N","U","L","H","N"),   # 6.3
    "SSL_HTTP":           CVSS.score("N","H","N","N","U","H","L","N"),   # 6.5
    "DEBUG_ENDPOINT":     CVSS.score("N","L","N","N","U","L","N","N"),   # 5.3
    "DEBUG_ENV_VARS":     CVSS.score("N","L","N","N","C","H","N","N"),   # 8.6
    "WAF_BYPASS":         CVSS.score("N","H","N","N","U","L","L","N"),   # 4.8
    "INFO_DISCLOSURE":    CVSS.score("N","L","N","N","U","L","N","N"),   # 5.3
    "OPEN_API_SPEC":      CVSS.score("N","H","N","N","U","L","N","N"),   # 3.7
    "RATELIMIT_BYPASS":   CVSS.score("N","L","N","N","U","N","N","H"),   # 7.5
}


# ─── Finding ──────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Single vulnerability finding produced by a scan module."""

    # Identity
    id:              str  = field(default_factory=lambda: str(uuid.uuid4()).split('-')[0].upper())
    vuln_type:       str  = ""
    title:           str  = ""

    # Location
    endpoint:        str  = ""
    method:          str  = "GET"
    parameter:       str  = ""

    # Evidence
    payload:         str  = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_status: int  = 0
    response_body:   str  = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0

    # Classification
    severity:        str  = Severity.INFO.value
    cvss_score:      float = 0.0
    cvss_vector:     str  = ""
    owasp_category:  str  = ""

    # Details
    description:     str  = ""
    recommendation:  str  = ""
    references:      List[str] = field(default_factory=list)

    # Meta
    confirmed:       bool = False
    confidence_score: float = 0.0
    confirmation_evidence: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)
    false_positive:  bool = False
    module:          str  = ""
    tags:            List[str] = field(default_factory=list)
    timestamp:       str  = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        # Cast to Any to satisfy linter regarding DataclassInstance
        d = dict(asdict(cast(Any, self)))
        d["status_label"] = str(self.status_label)
        return d

    def truncate_response(self, n: int = 500) -> str:
        body_val = str(self.response_body)
        if len(body_val) > int(n):
            # Try plain slicing again, but cast both as Any to bypass weird linter rule
            return str(cast(Any, body_val)[0:int(n)]) + " …[truncated]"
        return body_val

    @property
    def severity_obj(self) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
            "INFO":     Severity.INFO
        }
        val = str(self.severity).upper()
        return mapping.get(val, Severity.INFO)

    @property
    def risk_priority(self) -> int:
        """Lower = more severe (for sorting)."""
        mapping: Dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sev = str(self.severity)
        return mapping.get(sev, 5)

    @property
    def status_label(self) -> str:
        score = float(self.confidence_score)
        if score >= 0.9:
            return "✅ Confirmed"
        if score >= 0.7:
            return "⚠️ Probable"
        return "❓ Unconfirmed"

    def calculate_confidence(self, evidence: Dict[str, bool]) -> float:
        """
        Calculates score based on signals: status_match, pattern_match, time_based, boolean_based, oast_callback.
        """
        score = 0.0
        weights: Dict[str, float] = {
            "status_match": 0.2,
            "pattern_match": 0.3,
            "time_based": 0.25,
            "boolean_based": 0.25,
            "oast_callback": 0.5
        }
        for signal, weight in weights.items():
            if evidence.get(signal, False):
                # Use cast to force float addition
                s: float = cast(float, score)
                w: float = cast(float, weight)
                score = s + w
        
        final_score: float = min(1.0, float(score))
        self.confidence_score = final_score
        return final_score


# ─── ScanResult ───────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Aggregated results of a complete scan session."""

    target:               str  = ""
    scan_type:            str  = "full"
    start_time:           str  = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    end_time:             str  = ""
    duration_seconds:     float = 0.0

    findings:             List[Finding]  = field(default_factory=list)
    discovered_endpoints: List[str]      = field(default_factory=list)
    scanned_urls:         List[str]      = field(default_factory=list)

    waf_detected:         Optional[str]  = None
    waf_confidence:       float          = 0.0
    technologies:         List[str]      = field(default_factory=list)
    server_info:          Dict[str, str] = field(default_factory=dict)

    total_requests:       int   = 0
    errors:               int   = 0

    # Scanner metadata
    scanner_version:      str   = "2.0"
    threads_used:         int   = 0
    stealth_mode:         bool  = False

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def by_severity(self) -> Dict[str, List[Finding]]:
        d: Dict[str, List[Finding]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []
        }
        for f in self.findings:
            sev = str(f.severity)
            if sev in d:
                d[sev].append(f)
            else:
                d["INFO"].append(f)
        return d

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.risk_priority)

    def findings_count_by_status(self) -> Dict[str, int]:
        counts = {"Confirmed": 0, "Probable": 0, "Unconfirmed": 0}
        for f in self.findings:
            label = f.status_label.split(" ")[-1] # Handles "✅ Confirmed" -> "Confirmed"
            if label in counts:
                counts[label] += 1
        return counts

    @property
    def summary(self) -> Dict[str, Any]:
        counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in self.findings:
            sev = str(f.severity)
            if sev in counts:
                counts[sev] += 1

        top_cvss = max((f.cvss_score for f in self.findings), default=0.0)

        deduct = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
        total_deduction = 0
        for s, n in counts.items():
            total_deduction += deduct.get(s, 0) * n
        
        score = max(0, 100 - total_deduction)
        rating = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

        by_owasp = {}
        for f in self.findings:
            cat = f.owasp_category
            if cat:
                by_owasp[cat] = by_owasp.get(cat, 0) + 1

        return {
            "total":              len(self.findings),
            "by_severity":        counts,
            "by_owasp":           by_owasp,
            "security_score":     score,
            "security_rating":    rating,
            "highest_cvss":       float("%.1f" % top_cvss),
            "confirmed_count":    sum(1 for f in self.findings if f.confirmed),
            "waf_detected":       self.waf_detected,
            "technologies":       self.technologies,
            "total_requests":     self.total_requests,
            "endpoints_found":    len(self.discovered_endpoints),
            "duration":           float("%.1f" % self.duration_seconds),
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary
        return d
