"""
core/cvss.py — CVSS v3.1 Calculator Utility
Follows the FIRST.org specification for Base Score Calculation.
"""
from __future__ import annotations
from typing import Dict, Any

class CVSSCalculator:
    """
    CVSS v3.1 Base Score Calculator.
    """
    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC = {"L": 0.77, "H": 0.44}
    _UI = {"N": 0.85, "R": 0.62}
    _CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
    _PR = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }

    @classmethod
    def calculate(cls, av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H") -> Dict[str, Any]:
        """
        Calculates CVSS v3.1 Base Score.
        Returns: {score: float, severity: str, vector: str}
        """
        av_w = cls._AV.get(av, 0.85)
        ac_w = cls._AC.get(ac, 0.77)
        pr_w = cls._PR.get(s, cls._PR["U"]).get(pr, 0.85)
        ui_w = cls._UI.get(ui, 0.85)
        c_w = cls._CIA.get(c, 0.56)
        i_w = cls._CIA.get(i, 0.56)
        a_w = cls._CIA.get(a, 0.56)

        iss = 1 - (1 - c_w) * (1 - i_w) * (1 - a_w)
        
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploit = 8.22 * av_w * ac_w * pr_w * ui_w

        if impact <= 0:
            base = 0.0
        elif s == "U":
            base = min(impact + exploit, 10.0)
        else:
            base = min(1.08 * (impact + exploit), 10.0)

        base = float("%.1f" % base)

        if base == 0: sev = "NONE"
        elif base < 4.0: sev = "LOW"
        elif base < 7.0: sev = "MEDIUM"
        elif base < 9.0: sev = "HIGH"
        else: sev = "CRITICAL"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        return {"score": base, "severity": sev, "vector": vector}
