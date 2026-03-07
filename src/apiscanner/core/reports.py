"""
core/reports.py — Professional Report Generator (HTML/PDF)
"""
import os
import datetime
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader
from core.models import ScanResult, Finding
from core.logger import logger

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logger.warning("WeasyPrint not installed. PDF generation disabled.")

class ReportGenerator:
    def __init__(self, template_dir: str):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_html(self, result: ScanResult) -> str:
        """Gera string HTML do relatório usando Jinja2."""
        template = self.env.get_template("report_template.html")
        
        # Prepara dados para o template
        findings_list = [f.to_dict() if hasattr(f, "to_dict") else f for f in result.findings]
        
        render_data = {
            "target": result.target,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings_list,
            "total_requests": result.total_requests,
            "duration": result.duration_seconds,
            "technologies": result.technologies,
            "waf": result.waf_detected
        }
        
        return template.render(**render_data)

    def save_pdf(self, html_content: str, output_path: str) -> bool:
        """Converte HTML em PDF usando WeasyPrint."""
        if not WEASYPRINT_AVAILABLE:
            return False
        try:
            HTML(string=html_content).write_pdf(output_path)
            return True
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            return False

    def export(self, result: ScanResult, base_filename: str):
        """Exporta tanto HTML quanto PDF (se disponível)."""
        html_content = self.generate_html(result)
        
        html_path = f"{base_filename}.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {html_path}")

        if WEASYPRINT_AVAILABLE:
            pdf_path = f"{base_filename}.pdf"
            if self.save_pdf(html_content, pdf_path):
                logger.info(f"PDF report saved to {pdf_path}")
                return pdf_path
        
        return html_path
