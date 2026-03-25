"""
Notificações Slack/Teams para VulnExusAI
Envia alertas quando scans terminam ou vulnerabilidades são encontradas
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List
from enum import Enum

logger = logging.getLogger(__name__)


class NotificationChannel(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"


class NotificationService:
    """Serviço de notificações para Slack e Microsoft Teams"""
    
    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.teams_webhook = os.getenv("TEAMS_WEBHOOK_URL")
        self.enabled = bool(self.slack_webhook or self.teams_webhook)
    
    async def notify_scan_completed(
        self,
        target: str,
        status: str,
        findings_count: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        report_url: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Envia notificação quando um scan é concluído.
        
        Returns:
            Dict com status de envio para cada canal
        """
        if not self.enabled:
            logger.info("Notifications disabled - no webhook configured")
            return {"slack": False, "teams": False}
        
        # Prepara mensagem
        if status == "completed":
            emoji = "✅" if findings_count == 0 else "⚠️"
            title = f"{emoji} Scan Concluído - {target}"
        else:
            title = f"❌ Scan Falhou - {target}"
        
        blocks = self._build_slack_blocks(
            title=title,
            target=target,
            status=status,
            findings_count=findings_count,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            report_url=report_url
        )
        
        results = {}
        
        # Envia para Slack
        if self.slack_webhook:
            results["slack"] = await self._send_slack(blocks)
        
        # Envia para Teams
        if self.teams_webhook:
            results["teams"] = await self._send_teams(blocks)
        
        return results
    
    def _build_slack_blocks(
        self,
        title: str,
        target: str,
        status: str,
        findings_count: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        report_url: Optional[str]
    ) -> Dict[str, Any]:
        """Constrói mensagem formatada para Slack"""
        
        # Calcula severity
        if critical > 0:
            severity_emoji = "🔴"
            severity_text = "CRÍTICO"
        elif high > 0:
            severity_emoji = "🟠"
            severity_text = "ALTO"
        elif medium > 0:
            severity_emoji = "🟡"
            severity_text = "MÉDIO"
        else:
            severity_emoji = "🟢"
            severity_text = "SEGURO"
        
        blocks = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title,
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Target:*\n{target}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Status:*\n{status.title()}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Resumo das Vulnerabilidades*\n"
                            f"🔴 Critical: {critical} | "
                            f"🟠 High: {high} | "
                            f"🟡 Medium: {medium} | "
                            f"🔵 Low: {low}\n"
                            f"*Total: {findings_count} findings*"
                        )
                    }
                }
            ]
        }
        
        # Adiciona botão do relatório se disponível
        if report_url:
            blocks["blocks"].append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📄 Ver Relatório"
                        },
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })
        
        return blocks
    
    async def _send_slack(self, blocks: Dict[str, Any]) -> bool:
        """Envia notificação para Slack"""
        if not self.slack_webhook:
            return False
        
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.slack_webhook,
                    json=blocks,
                    timeout=10
                )
                if response.status_code == 200:
                    logger.info("Slack notification sent successfully")
                    return True
                else:
                    logger.error(f"Slack notification failed: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    async def _send_teams(self, blocks: Dict[str, Any]) -> bool:
        """Envia notificação para Microsoft Teams"""
        if not self.teams_webhook:
            return False
        
        # Converte formato Slack para Teams
        teams_message = self._convert_to_teams(blocks)
        
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.teams_webhook,
                    json=teams_message,
                    timeout=10
                )
                if response.status_code == 200:
                    logger.info("Teams notification sent successfully")
                    return True
                else:
                    logger.error(f"Teams notification failed: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Error sending Teams notification: {e}")
            return False
    
    def _convert_to_teams(self, slack_blocks: Dict[str, Any]) -> Dict[str, Any]:
        """Converte mensagem do Slack para formato Teams"""
        # Extrai informações do bloco Slack
        title = "VulnExusAI Scan"
        facts = []
        
        for block in slack_blocks.get("blocks", []):
            if block.get("type") == "section":
                fields = block.get("fields", [])
                for field in fields:
                    if "Target:" in field.get("text", ""):
                        facts.append({"name": "Target", "value": field["text"].replace("*Target:*\n", "")})
                    elif "Status:" in field.get("text", ""):
                        facts.append({"name": "Status", "value": field["text"].replace("*Status:*\n", "")})
                if "text" in block and "Resumo" in block["text"].get("text", ""):
                    facts.append({"name": "Findings", "value": block["text"]["text"].replace("*Resumo das Vulnerabilidades*\n", "")})
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "facts": facts,
                "markdown": True
            }]
        }


# Instância global
notifications = NotificationService()
