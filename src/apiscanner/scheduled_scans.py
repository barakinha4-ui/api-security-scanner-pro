"""
Scheduled Scans para VulnExusAI
Permite agendar scans automáticos em intervalos definidos
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class ScheduleFrequency(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ScheduledScan:
    """Modelo de scan agendado"""
    
    def __init__(
        self,
        id: str,
        target: str,
        scan_type: str,
        frequency: str,
        organization_id: str,
        user_id: str,
        enabled: bool = True,
        last_run: Optional[str] = None,
        next_run: Optional[str] = None,
        created_at: Optional[str] = None
    ):
        self.id = id
        self.target = target
        self.scan_type = scan_type
        self.frequency = frequency
        self.organization_id = organization_id
        self.user_id = user_id
        self.enabled = enabled
        self.last_run = last_run
        self.next_run = next_run
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "scan_type": self.scan_type,
            "frequency": self.frequency,
            "organization_id": self.organization_id,
            "user_id": self.user_id,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "created_at": self.created_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledScan":
        return cls(**data)
    
    def calculate_next_run(self) -> str:
        """Calcula a próxima execução baseado na frequência"""
        from datetime import timedelta
        
        now = datetime.now(timezone.utc)
        
        if self.frequency == "daily":
            next_dt = now + timedelta(days=1)
        elif self.frequency == "weekly":
            next_dt = now + timedelta(weeks=1)
        elif self.frequency == "monthly":
            next_dt = now + timedelta(days=30)
        else:
            next_dt = now + timedelta(days=1)
        
        return next_dt.isoformat()


class ScheduledScanManager:
    """Gerenciador de scans agendados"""
    
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    async def _get_redis(self):
        import redis.asyncio as redis
        return redis.from_url(self.redis_url)
    
    def _key(self, org_id: str) -> str:
        return f"scheduled_scans:{org_id}"
    
    async def create(
        self,
        target: str,
        scan_type: str,
        frequency: str,
        organization_id: str,
        user_id: str
    ) -> ScheduledScan:
        """Cria um novo scan agendado"""
        import uuid
        
        scan = ScheduledScan(
            id=str(uuid.uuid4()),
            target=target,
            scan_type=scan_type,
            frequency=frequency,
            organization_id=organization_id,
            user_id=user_id,
            enabled=True,
            next_run=scan.calculate_next_run()
        )
        
        # Salva no Redis
        r = await self._get_redis()
        key = self._key(organization_id)
        
        # Lista existente
        existing = await r.get(key)
        scans = json.loads(existing) if existing else []
        scans.append(scan.to_dict())
        
        await r.set(key, json.dumps(scans))
        
        logger.info(f"Created scheduled scan {scan.id} for {target}")
        return scan
    
    async def list(self, organization_id: str) -> List[ScheduledScan]:
        """Lista todos os scans agendados de uma organização"""
        r = await self._get_redis()
        key = self._key(organization_id)
        
        data = await r.get(key)
        if not data:
            return []
        
        scans_data = json.loads(data)
        return [ScheduledScan.from_dict(s) for s in scans_data]
    
    async def get(self, scan_id: str, organization_id: str) -> Optional[ScheduledScan]:
        """Busca um scan agendado pelo ID"""
        scans = await self.list(organization_id)
        for scan in scans:
            if scan.id == scan_id:
                return scan
        return None
    
    async def update(self, scan_id: str, organization_id: str, **kwargs) -> Optional[ScheduledScan]:
        """Atualiza um scan agendado"""
        r = await self._get_redis()
        key = self._key(organization_id)
        
        data = await r.get(key)
        if not data:
            return None
        
        scans_data = json.loads(data)
        updated = None
        
        for i, scan_dict in enumerate(scans_data):
            if scan_dict["id"] == scan_id:
                scan_dict.update(kwargs)
                if "enabled" in kwargs and kwargs["enabled"]:
                    # Recalcula próxima execução
                    scan = ScheduledScan.from_dict(scan_dict)
                    scan_dict["next_run"] = scan.calculate_next_run()
                scans_data[i] = scan_dict
                updated = ScheduledScan.from_dict(scan_dict)
                break
        
        if updated:
            await r.set(key, json.dumps(scans_data))
        
        return updated
    
    async def delete(self, scan_id: str, organization_id: str) -> bool:
        """Remove um scan agendado"""
        r = await self._get_redis()
        key = self._key(organization_id)
        
        data = await r.get(key)
        if not data:
            return False
        
        scans_data = json.loads(data)
        initial_len = len(scans_data)
        scans_data = [s for s in scans_data if s["id"] != scan_id]
        
        if len(scans_data) < initial_len:
            await r.set(key, json.dumps(scans_data))
            return True
        
        return False
    
    async def get_due_scans(self) -> List[ScheduledScan]:
        """Retorna scans que precisam ser executados"""
        from redis.asyncio import redis
        
        r = await self._get_redis()
        
        # Busca todas as chaves de scans
        keys = []
        async for key in r.scan_iter("scheduled_scans:*"):
            keys.append(key)
        
        due_scans = []
        now = datetime.now(timezone.utc)
        
        for key in keys:
            data = await r.get(key)
            if not data:
                continue
            
            scans_data = json.loads(data)
            for scan_dict in scans_data:
                if not scan_dict.get("enabled", True):
                    continue
                
                next_run = scan_dict.get("next_run")
                if not next_run:
                    continue
                
                # Verifica se está pronto para executar
                next_dt = datetime.fromisoformat(next_run.replace('Z', '+00:00'))
                if now >= next_dt:
                    due_scans.append(ScheduledScan.from_dict(scan_dict))
        
        return due_scans


# Instância global
scheduled_scan_manager = ScheduledScanManager()
