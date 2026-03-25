"""
Painel Admin para VulnExusAI
Gerencie usuários, scans, planos e muito mais
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AdminUser:
    """Modelo de usuário admin"""
    
    def __init__(
        self,
        id: str,
        email: str,
        role: str = "admin",
        created_at: Optional[str] = None
    ):
        self.id = id
        self.email = email
        self.role = role  # super_admin, admin, moderator
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at
        }


class BannedUser:
    """Modelo de usuário banido"""
    
    def __init__(
        self,
        user_id: str,
        email: str,
        reason: str,
        banned_by: str,
        banned_at: Optional[str] = None,
        expires_at: Optional[str] = None
    ):
        self.user_id = user_id
        self.email = email
        self.reason = reason
        self.banned_by = banned_by
        self.banned_at = banned_at or datetime.now(timezone.utc).isoformat()
        self.expires_at = expires_at  # None = permanente
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "reason": self.reason,
            "banned_by": self.banned_by,
            "banned_at": self.banned_at,
            "expires_at": self.expires_at,
            "is_permanent": self.expires_at is None
        }


class AdminManager:
    """Gerenciador do painel admin"""
    
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        # Lista de admins (em produção, viria do banco)
        self._admins = os.getenv("ADMIN_EMAILS", "").split(",")
    
    async def _get_redis(self):
        import redis.asyncio as redis
        return redis.from_url(self.redis_url)
    
    def is_admin(self, email: str) -> bool:
        """Verifica se email é admin"""
        return email in self._admins or email.endswith("@vulnexusai.com")
    
    # ═══════════════════════════════════════════════════════════════
    # GERENCIAMENTO DE USUÁRIOS
    # ═══════════════════════════════════════════════════════════════
    
    async def list_users(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Lista todos os usuários"""
        try:
            from supabase import create_client
            supabase = create_client(
                os.getenv("SUPABASE_URL"),
                os.getenv("SUPABASE_KEY")
            )
            
            result = supabase.table("users").select("*").range(offset, offset + limit - 1).execute()
            return result.data
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return []
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Busca usuário pelo ID"""
        try:
            from supabase import create_client
            supabase = create_client(
                os.getenv("SUPABASE_URL"),
                os.getenv("SUPABASE_KEY")
            )
            
            result = supabase.table("users").select("*").eq("id", user_id).execute()
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
    
    async def update_user_plan(self, user_id: str, plan: str) -> bool:
        """Atualiza plano do usuário"""
        try:
            from supabase import create_client
            supabase = create_client(
                os.getenv("SUPABASE_URL"),
                os.getenv("SUPABASE_KEY")
            )
            
            # Busca organização do usuário
            user = await self.get_user(user_id)
            if not user or "organization_id" not in user:
                return False
            
            # Atualiza plano da organização
            result = supabase.table("organizations").update({
                "plan": plan,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", user["organization_id"]).execute()
            
            return True
        except Exception as e:
            logger.error(f"Error updating user plan: {e}")
            return False
    
    async def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Retorna estatísticas do usuário"""
        try:
            from supabase import create_client
            supabase = create_client(
                os.getenv("SUPABASE_URL"),
                os.getenv("SUPABASE_KEY")
            )
            
            user = await self.get_user(user_id)
            if not user:
                return {}
            
            org_id = user.get("organization_id")
            if not org_id:
                return {}
            
            # Conta scans
            scans_result = supabase.table("scans").select("id", count="exact").eq("organization_id", org_id).execute()
            scan_count = scans_result.count or 0
            
            # Conta vulnerabilidades
            findings_result = supabase.table("findings").select("id", count="exact").execute()
            
            return {
                "user_id": user_id,
                "email": user.get("email"),
                "organization_id": org_id,
                "role": user.get("role"),
                "total_scans": scan_count,
                "member_since": user.get("created_at")
            }
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {}
    
    # ═══════════════════════════════════════════════════════════════
    # BANIMENTO DE USUÁRIOS
    # ═══════════════════════════════════════════════════════════════
    
    async def ban_user(
        self,
        user_id: str,
        reason: str,
        banned_by: str,
        expires_days: Optional[int] = None
    ) -> bool:
        """Bane um usuário"""
        try:
            r = await self._get_redis()
            
            user = await self.get_user(user_id)
            if not user:
                return False
            
            # Calcula data de expiração
            expires_at = None
            if expires_days:
                from datetime import timedelta
                expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
            
            banned = BannedUser(
                user_id=user_id,
                email=user["email"],
                reason=reason,
                banned_by=banned_by,
                expires_at=expires_at
            )
            
            # Salva no Redis
            key = "banned_users"
            banned_list = await r.get(key)
            bans = json.loads(banned_list) if banned_list else []
            bans.append(banned.to_dict())
            
            await r.set(key, json.dumps(bans))
            
            logger.info(f"User {user_id} banned by {banned_by}")
            return True
        except Exception as e:
            logger.error(f"Error banning user: {e}")
            return False
    
    async def unban_user(self, user_id: str) -> bool:
        """Desbane um usuário"""
        try:
            r = await self._get_redis()
            
            key = "banned_users"
            banned_list = await r.get(key)
            if not banned_list:
                return False
            
            bans = json.loads(banned_list)
            bans = [b for b in bans if b["user_id"] != user_id]
            
            await r.set(key, json.dumps(bans))
            return True
        except Exception as e:
            logger.error(f"Error unbanning user: {e}")
            return False
    
    async def is_banned(self, user_id: str) -> bool:
        """Verifica se usuário está banido"""
        try:
            r = await self._get_redis()
            
            key = "banned_users"
            banned_list = await r.get(key)
            if not banned_list:
                return False
            
            bans = json.loads(banned_list)
            now = datetime.now(timezone.utc).isoformat()
            
            for ban in bans:
                if ban["user_id"] == user_id:
                    # Verifica se banimento expirou
                    if ban.get("expires_at") and ban["expires_at"] < now:
                        return False
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking ban: {e}")
            return False
    
    async def list_banned_users(self) -> List[Dict[str, Any]]:
        """Lista usuários banidos"""
        try:
            r = await self._get_redis()
            
            key = "banned_users"
            banned_list = await r.get(key)
            return json.loads(banned_list) if banned_list else []
        except Exception as e:
            logger.error(f"Error listing banned users: {e}")
            return []
    
    # ═══════════════════════════════════════════════════════════════
    # ESTATÍSTICAS GERAIS
    # ═══════════════════════════════════════════════════════════════
    
    async def get_overall_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas gerais do sistema"""
        try:
            from supabase import create_client
            supabase = create_client(
                os.getenv("SUPABASE_URL"),
                os.getenv("SUPABASE_KEY")
            )
            
            # Total de usuários
            users_result = supabase.table("users").select("id", count="exact").execute()
            total_users = users_result.count or 0
            
            # Total de scans
            scans_result = supabase.table("scans").select("id", count="exact").execute()
            total_scans = scans_result.count or 0
            
            # Total de organizações
            orgs_result = supabase.table("organizations").select("id", count="exact").execute()
            total_orgs = orgs_result.count or 0
            
            # Scans por plano
            free_scans = supabase.table("scans").select("id", count="exact").execute()
            
            return {
                "total_users": total_users,
                "total_scans": total_scans,
                "total_organizations": total_orgs,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting overall stats: {e}")
            return {}


# Instância global
admin_manager = AdminManager()
