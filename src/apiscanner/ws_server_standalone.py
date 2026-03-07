# cli_server.py - WebSocket Server Standalone para API Security Scanner Pro
# Porta: 8765 | Auth: JWT via Supabase | Protocolo: JSON over WebSocket

import os
import json
import uuid
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set

import websockets
from websockets.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed
from jose import jwt, JWTError
from pydantic import BaseModel, ValidationError
from dotenv import load_dotenv

# ================= Configuration =================
load_dotenv()

WS_HOST = os.getenv("WS_HOST", "0.0.0.0")
WS_PORT = int(os.getenv("WS_PORT", 8765))
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "supabase-secret")
API_KEY_SECRET = os.getenv("API_KEY_SECRET", "super-secret-local-key")

HEARTBEAT_INTERVAL = 30  # segundos
INACTIVITY_TIMEOUT = 300  # 5 minutos
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB

# ================= Structured Logging =================
class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

logger = logging.getLogger("ws_server")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# ================= Models =================
class JWTPayload(BaseModel):
    """Schema para validar JWT do Supabase."""
    sub: str
    exp: int
    role: Optional[str] = "authenticated"
    
    def is_valid(self) -> bool:
        return datetime.now(timezone.utc).timestamp() < self.exp

class AuthMessage(BaseModel):
    """Primeira mensagem esperada no handshake WebSocket."""
    token: str

class ProgressMessage(BaseModel):
    """Mensagem de progresso da varredura para broadcast."""
    job_id: str
    host: str
    port: Optional[int] = None
    status: str  # "scanning", "open", "closed", "filtered", "critical", "high"
    severity: Optional[str] = None  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    message: Optional[str] = None
    timestamp: str

# ================= Connection Manager =================
class ConnectionManager:
    """Gerencia conexões WebSocket autenticadas com heartbeat e cleanup."""
    
    def __init__(self):
        self.connections: Dict[str, Dict[str, WebSocketServerProtocol]] = {}  # job_id -> {user_id -> ws}
        self.last_seen: Dict[str, Dict[str, float]] = {}  # job_id -> {user_id -> timestamp}
        self._lock = asyncio.Lock()
    
    async def add_connection(self, job_id: str, user_id: str, websocket: WebSocketServerProtocol):
        async with self._lock:
            if job_id not in self.connections:
                self.connections[job_id] = {}
                self.last_seen[job_id] = {}
            self.connections[job_id][user_id] = websocket
            self.last_seen[job_id][user_id] = datetime.now(timezone.utc).timestamp()
            logger.info(f"Connection added: job={job_id}, user={user_id}")
    
    async def remove_connection(self, job_id: str, user_id: str):
        async with self._lock:
            if job_id in self.connections and user_id in self.connections[job_id]:
                del self.connections[job_id][user_id]
                del self.last_seen[job_id][user_id]
                logger.info(f"Connection removed: job={job_id}, user={user_id}")
                # Limpa estruturas vazias
                if not self.connections[job_id]:
                    del self.connections[job_id]
                    del self.last_seen[job_id]
    
    async def update_last_seen(self, job_id: str, user_id: str):
        async with self._lock:
            if job_id in self.last_seen and user_id in self.last_seen[job_id]:
                self.last_seen[job_id][user_id] = datetime.now(timezone.utc).timestamp()
    
    async def broadcast(self, job_id: str, message: ProgressMessage):
        """Envia mensagem para todos os clientes autenticados de um job."""
        async with self._lock:
            if job_id not in self.connections:
                return
            msg_json = message.model_dump_json()
            disconnected = []
            
            for user_id, websocket in self.connections[job_id].items():
                try:
                    await websocket.send(msg_json)
                    logger.debug(f"Broadcasted to job={job_id}, user={user_id}")
                except ConnectionClosed:
                    disconnected.append((job_id, user_id))
                except Exception as e:
                    logger.error(f"Broadcast error for job={job_id}, user={user_id}: {e}")
                    disconnected.append((job_id, user_id))
            
            # Limpa conexões mortas
            for jid, uid in disconnected:
                await self.remove_connection(jid, uid)
    
    async def cleanup_inactive(self):
        """Remove conexões inativas por mais de INACTIVITY_TIMEOUT."""
        now = datetime.now(timezone.utc).timestamp()
        to_remove = []
        
        async with self._lock:
            for job_id, users in list(self.last_seen.items()):
                for user_id, last_ts in list(users.items()):
                    if now - last_ts > INACTIVITY_TIMEOUT:
                        to_remove.append((job_id, user_id))
        
        for job_id, user_id in to_remove:
            logger.warning(f"Removing inactive connection: job={job_id}, user={user_id}")
            await self.remove_connection(job_id, user_id)
            # Tenta fechar o socket se ainda existir
            if job_id in self.connections and user_id in self.connections[job_id]:
                try:
                    await self.connections[job_id][user_id].close(code=1000, reason="Inactive")
                except:
                    pass

# Instância global
manager = ConnectionManager()

# ================= Auth & Validation =================
def validate_token(token: str) -> Optional[str]:
    """
    Valida token JWT ou API Key.
    Retorna user_id se válido, None se inválido.
    """
    # Check API Key first
    if token == API_KEY_SECRET:
        return "api_key_user"
    
    try:
        payload_dict = jwt.decode(
            token, 
            SUPABASE_JWT_SECRET, 
            algorithms=["HS256"], 
            options={"verify_aud": False}
        )
        payload = JWTPayload(**payload_dict)
        if not payload.is_valid():
            logger.warning("JWT expired")
            return None
        return payload.sub
    except (JWTError, ValidationError, KeyError) as e:
        logger.warning(f"Token validation failed: {e}")
        return None

# ================= DEBUG: Token Inspector =================
def debug_token(token: str) -> dict:
    """
    Retorna detalhes do token para debugging (NÃO USE EM PRODUÇÃO).
    """
    result = {"valid": False, "reason": None, "payload": None}
    
    # Check API Key
    if token == API_KEY_SECRET:
        result["valid"] = True
        result["reason"] = "api_key_match"
        return result
    
    # Try JWT decode WITHOUT verification first (for debugging only)
    try:
        # Decode sem verificar assinatura para ver o payload
        unverified = jwt.get_unverified_claims(token)
        result["payload"] = unverified
        
        # Agora tenta validar de verdade
        payload_dict = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        payload = JWTPayload(**payload_dict)
        
        if not payload.is_valid():
            result["reason"] = "expired"
            result["exp"] = payload.exp
            result["now"] = datetime.now(timezone.utc).timestamp()
            return result
            
        result["valid"] = True
        result["reason"] = "jwt_valid"
        result["user_id"] = payload.sub
        
    except JWTError as e:
        result["reason"] = f"jwt_error: {str(e)}"
    except ValidationError as e:
        result["reason"] = f"pydantic_error: {str(e)}"
        result["payload"] = None
    except Exception as e:
        result["reason"] = f"unexpected: {str(e)}"
    
    return result

# ================= Heartbeat & Monitoring Tasks =================
async def heartbeat_sender(websocket: WebSocketServerProtocol, job_id: str, user_id: str):
    """Envia heartbeats a cada HEARTBEAT_INTERVAL segundos."""
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            heartbeat = json.dumps({
                "type": "heartbeat",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            await websocket.send(heartbeat)
            logger.debug(f"Heartbeat sent: job={job_id}, user={user_id}")
    except ConnectionClosed:
        logger.info(f"Heartbeat stopped (connection closed): job={job_id}, user={user_id}")
    except Exception as e:
        logger.error(f"Heartbeat error: job={job_id}, user={user_id}, error={e}")

async def inactivity_monitor():
    """Task global que roda a cada 60s limpando conexões inativas."""
    while True:
        await asyncio.sleep(60)
        await manager.cleanup_inactive()

# ================= WebSocket Handler =================
async def websocket_handler(websocket: WebSocketServerProtocol, path: Optional[str] = None):
    """
    Handler principal para conexões WebSocket.
    - Exige autenticação na primeira mensagem
    - Fecha com code 1008 se token inválido
    - Mantém heartbeat e monitora inatividade
    """
    # Se o path for algo como /job-123, pegamos o ID
    job_id = path.strip("/") if path else "global"
    user_id = None
    
    try:
        # 1. Aguarda mensagem de autenticação (timeout 10s)
        try:
            raw_msg = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            auth_data = json.loads(raw_msg)
            auth_msg = AuthMessage(**auth_data)
        except asyncio.TimeoutError:
            logger.warning("Auth timeout - no token received")
            await websocket.close(code=1008, reason="Auth timeout")
            return
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in auth message")
            await websocket.close(code=1008, reason="Invalid JSON")
            return
        except ValidationError as e:
            logger.warning(f"Auth message validation failed: {e}")
            await websocket.close(code=1008, reason="Invalid auth payload")
            return
        
        # 2. Valida token
        debug_info = debug_token(auth_msg.token)
        if not debug_info["valid"]:
            logger.warning(f"Auth failed for job={job_id}. Reason: {debug_info['reason']}")
            if debug_info.get("payload"):
                logger.info(f"Debug Token Payload: {debug_info['payload']}")
            await websocket.close(code=1008, reason=f"Invalid token: {debug_info['reason']}")
            return
        
        user_id = debug_info.get("user_id") or "api_key_user"
        
        # 3. Registra conexão
        await manager.add_connection(job_id, user_id, websocket)
        logger.info(f"WebSocket authenticated: job={job_id}, user={user_id}")
        
        # 4. Inicia tasks auxiliares
        heartbeat_task = asyncio.create_task(heartbeat_sender(websocket, job_id, user_id))
        
        # 5. Loop principal: recebe mensagens do cliente (ex: pause/resume) e atualiza last_seen
        while True:
            try:
                msg = await websocket.recv()
                await manager.update_last_seen(job_id, user_id)
                
                # Opcional: processar comandos do cliente
                try:
                    cmd = json.loads(msg)
                    if cmd.get("type") == "ping":
                        await websocket.send(json.dumps({"type": "pong", "ts": datetime.now(timezone.utc).isoformat()}))
                except json.JSONDecodeError:
                    pass  # Ignora mensagens não-JSON
                    
            except ConnectionClosed:
                logger.info(f"Connection closed normally: job={job_id}, user={user_id}")
                break
                
    except ConnectionClosed as e:
        logger.info(f"Connection closed with code {e.code}: job={job_id}, user={user_id}")
    except Exception as e:
        logger.error(f"Unexpected error in websocket_handler: job={job_id}, user={user_id}, error={e}")
    finally:
        # Cleanup final
        if job_id and user_id:
            await manager.remove_connection(job_id, user_id)
        logger.info(f"WebSocket session ended: job={job_id}, user={user_id}")

# ================= Public API para Engine de Scan =================
async def broadcast_scan_progress(message: ProgressMessage):
    """
    Função pública para a engine de scan chamar e broadcastar progresso.
    """
    await manager.broadcast(message.job_id, message)
    logger.debug(f"Progress broadcasted: job={message.job_id}, host={message.host}, status={message.status}")

# ================= Server Entry Point =================
async def start_websocket_server(host, port):
    """Inicia o servidor WebSocket standalone."""
    asyncio.create_task(inactivity_monitor())
    
    server = await websockets.serve(
        websocket_handler,
        host,
        port,
        max_size=MAX_MESSAGE_SIZE,
        ping_interval=20,
        ping_timeout=10,
    )
    
    logger.info(f"🚀 WebSocket server started on ws://{host}:{port}")
    return server

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Standalone WS Server")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_websocket_server("0.0.0.0", args.port))
    loop.run_forever()
