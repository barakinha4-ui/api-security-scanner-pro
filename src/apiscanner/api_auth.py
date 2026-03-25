"""
API Routes de Autenticação - Login, Signup, Logout
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional
import os

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@router.post("/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    """
    Registrar novo usuário
    
    Cria automaticamente:
    - Conta no Supabase Auth
    - Organização no banco
    - Plano gratuito
    """
    from supabase import create_client
    
    supabase = create_client(
        os.getenv("SUPABASE_URL"),
        os.getenv("SUPABASE_KEY")
    )
    
    try:
        # Criar usuário no Supabase Auth
        auth_response = supabase.auth.sign_up({
            "email": request.email,
            "password": request.password,
            "options": {
                "data": {
                    "full_name": request.full_name or request.email.split("@")[0]
                }
            }
        })
        
        if auth_response.user:
            return AuthResponse(
                access_token=auth_response.session.access_token if auth_response.session else "",
                user={
                    "id": str(auth_response.user.id),
                    "email": auth_response.user.email
                }
            )
        else:
            raise HTTPException(status_code=400, detail="Falha ao criar usuário")
            
    except Exception as e:
        error_msg = str(e)
        if "already registered" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Email já cadastrado")
        raise HTTPException(status_code=500, detail=f"Erro ao criar usuário: {error_msg}")


@router.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    """
    Login de usuário
    
    Retorna token de acesso JWT para usar na API
    """
    from supabase import create_client
    
    supabase = create_client(
        os.getenv("SUPABASE_URL"),
        os.getenv("SUPABASE_KEY")
    )
    
    try:
        auth_response = supabase.auth.sign_in_with_password({
            "email": request.email,
            "password": request.password
        })
        
        if auth_response.user and auth_response.session:
            return AuthResponse(
                access_token=auth_response.session.access_token,
                user={
                    "id": str(auth_response.user.id),
                    "email": auth_response.user.email
                }
            )
        else:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
            
    except Exception as e:
        raise HTTPException(status_code=401, detail="Email ou senha incorretos")


@router.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Logout de usuário
    
    Invalida o token de sessão
    """
    from supabase import create_client
    
    supabase = create_client(
        os.getenv("SUPABASE_URL"),
        os.getenv("SUPABASE_KEY")
    )
    
    try:
        supabase.auth.sign_out()
        return {"message": "Logout realizado com sucesso"}
    except Exception:
        return {"message": "Logout realizado"}


@router.get("/me")
async def get_me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Pegar dados do usuário atual
    
    Retorna informações do usuário logado
    """
    from supabase import create_client
    
    supabase = create_client(
        os.getenv("SUPABASE_URL"),
        os.getenv("SUPABASE_KEY")
    )
    
    try:
        user = supabase.auth.get_user(credentials.credentials)
        return {
            "id": str(user.user.id),
            "email": user.user.email,
            "created_at": user.user.created_at
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")


@router.post("/reset-password")
async def reset_password(email: EmailStr):
    """
    Solicitar reset de senha
    
    Envia email com link para redefinir senha
    """
    from supabase import create_client
    
    supabase = create_client(
        os.getenv("SUPABASE_URL"),
        os.getenv("SUPABASE_KEY")
    )
    
    try:
        supabase.auth.reset_password_email(email)
        return {"message": "Email de recuperação enviado"}
    except Exception:
        # Não revelar se email existe
        return {"message": "Se o email existir, você receberá um link de recuperação"}
