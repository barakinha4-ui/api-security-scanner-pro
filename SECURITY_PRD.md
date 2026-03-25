# SECURITY PRD - API Security Scanner Pro

## 1. Executive Summary

Este documento define os requisitos de segurança e plano de remediação para o projeto API Security Scanner Pro. A auditoria SAST identificou **8 vulnerabilidades** que devem ser corrigidas para garantir conformidade com OWASP Top 10 e melhores práticas de segurança.

## 2. Vulnerabilidades Identificadas

### 2.1 Criticas (CRITICAL)

| ID | Vulnerabilidade | Localização | OWASP Category |
|----|----------------|-------------|----------------|
| C1 | Hardcoded API Key Secret | `app.py:78-79` | A02:2021-Cryptographic Failures |
| C2 | Secrets Exposed in .env.example | `.env.example:9-31` | A02:2021-Cryptographic Failures |

### 2.2 Altas (HIGH)

| ID | Vulnerabilidade | Localização | OWASP Category |
|----|----------------|-------------|----------------|
| H1 | CORS Misconfiguration with Credentials | `app.py:167-172` | A01:2021-Broken Access Control |
| H2 | Weak JWT Secret Default | `app.py:83` | A02:2021-Cryptographic Failures |

### 2.3 Médias (MEDIUM)

| ID | Vulnerabilidade | Localização | OWASP Category |
|----|----------------|-------------|----------------|
| M1 | Timing Attack on Token Comparison | `app.py:274` | A02:2021-Cryptographic Failures |
| M2 | SSRF Bypass via Environment | `security_shield.py:118-120` | A10:2021-Server-Side Request Forgery |

### 2.4 Baixas (LOW)

| ID | Vulnerabilidade | Localização | OWASP Category |
|----|----------------|-------------|----------------|
| L1 | Weak Fallback Rate Limit | `security_shield.py:209` | A04:2021-Insecure Design |
| L2 | Missing Input Validation | `app.py:216-223` | A03:2021-Injection |

## 3. Requisitos Funcionais de Segurança

### 3.1 Autenticação e Autorização

- [ ] RF01: Tokens de API devem ser comparados usando `secrets.compare_digest()` para evitar timing attacks
- [ ] RF02: Secrets não devem ter valores hardcoded ou defaults inseguros
- [ ] RF03: JWT secrets devem ter no mínimo 256 bits de entropia
- [ ] RF04: Autenticação multi-fator (MFA) deve ser suportada via Supabase

### 3.2 Proteção de Dados

- [ ] RF05: Todas as variáveis de ambiente sensíveis devem ser validadas na inicialização
- [ ] RF06: Arquivos .env.example NÃO devem conter valores reais ou 示例 de secrets
- [ ] RF07: Comunicação deve usar TLS 1.3 obrigatório em produção

### 3.3 Controle de Acesso

- [ ] RF08: CORS deve validar origens explicitamente (não usar `*` com credentials)
- [ ] RF09: Rate limiting deve ser consistente mesmo em fallback
- [ ] RF10: SSRF protection deve ter whitelist explícita

### 3.4 Logging e Monitoramento

- [ ] RF11: Eventos de segurança devem ser logados com correlation ID
- [ ] RF12: Falhas de autenticação devem ser monitoradas

## 4. Requisitos Não Funcionais

### 4.1 Segurança

- Tempo de resposta de autenticação: < 100ms
- Rate limit: 100 req/min por usuário
- TLS: Versão mínima 1.2, preferencial 1.3

### 4.2 Compliance

- Conformidade OWASP Top 10 (2021)
- LGPD compliance para dados de usuários brasileiros

## 5. Plano de Implementação

### Sprint 1: Critical Fixes
- [ ] Remover secrets do .env.example
- [ ] Implementar validação de secrets em startup
- [ ] Adicionar secrets ao .gitignore (verificar)

### Sprint 2: High Priority
- [ ] Corrigir CORS configuration
- [ ] Forçar JWT secret forte
- [ ] Implementar timing-safe comparison

### Sprint 3: Medium Priority
- [ ] Revisar SSRF bypass
- [ ] Melhorar rate limiting
- [ ] Adicionar validação de input com Pydantic

### Sprint 4: Testing
- [ ] Executar testes de segurança
- [ ] Verificar com ferramentas automatizadas
- [ ] Validar conformidade

## 6. Critérios de Aceitação

- [ ] Zero vulnerabilidades CRITICAL
- [ ] Zero vulnerabilidades HIGH
- [ ] Cobertura de testes > 80%
- [ ] Pipeline CI/CD passando com security checks

---

**Data de Criação:** 2026-03-25  
**Versão:** 1.0  
**Status:** Em Andamento
