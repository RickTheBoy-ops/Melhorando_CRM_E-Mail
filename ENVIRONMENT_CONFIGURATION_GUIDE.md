# Guia de Configuração de Ambiente - BillionMail CRM

## Visão Geral

Este guia explica como configurar e usar as variáveis de ambiente do BillionMail CRM para diferentes cenários de deployment (desenvolvimento, staging, produção).

## Estrutura de Arquivos

```
BillionMail-dev/
├── .env                    # Arquivo de configuração ativo (NÃO committar)
├── .env.example           # Template para novos ambientes
├── docker-compose.yml     # Configuração Docker principal
└── docker-compose.microservices.yml  # Configuração dos microserviços
```

## Configuração Inicial

### 1. Primeiro Setup

```bash
# Copie o template
cp .env.example .env

# Edite as configurações necessárias
nano .env  # ou seu editor preferido
```

### 2. Validação da Configuração

```bash
# Valide a sintaxe do docker-compose
docker-compose -f docker-compose.microservices.yml config

# Teste as variáveis
docker-compose -f docker-compose.microservices.yml up --dry-run
```

## Configurações por Ambiente

### 🔧 Desenvolvimento Local

**Características:**
- Serviços rodando em containers Docker
- Dados não persistentes (desenvolvimento)
- Logs detalhados habilitados
- Senhas simples para facilitar desenvolvimento

**Configurações Principais:**
```env
NODE_ENV=development
GIN_MODE=debug
LOG_LEVEL=debug
DEBUG=true

# URLs internas Docker
AUTH_SERVICE_URL=http://auth-service:8001
EMAIL_SERVICE_URL=http://email-service:8002

# Senhas simples para dev
POSTGRES_PASSWORD=dev_password_123
REDIS_PASSWORD=dev_redis_123
JWT_SECRET=dev-jwt-secret-key-not-for-production
```

**Comandos:**
```bash
# Iniciar todos os serviços
docker-compose -f docker-compose.microservices.yml up -d

# Ver logs em tempo real
docker-compose -f docker-compose.microservices.yml logs -f

# Parar todos os serviços
docker-compose -f docker-compose.microservices.yml down
```

### 🧪 Desenvolvimento Local (Fora do Docker)

**Características:**
- Serviços rodando diretamente no host
- Útil para debugging e desenvolvimento ativo
- Requer PostgreSQL e Redis instalados localmente

**Configurações Principais:**
```env
NODE_ENV=development
GIN_MODE=debug
LOG_LEVEL=debug

# URLs locais
POSTGRES_HOST=localhost
REDIS_HOST=localhost
AUTH_SERVICE_URL=http://localhost:8001
EMAIL_SERVICE_URL=http://localhost:8002

# Portas locais
POSTGRES_PORT=5432
REDIS_PORT=6379
```

**Comandos:**
```bash
# Iniciar apenas infraestrutura (PostgreSQL, Redis)
docker-compose up -d postgres redis

# Rodar serviços individualmente
cd services/auth-service && go run .
cd services/email-service && go run .
cd gateway && go run .
```

### 🚀 Staging/Teste

**Características:**
- Ambiente similar à produção
- Dados de teste
- Monitoramento habilitado
- Senhas mais seguras

**Configurações Principais:**
```env
NODE_ENV=staging
GIN_MODE=release
LOG_LEVEL=info
DEBUG=false

# Senhas mais seguras
POSTGRES_PASSWORD=staging_secure_password_2024
REDIS_PASSWORD=staging_redis_secure_2024
JWT_SECRET=staging-jwt-secret-key-32-chars-minimum-length

# Monitoramento habilitado
METRICS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_PORT=3001

# SSL desabilitado para staging
SSL_ENABLED=false
SESSION_SECURE=false
```

### 🏭 Produção

**Características:**
- Máxima segurança
- SSL habilitado
- Backup automático
- Monitoramento completo
- Senhas geradas aleatoriamente

**Configurações Principais:**
```env
NODE_ENV=production
GIN_MODE=release
LOG_LEVEL=warn
DEBUG=false

# Senhas seguras (use geradores de senha)
POSTGRES_PASSWORD=GENERATE_RANDOM_64_CHARS
REDIS_PASSWORD=GENERATE_RANDOM_64_CHARS
JWT_SECRET=GENERATE_RANDOM_JWT_SECRET_MIN_64_CHARS

# SSL habilitado
SSL_ENABLED=true
SESSION_SECURE=true
HTTPS_PORT=443

# CORS restritivo
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Backup habilitado
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=30

# Monitoramento completo
METRICS_ENABLED=true
HEALTH_CHECK_INTERVAL=30s
```

## Seções de Configuração Detalhadas

### 🗄️ Database (PostgreSQL)

```env
# Configuração principal
POSTGRES_USER=billionmail_user
POSTGRES_PASSWORD=sua_senha_segura
POSTGRES_DB=billionmail
POSTGRES_HOST=postgres  # ou localhost para dev local
POSTGRES_PORT=5432

# URLs específicas por serviço
DATABASE_URL=postgres://user:pass@host:port/db?sslmode=disable
AUTH_DATABASE_URL=postgres://user:pass@host:port/billionmail_auth?sslmode=disable

# Pool de conexões
DB_MAX_OPEN_CONNS=25      # Máximo de conexões abertas
DB_MAX_IDLE_CONNS=5       # Conexões idle mantidas
DB_CONN_MAX_LIFETIME=300s # Tempo de vida das conexões
```

### 🔴 Redis Cache

```env
# Configuração básica
REDIS_HOST=redis          # ou localhost para dev local
REDIS_PORT=6379
REDIS_PASSWORD=sua_senha_redis
REDIS_URL=redis:6379

# Configurações de conexão
REDIS_MAX_RETRIES=3       # Tentativas de reconexão
REDIS_POOL_SIZE=10        # Tamanho do pool
REDIS_DIAL_TIMEOUT=5s     # Timeout de conexão

# Databases separados por função
REDIS_CACHE_DB=0          # Cache geral
REDIS_SESSION_DB=1        # Sessões de usuário
REDIS_QUEUE_DB=2          # Filas de email
REDIS_RATE_LIMIT_DB=3     # Rate limiting
```

### 🔐 Segurança e Autenticação

```env
# JWT Configuration
JWT_SECRET=sua_chave_jwt_minimo_32_caracteres
JWT_EXPIRATION=24h        # Expiração do token
JWT_REFRESH_EXPIRATION=168h # Expiração do refresh token
JWT_ISSUER=billionmail-crm

# Rate Limiting
RATE_LIMIT_REQUESTS=100   # Requests por janela
RATE_LIMIT_WINDOW=1m      # Janela de tempo
RATE_LIMIT_BURST=200      # Burst permitido

# CORS (ajuste para seu domínio)
CORS_ALLOWED_ORIGINS=https://yourdomain.com
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS

# Sessões
SESSION_SECRET=sua_chave_sessao_segura
SESSION_MAX_AGE=86400     # 24 horas
SESSION_SECURE=true       # Apenas HTTPS em produção
```

### 📧 SMTP e Email

```env
# Servidor SMTP
SMTP_HOST=postfix         # ou seu provedor SMTP
SMTP_PORT=587             # 587 para STARTTLS, 465 para SSL
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=sua_senha_smtp
SMTP_TLS=true
SMTP_START_TLS=true

# Configuração do Email Service
EMAIL_SERVICE_PORT=8002
MAX_WORKERS=5             # Workers concorrentes
BATCH_SIZE=100            # Emails por batch
MAX_EMAIL_RETRIES=3       # Tentativas de reenvio

# Circuit Breaker
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5  # Falhas para abrir
CIRCUIT_BREAKER_TIMEOUT=30s          # Tempo para tentar novamente
```

### 📊 Monitoramento

```env
# Prometheus
PROMETHEUS_PORT=9090
METRICS_ENABLED=true
METRICS_PATH=/metrics

# Grafana
GRAFANA_PORT=3001
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=sua_senha_grafana

# Health Checks
HEALTH_CHECK_INTERVAL=30s
HEALTH_CHECK_TIMEOUT=10s
HEALTH_CHECK_PATH=/health

# Logs
LOG_LEVEL=info            # debug, info, warn, error
LOG_FORMAT=json           # json ou text
LOG_OUTPUT=stdout         # stdout ou file
```

## Checklist de Segurança para Produção

### ✅ Antes do Deploy

- [ ] **Senhas Únicas**: Gere senhas aleatórias para todos os serviços
- [ ] **JWT Secret**: Mínimo 64 caracteres, gerado aleatoriamente
- [ ] **SSL Habilitado**: `SSL_ENABLED=true`
- [ ] **CORS Restritivo**: Apenas domínios necessários
- [ ] **Session Secure**: `SESSION_SECURE=true` para HTTPS
- [ ] **Log Level**: `LOG_LEVEL=warn` ou `error`
- [ ] **Debug Desabilitado**: `DEBUG=false`
- [ ] **Environment**: `NODE_ENV=production`

### 🔒 Geração de Senhas Seguras

```bash
# Gerar senha PostgreSQL (32 chars)
openssl rand -base64 32

# Gerar JWT Secret (64 chars)
openssl rand -base64 64

# Gerar senha Redis (32 chars)
openssl rand -hex 32

# Gerar chave de criptografia (32 chars)
openssl rand -base64 32
```

### 🛡️ Configurações de Segurança Avançadas

```env
# Rate Limiting mais restritivo
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW=1m
RATE_LIMIT_BURST=100

# Timeouts mais baixos
REDIS_DIAL_TIMEOUT=3s
REDIS_READ_TIMEOUT=2s
REDIS_WRITE_TIMEOUT=2s

# Fail2Ban habilitado
FAIL2BAN_ENABLED=true
FAIL2BAN_BANTIME=3600
FAIL2BAN_MAXRETRY=3

# Whitelist apenas IPs necessários
WHITELIST_IPS=seu.ip.publico,172.20.0.0/16
```

## Troubleshooting

### 🔍 Problemas Comuns

#### Serviço não inicia
```bash
# Verificar logs
docker-compose logs [service-name]

# Verificar configuração
docker-compose config

# Verificar portas em uso
netstat -tulpn | grep :8080
```

#### Erro de conexão com banco
```bash
# Testar conexão PostgreSQL
psql -h localhost -p 5432 -U billionmail_user -d billionmail

# Verificar se PostgreSQL está rodando
docker-compose ps postgres

# Ver logs do PostgreSQL
docker-compose logs postgres
```

#### Erro de conexão com Redis
```bash
# Testar conexão Redis
redis-cli -h localhost -p 6379 -a sua_senha ping

# Verificar se Redis está rodando
docker-compose ps redis

# Ver logs do Redis
docker-compose logs redis
```

#### SMTP não funciona
```bash
# Testar conexão SMTP
telnet smtp.host.com 587

# Verificar logs do email service
docker-compose logs email-service

# Verificar configurações SMTP
echo $SMTP_HOST $SMTP_PORT $SMTP_USER
```

### 🔧 Comandos Úteis

```bash
# Reiniciar serviço específico
docker-compose restart [service-name]

# Rebuild e restart
docker-compose up -d --build [service-name]

# Ver uso de recursos
docker stats

# Limpar volumes (CUIDADO: apaga dados)
docker-compose down -v

# Backup do banco
docker exec postgres pg_dump -U billionmail_user billionmail > backup.sql

# Restore do banco
docker exec -i postgres psql -U billionmail_user billionmail < backup.sql
```

### 📋 Health Checks

```bash
# Gateway
curl http://localhost:8080/health

# Auth Service
curl http://localhost:8001/health

# Email Service
curl http://localhost:8002/health

# Métricas Prometheus
curl http://localhost:9090/metrics

# Stats do Email Service
curl http://localhost:8002/email/stats
```

## Backup e Restore

### 💾 Backup Automático

```env
# Configuração no .env
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *  # Todo dia às 2h
BACKUP_RETENTION_DAYS=30
BACKUP_STORAGE_PATH=/var/backups/billionmail
```

### 📦 Backup Manual

```bash
# Backup completo
./scripts/backup.sh

# Backup apenas banco
docker exec postgres pg_dumpall -U billionmail_user > full_backup.sql

# Backup arquivos de configuração
tar -czf config_backup.tar.gz .env docker-compose*.yml
```

## Monitoramento e Alertas

### 📈 Métricas Importantes

- **CPU/Memory**: Uso de recursos dos containers
- **Database**: Conexões ativas, queries lentas
- **Redis**: Uso de memória, hit rate
- **Email**: Taxa de envio, falhas, filas
- **API**: Response time, error rate

### 🚨 Alertas Recomendados

- CPU > 80% por 5 minutos
- Memory > 90% por 2 minutos
- Disk space < 10%
- Email queue > 1000 emails
- Error rate > 5%
- Response time > 2 segundos

## Conclusão

Este guia cobre todas as configurações necessárias para deploy do BillionMail CRM em diferentes ambientes. Sempre siga as práticas de segurança e teste as configurações antes do deploy em produção.

Para suporte adicional, consulte:
- [Documentação do Docker Compose](https://docs.docker.com/compose/)
- [Guia de Segurança PostgreSQL](https://www.postgresql.org/docs/current/security.html)
- [Boas Práticas Redis](https://redis.io/topics/security)
- [Configuração SMTP](https://tools.ietf.org/html/rfc5321)