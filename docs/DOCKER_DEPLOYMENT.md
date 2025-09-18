# 🐳 BillionMail - Guia de Deploy Docker

## 📋 Visão Geral

Este guia documenta o processo completo de build e deploy do BillionMail em ambiente Docker, incluindo a configuração de microserviços e testes de conectividade.

## 🏗️ Arquitetura dos Microserviços

### Serviços Principais
- **Gateway API** (`:8080`) - Ponto de entrada e roteamento
- **Auth Service** (`:8001`) - Autenticação e autorização
- **Email Service** (`:8002`) - Processamento de emails
- **Campaign Service** (`:8003`) - Gerenciamento de campanhas
- **Contact Service** (`:8004`) - Gerenciamento de contatos
- **Analytics Service** (`:8005`) - Análises e métricas
- **Template Service** (`:8006`) - Gerenciamento de templates
- **Notification Service** (`:8007`) - Sistema de notificações

### Infraestrutura
- **PostgreSQL** (`:25432`) - Banco de dados principal
- **Redis** (`:26379`) - Cache e filas
- **Postfix** (`:25`, `:587`) - Servidor SMTP

## ⚙️ Configuração de Ambiente

### 1. Arquivo .env

O arquivo `.env` contém todas as configurações necessárias:

```bash
# Copiar e ajustar conforme necessário
cp .env.example .env
```

**Principais variáveis configuradas:**
- `AUTH_SERVICE_URL=http://auth-service:8001`
- `EMAIL_SERVICE_URL=http://email-service:8002`
- `DATABASE_URL=postgresql://billionmail:password@pgsql:5432/billionmail`
- `REDIS_URL=redis://:password@redis:6379`
- `JWT_SECRET=BillionMail_JWT_Secret_Key_2024_Ultra_Secure_Random_String_!@#$%`

### 2. Configuração para Desenvolvimento Local

Para desenvolvimento local, descomente as URLs localhost no `.env`:

```bash
# Descomente estas linhas para desenvolvimento local
# AUTH_SERVICE_URL=http://localhost:8001
# EMAIL_SERVICE_URL=http://localhost:8002
# ...
```

## 🚀 Processo de Build e Deploy

### 1. Build dos Microserviços

```bash
# Build de todos os serviços
docker-compose -f docker-compose.microservices.yml build

# Build de um serviço específico
docker-compose -f docker-compose.microservices.yml build gateway
docker-compose -f docker-compose.microservices.yml build auth-service
```

### 2. Deploy Completo

```bash
# Deploy de toda a stack
docker-compose -f docker-compose.microservices.yml up -d

# Verificar status dos containers
docker-compose -f docker-compose.microservices.yml ps

# Visualizar logs
docker-compose -f docker-compose.microservices.yml logs -f
```

### 3. Deploy Incremental

```bash
# Atualizar apenas um serviço
docker-compose -f docker-compose.microservices.yml up -d --no-deps gateway

# Reiniciar serviço específico
docker-compose -f docker-compose.microservices.yml restart auth-service
```

## 🔍 Testes de Conectividade

### 1. Health Checks dos Serviços

```bash
# Gateway API
curl http://localhost:8080/health

# Auth Service
curl http://localhost:8001/health

# Email Service
curl http://localhost:8002/health

# Campaign Service
curl http://localhost:8003/health
```

### 2. Teste de Conectividade Entre Containers

```bash
# Entrar no container do gateway
docker exec -it billionmail-gateway sh

# Testar conectividade com outros serviços
wget -qO- http://auth-service:8001/health
wget -qO- http://email-service:8002/health
wget -qO- http://campaign-service:8003/health

# Testar conectividade com infraestrutura
telnet pgsql 5432
telnet redis 6379
```

### 3. Teste de Resolução DNS

```bash
# Verificar resolução de nomes
docker exec billionmail-gateway nslookup auth-service
docker exec billionmail-gateway nslookup pgsql
docker exec billionmail-gateway nslookup redis
```

### 4. Teste de Autenticação

```bash
# Registrar usuário
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"123456"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"123456"}'
```

## 🐛 Troubleshooting

### Problemas Comuns

#### 1. Serviço não consegue conectar com banco
```bash
# Verificar se PostgreSQL está rodando
docker-compose -f docker-compose.microservices.yml logs pgsql

# Testar conexão manual
docker exec -it billionmail-auth-service sh
telnet pgsql 5432
```

#### 2. Gateway não encontra microserviços
```bash
# Verificar variáveis de ambiente
docker exec billionmail-gateway env | grep SERVICE_URL

# Verificar rede Docker
docker network ls
docker network inspect billionmail-dev_billionmail-network
```

#### 3. Redis não conecta
```bash
# Verificar senha do Redis
docker exec -it redis-billionmail redis-cli
AUTH sua_senha_redis
PING
```

### Logs Úteis

```bash
# Logs de todos os serviços
docker-compose -f docker-compose.microservices.yml logs

# Logs de serviço específico
docker-compose -f docker-compose.microservices.yml logs gateway
docker-compose -f docker-compose.microservices.yml logs auth-service

# Logs em tempo real
docker-compose -f docker-compose.microservices.yml logs -f --tail=100
```

## 🔧 Comandos de Manutenção

### Limpeza
```bash
# Parar todos os containers
docker-compose -f docker-compose.microservices.yml down

# Remover volumes (CUIDADO: apaga dados)
docker-compose -f docker-compose.microservices.yml down -v

# Limpeza completa
docker system prune -a
```

### Backup
```bash
# Backup do banco PostgreSQL
docker exec pgsql-billionmail pg_dump -U billionmail billionmail > backup.sql

# Backup do Redis
docker exec redis-billionmail redis-cli --rdb /data/backup.rdb
```

### Monitoramento
```bash
# Status dos containers
docker stats

# Uso de recursos por container
docker-compose -f docker-compose.microservices.yml top

# Informações detalhadas
docker inspect billionmail-gateway
```

## 📊 Métricas e Monitoramento

### Endpoints de Health Check
- Gateway: `http://localhost:8080/health`
- Auth: `http://localhost:8001/health`
- Email: `http://localhost:8002/health`
- Campaign: `http://localhost:8003/health`
- Contact: `http://localhost:8004/health`
- Analytics: `http://localhost:8005/health`
- Template: `http://localhost:8006/health`
- Notification: `http://localhost:8007/health`

### Verificação de Performance
```bash
# Teste de carga no gateway
ab -n 1000 -c 10 http://localhost:8080/health

# Monitoramento de recursos
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

## 🔐 Segurança

### Variáveis Sensíveis
- `JWT_SECRET`: Chave para assinatura de tokens JWT
- `DBPASS`: Senha do banco PostgreSQL
- `REDISPASS`: Senha do Redis
- `SMTP_PASS`: Senha do SMTP

### Recomendações
1. **Nunca commitar** o arquivo `.env` com dados reais
2. **Usar secrets** do Docker Swarm em produção
3. **Rotacionar senhas** regularmente
4. **Configurar firewall** para limitar acesso às portas

## 🚀 Deploy em Produção

### Docker Swarm
```bash
# Inicializar swarm
docker swarm init

# Deploy da stack
docker stack deploy -c docker-compose.microservices.yml billionmail

# Verificar serviços
docker service ls
```

### Kubernetes (Helm)
```bash
# Converter docker-compose para Kubernetes
kompose convert -f docker-compose.microservices.yml

# Aplicar manifests
kubectl apply -f .
```

---

## 📞 Suporte

Para problemas ou dúvidas:
1. Verificar logs dos containers
2. Consultar este guia de troubleshooting
3. Verificar conectividade de rede
4. Validar configurações do `.env`

**Última atualização:** $(date)
**Versão:** 1.0.0