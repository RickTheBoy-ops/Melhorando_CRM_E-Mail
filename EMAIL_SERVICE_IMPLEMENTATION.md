# Email Service - Implementação Completa

## Visão Geral

O Email Service é um microserviço robusto e escalável para envio de emails em massa, desenvolvido em Go com arquitetura assíncrona e recursos avançados de confiabilidade.

## Arquitetura

### Componentes Principais

1. **EmailService**: Serviço principal que coordena todas as operações
2. **SMTPPool**: Pool de conexões SMTP reutilizáveis
3. **WorkerPool**: Pool de workers para processamento assíncrono
4. **RateLimiter**: Limitador de taxa por domínio/IP
5. **CircuitBreaker**: Proteção contra falhas em cascata
6. **Template Engine**: Sistema de templates para emails

### Fluxo de Processamento

```
Client → API Endpoint → Rate Limiter → Redis Queue → Workers → SMTP Pool → Email Delivery
                                    ↓
                              Retry Queue ← Circuit Breaker
                                    ↓
                              Failed Queue
```

## Endpoints da API

### POST /email/send
Envia um email único.

**Request Body:**
```json
{
  "to": ["user@example.com"],
  "from": "noreply@billionmail.com",
  "subject": "Assunto do Email",
  "body": "Conteúdo em texto",
  "html_body": "<h1>Conteúdo HTML</h1>",
  "template": "welcome",
  "template_data": {
    "UserName": "João",
    "CompanyName": "BillionMail",
    "Email": "joao@example.com",
    "LoginURL": "https://app.billionmail.com/login"
  }
}
```

**Response:**
```json
{
  "message": "Email queued for processing",
  "job_id": "email_1234567890",
  "queued_at": 1640995200
}
```

### POST /email/bulk
Envia emails em massa.

**Request Body:**
```json
{
  "emails": [
    {
      "to": ["user1@example.com"],
      "subject": "Email 1",
      "body": "Conteúdo 1"
    },
    {
      "to": ["user2@example.com"],
      "subject": "Email 2",
      "body": "Conteúdo 2"
    }
  ]
}
```

### GET /email/status/:id
Verifica o status de um job de email.

**Response:**
```json
{
  "status": "sent",
  "message": "Email sent successfully",
  "updated_at": 1640995300
}
```

### GET /email/stats
Retorna estatísticas detalhadas do serviço.

**Response:**
```json
{
  "timestamp": 1640995400,
  "queues": {
    "email_queue": 150,
    "retry_queue": 5,
    "failed_queue": 2
  },
  "circuit_breaker": {
    "state": "closed",
    "failure_count": 0,
    "last_failure": 0
  },
  "rate_limiter": {
    "active_domains": 25,
    "rate_limit": 60,
    "burst": 120
  }
}
```

### GET /health
Health check do serviço.

### GET /metrics
Métricas Prometheus.

## Recursos Implementados

### 1. Rate Limiting por Domínio
- Limita emails por domínio de destino
- Configurável via `RATE_LIMIT_PER_MINUTE`
- Previne spam e sobrecarga de provedores

### 2. Circuit Breaker
- Proteção contra falhas em cascata
- Estados: closed, open, half-open
- Configurável via variáveis de ambiente

### 3. Filas Redis Separadas
- **email_queue**: Emails novos para processamento
- **retry_queue**: Emails para reprocessamento
- **failed_queue**: Emails que falharam definitivamente

### 4. Sistema de Templates
- Templates pré-definidos: welcome, password_reset
- Renderização de subject, HTML e texto
- Suporte a variáveis dinâmicas

### 5. Pool de Conexões SMTP
- Reutilização de conexões
- Configuração de máximo de conexões
- Gerenciamento automático de recursos

### 6. Processamento Assíncrono
- Workers concorrentes configuráveis
- Processamento de filas em background
- Retry com exponential backoff

### 7. Métricas Prometheus
- Emails enviados/falhados
- Tempo de processamento
- Tamanho das filas
- Conexões SMTP ativas

### 8. Graceful Shutdown
- Finalização controlada do serviço
- Processamento de jobs em andamento
- Timeout configurável

## Variáveis de Ambiente

### Configuração Básica
```env
# Porta do serviço
EMAIL_SERVICE_PORT=8002

# Configuração SMTP
SMTP_HOST=postfix
SMTP_PORT=587
SMTP_USER=noreply@billionmail.com
SMTP_PASS=smtp_password_here
SMTP_MAX_CONNECTIONS=10

# Redis
REDIS_URL=redis:6379
REDIS_PASSWORD=password
```

### Configuração de Processamento
```env
# Workers e processamento
MAX_WORKERS=5
BATCH_SIZE=100
RATE_LIMIT_PER_MINUTE=60

# Retry e circuit breaker
MAX_EMAIL_RETRIES=3
RETRY_BACKOFF_MULTIPLIER=2
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT=30s
```

### Configuração de Templates
```env
# Email padrão
DEFAULT_FROM_EMAIL=noreply@billionmail.com
COMPANY_NAME=BillionMail
SUPPORT_EMAIL=support@billionmail.com
```

## Templates Disponíveis

### Welcome Template
Usado para emails de boas-vindas.

**Variáveis:**
- `UserName`: Nome do usuário
- `CompanyName`: Nome da empresa
- `Email`: Email do usuário
- `LoginURL`: URL de login

### Password Reset Template
Usado para reset de senha.

**Variáveis:**
- `UserName`: Nome do usuário
- `CompanyName`: Nome da empresa
- `ResetURL`: URL de reset
- `ExpirationTime`: Tempo de expiração em minutos

## Monitoramento e Observabilidade

### Métricas Prometheus
- `emails_sent_total`: Total de emails enviados
- `emails_failed_total`: Total de emails falhados
- `emails_queued_total`: Total de emails enfileirados
- `email_processing_duration_seconds`: Tempo de processamento
- `email_queue_size`: Tamanho da fila
- `smtp_connections_active`: Conexões SMTP ativas

### Logs Estruturados
- Logs de início/parada do serviço
- Logs de processamento de emails
- Logs de erros e retries
- Logs de circuit breaker

## Tratamento de Erros

### Estratégia de Retry
1. Falha inicial → Retry Queue
2. Exponential backoff: 1min, 4min, 9min
3. Após 3 tentativas → Failed Queue

### Circuit Breaker
- **Closed**: Operação normal
- **Open**: Falhas frequentes, bloqueia requests
- **Half-Open**: Testa recuperação

## Segurança

### Rate Limiting
- Previne spam por domínio
- Proteção contra ataques de volume
- Configuração flexível por ambiente

### Validação de Input
- Validação de emails
- Sanitização de templates
- Validação de headers

## Performance

### Otimizações
- Pool de conexões SMTP
- Processamento assíncrono
- Filas Redis para escalabilidade
- Workers concorrentes

### Benchmarks Esperados
- 1000+ emails/minuto (configuração padrão)
- Latência < 100ms para enfileiramento
- Throughput escalável com workers

## Deployment

### Docker
O serviço está configurado para rodar em container Docker com:
- Imagem base Go
- Configuração via environment
- Health checks integrados
- Graceful shutdown

### Dependências
- Redis (filas e cache)
- SMTP Server (Postfix ou externo)
- Prometheus (métricas)

## Próximos Passos

1. **Webhook Callbacks**: Notificações de status
2. **Tracking**: Opens e clicks
3. **Templates Avançados**: Editor visual
4. **A/B Testing**: Testes de subject/conteúdo
5. **Bounce Handling**: Tratamento de bounces
6. **DKIM/SPF**: Autenticação de emails

## Critérios de Sucesso Atendidos

✅ Service inicia e conecta ao Redis/SMTP  
✅ Processa emails assincronamente via workers  
✅ Rate limiting funciona corretamente  
✅ Health check mostra status de componentes  
✅ Bulk email divide em batches adequados  
✅ Retry logic reprocessa falhas  
✅ Logs estruturados para debugging  
✅ Graceful shutdown implementado  
✅ Circuit breaker protege contra falhas  
✅ Templates básicos funcionais  
✅ Métricas Prometheus expostas  
✅ Configuração via environment variables  

## Conclusão

O Email Service foi implementado com sucesso seguindo as melhores práticas de arquitetura de microserviços, incluindo todos os recursos solicitados e recursos adicionais para robustez e observabilidade. O serviço está pronto para produção e pode escalar horizontalmente conforme necessário.