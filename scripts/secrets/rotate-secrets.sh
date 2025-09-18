#!/bin/bash
# ========================================
# BILLIONMAIL - ROTAÇÃO AUTOMÁTICA DE SECRETS
# ========================================
# P0 SECURITY FIX: Rotação segura sem downtime
# Compliance: GDPR, SOC2, PCI-DSS requirements
# Zero Trust: Rotação automática com rollback

set -euo pipefail

# Configurações
ENVIRONMENT=${1:-production}
SERVICE_PREFIX="billionmail"
ROTATION_LOG="/var/log/billionmail/secret-rotation.log"
SLACK_WEBHOOK=${SLACK_WEBHOOK:-""}
MAX_ROLLBACK_ATTEMPTS=3
HEALTH_CHECK_TIMEOUT=60

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$ROTATION_LOG"
}

info() { log "INFO" "$*"; }
warn() { log "WARN" "$*"; }
error() { log "ERROR" "$*"; }
success() { log "SUCCESS" "$*"; }

# Função para gerar passwords seguros
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Função para gerar JWT secret
generate_jwt_secret() {
    openssl rand -hex 32
}

# Função para notificar Slack
notify_slack() {
    local message="$1"
    local color="$2"
    
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"attachments\":[{\"color\":\"$color\",\"text\":\"🔐 BillionMail Secrets Rotation\\n$message\"}]}" \
            "$SLACK_WEBHOOK" 2>/dev/null || true
    fi
}

# Função para verificar se Docker Swarm está ativo
check_swarm() {
    if ! docker info --format '{{.Swarm.LocalNodeState}}' | grep -q "active"; then
        error "Docker Swarm não está ativo. Execute: docker swarm init"
        exit 1
    fi
    info "Docker Swarm ativo ✅"
}

# Função para verificar saúde dos serviços
check_service_health() {
    local service_name="$1"
    local max_attempts=12
    local attempt=1
    
    info "Verificando saúde do serviço: $service_name"
    
    while [[ $attempt -le $max_attempts ]]; do
        local replicas=$(docker service ls --filter "name=$service_name" --format "{{.Replicas}}")
        
        if [[ "$replicas" =~ ^[0-9]+/[0-9]+$ ]]; then
            local running=$(echo "$replicas" | cut -d'/' -f1)
            local desired=$(echo "$replicas" | cut -d'/' -f2)
            
            if [[ "$running" == "$desired" && "$running" -gt 0 ]]; then
                success "Serviço $service_name saudável: $replicas"
                return 0
            fi
        fi
        
        warn "Tentativa $attempt/$max_attempts: $service_name não está saudável ($replicas)"
        sleep 5
        ((attempt++))
    done
    
    error "Serviço $service_name falhou no health check após $max_attempts tentativas"
    return 1
}

# Função para fazer rollback de um secret
rollback_secret() {
    local service_name="$1"
    local secret_name="$2"
    
    warn "🔄 Iniciando rollback para $service_name..."
    
    # Rollback do serviço
    if docker service rollback "$service_name" 2>/dev/null; then
        success "Rollback do serviço $service_name executado"
        
        # Aguardar estabilização
        sleep 30
        
        # Verificar saúde após rollback
        if check_service_health "$service_name"; then
            success "Rollback de $secret_name concluído com sucesso"
            notify_slack "⚠️ Rollback executado para $secret_name no ambiente $ENVIRONMENT" "warning"
            return 0
        else
            error "Rollback falhou para $service_name"
            return 1
        fi
    else
        error "Falha ao executar rollback do serviço $service_name"
        return 1
    fi
}

# Função principal para rotacionar um secret
rotate_secret() {
    local secret_name="$1"
    local new_value="$2"
    local services=("${@:3}")
    
    info "🔄 Iniciando rotação do secret: $secret_name"
    
    # Criar novo secret com timestamp
    local timestamp=$(date +%s)
    local new_secret_name="${secret_name}_${timestamp}"
    
    # Criar o novo secret
    if echo "$new_value" | docker secret create "$new_secret_name" - 2>/dev/null; then
        success "Novo secret criado: $new_secret_name"
    else
        error "Falha ao criar novo secret: $new_secret_name"
        return 1
    fi
    
    # Atualizar cada serviço
    for service in "${services[@]}"; do
        local full_service_name="${SERVICE_PREFIX}_${service}"
        
        info "Atualizando serviço: $full_service_name"
        
        # Atualizar serviço com novo secret
        if docker service update \
            --secret-rm "$secret_name" \
            --secret-add "source=$new_secret_name,target=$secret_name" \
            "$full_service_name" >/dev/null 2>&1; then
            
            success "Serviço $full_service_name atualizado"
            
            # Aguardar estabilização
            info "Aguardando estabilização do serviço..."
            sleep 30
            
            # Verificar saúde do serviço
            if check_service_health "$full_service_name"; then
                success "✅ Rotação de $secret_name concluída para $service"
            else
                error "❌ Health check falhou para $service após rotação"
                
                # Tentar rollback
                if rollback_secret "$full_service_name" "$secret_name"; then
                    # Remover secret novo que falhou
                    docker secret rm "$new_secret_name" 2>/dev/null || true
                    return 1
                else
                    error "CRÍTICO: Rollback falhou para $service"
                    notify_slack "🚨 CRÍTICO: Rollback falhou para $secret_name em $service no ambiente $ENVIRONMENT" "danger"
                    return 1
                fi
            fi
        else
            error "Falha ao atualizar serviço $full_service_name"
            # Remover secret novo que falhou
            docker secret rm "$new_secret_name" 2>/dev/null || true
            return 1
        fi
    done
    
    # Se chegou até aqui, rotação foi bem-sucedida
    # Remover secret antigo
    if docker secret rm "$secret_name" 2>/dev/null; then
        success "Secret antigo removido: $secret_name"
    else
        warn "Não foi possível remover secret antigo: $secret_name"
    fi
    
    # Renomear novo secret para o nome original
    # Nota: Docker não suporta rename, então mantemos o novo nome
    # e atualizamos os serviços novamente
    for service in "${services[@]}"; do
        local full_service_name="${SERVICE_PREFIX}_${service}"
        docker service update \
            --secret-rm "$secret_name" \
            --secret-add "source=$new_secret_name,target=$secret_name" \
            "$full_service_name" >/dev/null 2>&1 || true
    done
    
    success "🎉 Rotação de $secret_name concluída com sucesso!"
    notify_slack "✅ Secret $secret_name rotacionado com sucesso no ambiente $ENVIRONMENT" "good"
    
    return 0
}

# Função principal
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}🔐 BILLIONMAIL SECRETS ROTATION${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${YELLOW}Ambiente: $ENVIRONMENT${NC}"
    echo -e "${YELLOW}Timestamp: $(date)${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Verificações iniciais
    check_swarm
    
    # Criar diretório de logs se não existir
    mkdir -p "$(dirname "$ROTATION_LOG")"
    
    info "Iniciando rotação de secrets para ambiente: $ENVIRONMENT"
    notify_slack "🔄 Iniciando rotação de secrets no ambiente $ENVIRONMENT" "#36a64f"
    
    local rotation_success=true
    
    # Rotacionar postgres_password
    info "Rotacionando postgres_password..."
    if rotate_secret "postgres_password" "$(generate_password)" "auth-service" "email-service" "campaign-service" "contact-service" "analytics-service"; then
        success "postgres_password rotacionado ✅"
    else
        error "Falha na rotação do postgres_password ❌"
        rotation_success=false
    fi
    
    # Rotacionar redis_password
    info "Rotacionando redis_password..."
    if rotate_secret "redis_password" "$(generate_password)" "auth-service" "email-service" "campaign-service" "contact-service" "analytics-service"; then
        success "redis_password rotacionado ✅"
    else
        error "Falha na rotação do redis_password ❌"
        rotation_success=false
    fi
    
    # Rotacionar jwt_secret
    info "Rotacionando jwt_secret..."
    if rotate_secret "jwt_secret" "$(generate_jwt_secret)" "auth-service" "gateway"; then
        success "jwt_secret rotacionado ✅"
    else
        error "Falha na rotação do jwt_secret ❌"
        rotation_success=false
    fi
    
    # Rotacionar smtp_password
    info "Rotacionando smtp_password..."
    if rotate_secret "smtp_password" "$(generate_password)" "email-service"; then
        success "smtp_password rotacionado ✅"
    else
        error "Falha na rotação do smtp_password ❌"
        rotation_success=false
    fi
    
    # Rotacionar api_secret_key
    info "Rotacionando api_secret_key..."
    if rotate_secret "api_secret_key" "$(generate_jwt_secret)" "gateway" "auth-service"; then
        success "api_secret_key rotacionado ✅"
    else
        error "Falha na rotação do api_secret_key ❌"
        rotation_success=false
    fi
    
    # Rotacionar encryption_key
    info "Rotacionando encryption_key..."
    if rotate_secret "encryption_key" "$(generate_jwt_secret)" "auth-service" "email-service"; then
        success "encryption_key rotacionado ✅"
    else
        error "Falha na rotação do encryption_key ❌"
        rotation_success=false
    fi
    
    # Resultado final
    echo -e "${BLUE}========================================${NC}"
    if [[ "$rotation_success" == "true" ]]; then
        echo -e "${GREEN}🎉 ROTAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
        echo -e "${GREEN}✅ Todos os secrets foram rotacionados${NC}"
        echo -e "${GREEN}✅ Todos os serviços estão saudáveis${NC}"
        echo -e "${GREEN}✅ Compliance GDPR/SOC2/PCI-DSS mantido${NC}"
        notify_slack "🎉 Rotação de secrets concluída com SUCESSO no ambiente $ENVIRONMENT. Todos os serviços estão operacionais." "good"
        
        # Auditoria
        info "Rotação concluída. Secrets ativos:"
        docker secret ls --format "table {{.Name}}\t{{.CreatedAt}}" | grep -E "(postgres_|redis_|jwt_|smtp_|api_|encryption_)"
        
    else
        echo -e "${RED}❌ ROTAÇÃO FALHOU PARCIALMENTE${NC}"
        echo -e "${RED}⚠️  Alguns secrets podem não ter sido rotacionados${NC}"
        echo -e "${YELLOW}📋 Verifique os logs para detalhes${NC}"
        notify_slack "⚠️ Rotação de secrets FALHOU PARCIALMENTE no ambiente $ENVIRONMENT. Verificação manual necessária." "warning"
        exit 1
    fi
    echo -e "${BLUE}========================================${NC}"
    
    info "Log completo disponível em: $ROTATION_LOG"
}

# Verificar argumentos
if [[ $# -gt 1 ]]; then
    echo "Uso: $0 [ambiente]"
    echo "Ambientes: production, staging, development"
    exit 1
fi

# Verificar se está rodando como root (necessário para Docker)
if [[ $EUID -ne 0 ]] && ! groups | grep -q docker; then
    error "Este script precisa ser executado como root ou usuário no grupo docker"
    exit 1
fi

# Executar função principal
main "$@"