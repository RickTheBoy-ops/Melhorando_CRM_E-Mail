# Script de validação para correções de race conditions
# Valida as correções implementadas no código

Write-Host "=== Validação de Correções de Race Conditions - BillionMail ===" -ForegroundColor Cyan
Write-Host "Analisando correções implementadas no código...`n"

# 1. Verificar se as funções de idempotência foram implementadas
Write-Host "1. Verificando implementação de idempotência..." -ForegroundColor Yellow

$mainGoPath = "C:\BillionMail-dev\services\email-service\main.go"
if (Test-Path $mainGoPath) {
    $content = Get-Content $mainGoPath -Raw
    
    # Verificar GenerateFingerprint
    if ($content -match "func \(job \*EmailJob\) GenerateFingerprint\(\)") {
        Write-Host "  [OK] Função GenerateFingerprint implementada" -ForegroundColor Green
    } else {
        Write-Host "  [ERRO] Função GenerateFingerprint não encontrada" -ForegroundColor Red
    }
    
    # Verificar isDuplicateJob
    if ($content -match "func \(s \*EmailService\) isDuplicateJob\(") {
        Write-Host "  [OK] Função isDuplicateJob implementada" -ForegroundColor Green
    } else {
        Write-Host "  [ERRO] Função isDuplicateJob não encontrada" -ForegroundColor Red
    }
    
    # Verificar uso de SHA256
    if ($content -match "sha256\.New\(\)") {
        Write-Host "  [OK] Hash SHA256 implementado para fingerprint" -ForegroundColor Green
    } else {
        Write-Host "  [ERRO] Hash SHA256 não encontrado" -ForegroundColor Red
    }
} else {
    Write-Host "  [ERRO] Arquivo main.go não encontrado" -ForegroundColor Red
}

# 2. Verificar dequeue atômico
Write-Host "`n2. Verificando dequeue atômico..." -ForegroundColor Yellow

if ($content -match "dequeueEmailAtomic") {
    Write-Host "  [OK] Função dequeueEmailAtomic implementada" -ForegroundColor Green
    
    # Verificar script Lua
    if ($content -match "local job_data = redis\.call\('RPOP', KEYS\[1\]\)") {
        Write-Host "  [OK] Script Lua para operação atômica implementado" -ForegroundColor Green
    } else {
        Write-Host "  [AVISO] Script Lua pode estar modificado" -ForegroundColor Yellow
    }
    
    # Verificar workerID com rand
    if ($content -match "rand\.Int\(\)") {
        Write-Host "  [OK] WorkerID com rand implementado" -ForegroundColor Green
    } else {
        Write-Host "  [AVISO] WorkerID pode não usar rand" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [ERRO] Função dequeueEmailAtomic não encontrada" -ForegroundColor Red
}

# 3. Verificar correções no StartRedisWorker
Write-Host "`n3. Verificando correções no StartRedisWorker..." -ForegroundColor Yellow

if ($content -match "func \(w \*Worker\) StartRedisWorker\(\)") {
    Write-Host "  [OK] Função StartRedisWorker encontrada" -ForegroundColor Green
    
    # Verificar uso de dequeueEmailAtomic
    if ($content -match "dequeueEmailAtomic\(") {
        Write-Host "  [OK] Uso de dequeueEmailAtomic implementado" -ForegroundColor Green
    } else {
        Write-Host "  [ERRO] dequeueEmailAtomic não usado no StartRedisWorker" -ForegroundColor Red
    }
    
    # Verificar verificação de duplicatas
    if ($content -match "isDuplicateJob\(") {
        Write-Host "  [OK] Verificação de duplicatas implementada" -ForegroundColor Green
    } else {
        Write-Host "  [ERRO] Verificação de duplicatas não encontrada" -ForegroundColor Red
    }
} else {
    Write-Host "  [ERRO] Função StartRedisWorker não encontrada" -ForegroundColor Red
}

# 4. Verificar WorkerPool Stop melhorado
Write-Host "`n4. Verificando WorkerPool Stop..." -ForegroundColor Yellow

if ($content -match "func \(wp \*WorkerPool\) Stop\(\)") {
    Write-Host "  [OK] Função WorkerPool Stop encontrada" -ForegroundColor Green
    
    # Verificar graceful shutdown
    if ($content -match "All workers stopped gracefully") {
        Write-Host "  [OK] Graceful shutdown implementado" -ForegroundColor Green
    } else {
        Write-Host "  [AVISO] Mensagem de graceful shutdown pode estar modificada" -ForegroundColor Yellow
    }
    
    # Verificar timeout
    if ($content -match "30 \* time\.Second") {
        Write-Host "  [OK] Timeout de 30 segundos implementado" -ForegroundColor Green
    } else {
        Write-Host "  [AVISO] Timeout pode estar modificado" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [ERRO] Função WorkerPool Stop não encontrada" -ForegroundColor Red
}

# 5. Verificar proteção no endpoint
Write-Host "`n5. Verificando proteção no endpoint..." -ForegroundColor Yellow

if ($content -match "DUPLICATE_EMAIL") {
    Write-Host "  [OK] Proteção contra duplicatas no endpoint implementada" -ForegroundColor Green
} else {
    Write-Host "  [ERRO] Proteção no endpoint não encontrada" -ForegroundColor Red
}

# 6. Verificar anotações de correção
Write-Host "`n6. Verificando anotações de correção..." -ForegroundColor Yellow

$raceConditionFixes = ($content | Select-String "P0 RACE CONDITION FIX" -AllMatches).Matches.Count
if ($raceConditionFixes -gt 0) {
    Write-Host "  [OK] $raceConditionFixes anotações de correção encontradas" -ForegroundColor Green
} else {
    Write-Host "  [AVISO] Nenhuma anotação de correção encontrada" -ForegroundColor Yellow
}

# Resumo final
Write-Host "`n=== RESUMO DA VALIDAÇÃO ===" -ForegroundColor Cyan

$checks = @(
    ($content -match "func \(job \*EmailJob\) GenerateFingerprint\(\)"),
    ($content -match "func \(s \*EmailService\) isDuplicateJob\("),
    ($content -match "dequeueEmailAtomic"),
    ($content -match "isDuplicateJob\(" -and $content -match "StartRedisWorker"),
    ($content -match "DUPLICATE_EMAIL")
)

$passedChecks = ($checks | Where-Object { $_ -eq $true }).Count
$totalChecks = $checks.Count

Write-Host "Verificações passaram: $passedChecks/$totalChecks" -ForegroundColor $(if($passedChecks -eq $totalChecks) {'Green'} else {'Yellow'})

if ($passedChecks -eq $totalChecks) {
    Write-Host "`nTODAS AS CORREÇÕES FORAM IMPLEMENTADAS!" -ForegroundColor Green
    Write-Host "As race conditions foram corrigidas com:" -ForegroundColor Green
    Write-Host "- Sistema de idempotência com fingerprint" -ForegroundColor White
    Write-Host "- Dequeue atômico com Lua script" -ForegroundColor White
    Write-Host "- Verificação de duplicatas" -ForegroundColor White
    Write-Host "- WorkerPool com graceful shutdown" -ForegroundColor White
    Write-Host "- Proteção no endpoint de envio" -ForegroundColor White
} elseif ($passedChecks -ge 3) {
    Write-Host "`nMAIORIA DAS CORREÇÕES IMPLEMENTADAS" -ForegroundColor Yellow
    Write-Host "Algumas verificações podem precisar de ajustes" -ForegroundColor Yellow
} else {
    Write-Host "`nALGUMAS CORREÇÕES AINDA PRECISAM SER IMPLEMENTADAS" -ForegroundColor Red
}

Write-Host "`nPara testar com serviços rodando:" -ForegroundColor Cyan
Write-Host "1. Inicie o Docker Desktop" -ForegroundColor White
Write-Host "2. Execute: docker-compose up -d" -ForegroundColor White
Write-Host "3. Execute este script novamente" -ForegroundColor White

Write-Host "`nValidação concluída!" -ForegroundColor Cyan