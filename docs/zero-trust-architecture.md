# Zero Trust Architecture para BillionMail

## Visão Geral

A implementação de Zero Trust Architecture (ZTA) no BillionMail segue o princípio "nunca confie, sempre verifique", garantindo que cada componente, usuário e dispositivo seja continuamente autenticado e autorizado.

## Componentes Principais da ZTA

### 1. Policy Engine (PE)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-engine-config
data:
  policies.yaml: |
    policies:
      - name: "email-access"
        subjects:
          - type: "user"
            attributes:
              - "authenticated"
              - "mfa_verified"
        resources:
          - type: "mailbox"
            actions: ["read", "write", "delete"]
        conditions:
          - "time_of_day < 22:00"
          - "location_trusted == true"
          - "device_compliance == true"
      
      - name: "admin-access"
        subjects:
          - type: "user"
            roles: ["admin"]
        resources:
          - type: "system"
            actions: ["configure", "monitor"]
        conditions:
          - "source_ip in trusted_networks"
          - "session_duration < 8h"
```

### 2. Policy Decision Point (PDP)

```go
// internal/service/ztrust/pdp.go
package ztrust

import (
    "context"
    "time"
    "github.com/open-policy-agent/opa/rego"
)

type PolicyDecisionPoint struct {
    engine *rego.Rego
    cache  *PolicyCache
}

type AccessRequest struct {
    Subject   Subject   `json:"subject"`
    Resource  Resource  `json:"resource"`
    Action    string    `json:"action"`
    Context   Context   `json:"context"`
}

type Subject struct {
    ID          string            `json:"id"`
    Type        string            `json:"type"`
    Attributes  map[string]string `json:"attributes"`
    Roles       []string          `json:"roles"`
}

type Resource struct {
    ID         string            `json:"id"`
    Type       string            `json:"type"`
    Attributes map[string]string `json:"attributes"`
}

type Context struct {
    Time        time.Time         `json:"time"`
    Location    string            `json:"location"`
    DeviceID    string            `json:"device_id"`
    NetworkInfo NetworkInfo       `json:"network_info"`
}

type NetworkInfo struct {
    SourceIP    string `json:"source_ip"`
    UserAgent   string `json:"user_agent"`
    TLSVersion  string `json:"tls_version"`
}

func (pdp *PolicyDecisionPoint) Evaluate(ctx context.Context, req AccessRequest) (*Decision, error) {
    // Verificar cache primeiro
    if decision := pdp.cache.Get(req); decision != nil {
        return decision, nil
    }

    // Avaliar políticas usando OPA
    input := map[string]interface{}{
        "subject":  req.Subject,
        "resource": req.Resource,
        "action":   req.Action,
        "context":  req.Context,
    }

    results, err := pdp.engine.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return nil, err
    }

    decision := &Decision{
        Allow:     results.Allowed(),
        Reason:    results.Reason(),
        TTL:       time.Minute * 5,
        Timestamp: time.Now(),
    }

    // Cache da decisão
    pdp.cache.Set(req, decision)
    
    return decision, nil
}
```

### 3. Policy Enforcement Point (PEP)

```go
// internal/middleware/ztrust_enforcement.go
package middleware

import (
    "context"
    "net/http"
    "github.com/gofiber/fiber/v2"
    "billionmail-core/internal/service/ztrust"
)

type ZTrustEnforcement struct {
    pdp *ztrust.PolicyDecisionPoint
    contextExtractor *ContextExtractor
}

func NewZTrustEnforcement(pdp *ztrust.PolicyDecisionPoint) *ZTrustEnforcement {
    return &ZTrustEnforcement{
        pdp: pdp,
        contextExtractor: NewContextExtractor(),
    }
}

func (zte *ZTrustEnforcement) Enforce() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Extrair contexto da requisição
        ctx := zte.contextExtractor.Extract(c)
        
        // Construir requisição de acesso
        accessReq := ztrust.AccessRequest{
            Subject:  ctx.Subject,
            Resource: ctx.Resource,
            Action:   ctx.Action,
            Context:  ctx.RequestContext,
        }

        // Avaliar política
        decision, err := zte.pdp.Evaluate(c.Context(), accessReq)
        if err != nil {
            return c.Status(500).JSON(fiber.Map{
                "error": "Policy evaluation failed",
            })
        }

        if !decision.Allow {
            return c.Status(403).JSON(fiber.Map{
                "error": "Access denied",
                "reason": decision.Reason,
            })
        }

        // Log da decisão para auditoria
        zte.logAccess(accessReq, decision)
        
        return c.Next()
    }
}
```

### 4. Identity Verification Service

```go
// internal/service/identity/verification.go
package identity

import (
    "context"
    "crypto/x509"
    "time"
)

type VerificationService struct {
    certStore    *CertificateStore
    tokenService *TokenService
    mfaService   *MFAService
}

type VerificationResult struct {
    Verified     bool              `json:"verified"`
    Identity     *Identity         `json:"identity"`
    TrustLevel   TrustLevel        `json:"trust_level"`
    Attributes   map[string]string `json:"attributes"`
    ExpiresAt    time.Time         `json:"expires_at"`
}

type TrustLevel int

const (
    TrustLevelNone TrustLevel = iota
    TrustLevelLow
    TrustLevelMedium
    TrustLevelHigh
    TrustLevelCritical
)

func (vs *VerificationService) VerifyIdentity(ctx context.Context, req *VerificationRequest) (*VerificationResult, error) {
    result := &VerificationResult{
        Verified:   false,
        TrustLevel: TrustLevelNone,
        Attributes: make(map[string]string),
    }

    // 1. Verificar certificado mTLS
    if req.ClientCert != nil {
        if err := vs.verifyCertificate(req.ClientCert); err != nil {
            return result, err
        }
        result.TrustLevel = TrustLevelLow
        result.Attributes["cert_verified"] = "true"
    }

    // 2. Verificar token JWT
    if req.Token != "" {
        claims, err := vs.tokenService.ValidateToken(req.Token)
        if err != nil {
            return result, err
        }
        result.Identity = claims.Identity
        result.TrustLevel = TrustLevelMedium
        result.Attributes["token_verified"] = "true"
    }

    // 3. Verificar MFA se necessário
    if vs.requiresMFA(result.Identity) {
        if req.MFAToken == "" {
            result.Attributes["mfa_required"] = "true"
            return result, nil
        }
        
        if !vs.mfaService.Verify(result.Identity.ID, req.MFAToken) {
            return result, errors.New("MFA verification failed")
        }
        
        result.TrustLevel = TrustLevelHigh
        result.Attributes["mfa_verified"] = "true"
    }

    // 4. Verificar contexto do dispositivo
    deviceTrust := vs.evaluateDeviceTrust(req.DeviceContext)
    if deviceTrust == TrustLevelCritical {
        result.TrustLevel = TrustLevelCritical
    }

    result.Verified = result.TrustLevel >= TrustLevelMedium
    result.ExpiresAt = time.Now().Add(time.Hour)
    
    return result, nil
}
```

### 5. Continuous Monitoring

```go
// internal/service/monitoring/continuous.go
package monitoring

import (
    "context"
    "time"
)

type ContinuousMonitor struct {
    riskEngine    *RiskEngine
    alertManager  *AlertManager
    sessionStore  *SessionStore
}

type RiskScore struct {
    Score       float64           `json:"score"`
    Level       RiskLevel         `json:"level"`
    Factors     []RiskFactor      `json:"factors"`
    Timestamp   time.Time         `json:"timestamp"`
}

type RiskFactor struct {
    Type        string  `json:"type"`
    Weight      float64 `json:"weight"`
    Description string  `json:"description"`
}

func (cm *ContinuousMonitor) MonitorSession(ctx context.Context, sessionID string) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            session := cm.sessionStore.Get(sessionID)
            if session == nil {
                return
            }

            // Calcular score de risco atual
            riskScore := cm.riskEngine.CalculateRisk(session)
            
            // Verificar se o risco aumentou significativamente
            if riskScore.Level >= RiskLevelHigh {
                cm.handleHighRisk(session, riskScore)
            }

            // Atualizar score na sessão
            session.RiskScore = riskScore
            cm.sessionStore.Update(session)
        }
    }
}

func (cm *ContinuousMonitor) handleHighRisk(session *Session, risk RiskScore) {
    switch risk.Level {
    case RiskLevelHigh:
        // Requerer re-autenticação
        cm.requireReauth(session)
    case RiskLevelCritical:
        // Terminar sessão imediatamente
        cm.terminateSession(session)
        cm.alertManager.SendAlert(AlertTypeSecurity, 
            "Critical risk detected for session", session)
    }
}
```

## Implementação de Microsegmentação

### Network Policies (Kubernetes)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: billionmail-microsegmentation
spec:
  podSelector:
    matchLabels:
      app: billionmail
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - podSelector:
        matchLabels:
          app: monitoring
    ports:
    - protocol: TCP
      port: 9090
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

### Service Mesh (Istio)

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: billionmail-authz
spec:
  selector:
    matchLabels:
      app: billionmail-core
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/billionmail/sa/api-gateway"]
  - to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/v1/*"]
  - when:
    - key: source.certificate_fingerprint
      values: ["sha256:1234567890abcdef..."]
```

## Implementação de Least Privilege

### RBAC Granular

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: billionmail-email-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["email-credentials"]
  verbs: ["get"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: billionmail-email-reader-binding
subjects:
- kind: ServiceAccount
  name: email-service
  namespace: billionmail
roleRef:
  kind: Role
  name: billionmail-email-reader
  apiGroup: rbac.authorization.k8s.io
```

### Just-in-Time Access

```go
// internal/service/access/jit.go
package access

import (
    "context"
    "time"
)

type JITAccessManager struct {
    approvalEngine *ApprovalEngine
    accessStore    *AccessStore
}

type AccessRequest struct {
    UserID      string        `json:"user_id"`
    Resource    string        `json:"resource"`
    Permission  string        `json:"permission"`
    Duration    time.Duration `json:"duration"`
    Justification string      `json:"justification"`
}

func (jam *JITAccessManager) RequestAccess(ctx context.Context, req AccessRequest) (*AccessGrant, error) {
    // Validar requisição
    if err := jam.validateRequest(req); err != nil {
        return nil, err
    }

    // Verificar se precisa de aprovação
    if jam.requiresApproval(req) {
        approval, err := jam.approvalEngine.RequestApproval(ctx, req)
        if err != nil {
            return nil, err
        }
        
        if !approval.Approved {
            return nil, errors.New("Access request denied")
        }
    }

    // Conceder acesso temporário
    grant := &AccessGrant{
        UserID:     req.UserID,
        Resource:   req.Resource,
        Permission: req.Permission,
        ExpiresAt:  time.Now().Add(req.Duration),
        GrantedAt:  time.Now(),
    }

    if err := jam.accessStore.Store(grant); err != nil {
        return nil, err
    }

    // Agendar revogação automática
    jam.scheduleRevocation(grant)
    
    return grant, nil
}
```

## Monitoramento e Auditoria

### Logging Estruturado

```go
// internal/service/audit/logger.go
package audit

import (
    "context"
    "encoding/json"
    "time"
)

type AuditEvent struct {
    Timestamp   time.Time         `json:"timestamp"`
    EventType   string            `json:"event_type"`
    UserID      string            `json:"user_id"`
    Resource    string            `json:"resource"`
    Action      string            `json:"action"`
    Result      string            `json:"result"`
    Context     map[string]string `json:"context"`
    RiskScore   float64           `json:"risk_score"`
}

type AuditLogger struct {
    output chan AuditEvent
}

func (al *AuditLogger) LogAccess(ctx context.Context, event AuditEvent) {
    event.Timestamp = time.Now()
    
    // Enriquecer com contexto adicional
    event.Context["source_ip"] = getSourceIP(ctx)
    event.Context["user_agent"] = getUserAgent(ctx)
    event.Context["session_id"] = getSessionID(ctx)
    
    select {
    case al.output <- event:
    default:
        // Log buffer cheio - evento crítico
        panic("Audit log buffer full")
    }
}
```

## Configuração de Deployment

### Helm Chart

```yaml
# charts/billionmail-ztrust/values.yaml
ztrust:
  enabled: true
  
  policyEngine:
    image: openpolicyagent/opa:latest
    replicas: 3
    resources:
      requests:
        memory: "256Mi"
        cpu: "100m"
      limits:
        memory: "512Mi"
        cpu: "500m"
  
  identityService:
    image: billionmail/identity-service:latest
    replicas: 2
    mfa:
      enabled: true
      providers:
        - totp
        - webauthn
    
  monitoring:
    enabled: true
    riskThresholds:
      low: 0.3
      medium: 0.6
      high: 0.8
      critical: 0.9
    
  certificates:
    autoRotation: true
    rotationInterval: "720h" # 30 days
```

Esta implementação de Zero Trust Architecture fornece uma base sólida para a segurança do BillionMail, garantindo verificação contínua, microsegmentação efetiva e princípios de menor privilégio em toda a infraestrutura.