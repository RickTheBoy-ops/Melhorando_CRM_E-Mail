# Estratégia de Containerização e Orquestração - BillionMail

## Visão Geral

Este documento define a estratégia completa de containerização e orquestração para o BillionMail, focando em segurança, escalabilidade e alta disponibilidade.

## 1. Arquitetura de Containers

### 1.1 Estrutura de Microserviços

```yaml
# Estrutura de containers proposta
services:
  - api-gateway          # Nginx + Kong/Istio
  - auth-service         # Serviço de autenticação
  - core-service         # Lógica principal do BillionMail
  - smtp-service         # Processamento SMTP
  - imap-service         # Processamento IMAP
  - pop3-service         # Processamento POP3
  - message-processor    # Processamento de mensagens
  - storage-service      # Gerenciamento de armazenamento
  - monitoring-service   # Monitoramento e métricas
  - security-scanner     # Scanner de segurança
```

### 1.2 Base Images Seguras

```dockerfile
# Exemplo de Dockerfile base seguro
FROM gcr.io/distroless/go:nonroot

# Usar usuário não-root
USER nonroot:nonroot

# Configurações de segurança
LABEL security.scan="enabled"
LABEL security.policy="strict"

# Health checks
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["./healthcheck"]
```

## 2. Kubernetes Configuration

### 2.1 Namespace Strategy

```yaml
# namespaces.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: billionmail-prod
  labels:
    security-policy: strict
    network-policy: isolated
---
apiVersion: v1
kind: Namespace
metadata:
  name: billionmail-staging
  labels:
    security-policy: moderate
---
apiVersion: v1
kind: Namespace
metadata:
  name: billionmail-dev
  labels:
    security-policy: permissive
```

### 2.2 Security Policies

```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: billionmail-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

### 2.3 Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: billionmail-network-policy
  namespace: billionmail-prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: billionmail-prod
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: billionmail-prod
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
```

## 3. Service Mesh (Istio)

### 3.1 Istio Configuration

```yaml
# istio-gateway.yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: billionmail-gateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: billionmail-tls
    hosts:
    - "*.billionmail.com"
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: billionmail-vs
spec:
  hosts:
  - "api.billionmail.com"
  gateways:
  - billionmail-gateway
  http:
  - match:
    - uri:
        prefix: "/api/v1/"
    route:
    - destination:
        host: api-gateway
        port:
          number: 8080
```

### 3.2 mTLS Configuration

```yaml
# mtls-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: billionmail-prod
spec:
  mtls:
    mode: STRICT
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: billionmail-authz
  namespace: billionmail-prod
spec:
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/billionmail-prod/sa/api-gateway"]
    to:
    - operation:
        methods: ["GET", "POST"]
```

## 4. Container Security

### 4.1 Image Scanning

```yaml
# .github/workflows/security-scan.yml
name: Container Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build image
      run: docker build -t billionmail:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'billionmail:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
```

### 4.2 Runtime Security

```yaml
# falco-rules.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
  namespace: falco-system
data:
  billionmail_rules.yaml: |
    - rule: Unauthorized Process in BillionMail Container
      desc: Detect unauthorized process execution
      condition: >
        spawned_process and
        container and
        k8s.ns.name="billionmail-prod" and
        not proc.name in (billionmail, healthcheck)
      output: >
        Unauthorized process in BillionMail container
        (user=%user.name command=%proc.cmdline container=%container.name)
      priority: WARNING
```

## 5. Monitoring e Observabilidade

### 5.1 Prometheus Configuration

```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    scrape_configs:
    - job_name: 'billionmail-services'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
          - billionmail-prod
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
```

### 5.2 Grafana Dashboards

```json
{
  "dashboard": {
    "title": "BillionMail - Container Metrics",
    "panels": [
      {
        "title": "Container CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(container_cpu_usage_seconds_total{namespace=\"billionmail-prod\"}[5m])",
            "legendFormat": "{{pod}}"
          }
        ]
      },
      {
        "title": "Container Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "container_memory_usage_bytes{namespace=\"billionmail-prod\"}",
            "legendFormat": "{{pod}}"
          }
        ]
      }
    ]
  }
}
```

## 6. Deployment Strategy

### 6.1 Blue-Green Deployment

```yaml
# blue-green-deployment.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: billionmail-api
spec:
  replicas: 5
  strategy:
    blueGreen:
      activeService: billionmail-api-active
      previewService: billionmail-api-preview
      autoPromotionEnabled: false
      scaleDownDelaySeconds: 30
      prePromotionAnalysis:
        templates:
        - templateName: success-rate
        args:
        - name: service-name
          value: billionmail-api-preview
      postPromotionAnalysis:
        templates:
        - templateName: success-rate
        args:
        - name: service-name
          value: billionmail-api-active
  selector:
    matchLabels:
      app: billionmail-api
  template:
    metadata:
      labels:
        app: billionmail-api
    spec:
      containers:
      - name: billionmail-api
        image: billionmail/api:latest
        ports:
        - containerPort: 8080
```

### 6.2 Canary Deployment

```yaml
# canary-deployment.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: billionmail-core
spec:
  replicas: 10
  strategy:
    canary:
      steps:
      - setWeight: 10
      - pause: {duration: 1m}
      - setWeight: 20
      - pause: {duration: 1m}
      - setWeight: 50
      - pause: {duration: 2m}
      - setWeight: 100
      analysis:
        templates:
        - templateName: success-rate
        - templateName: latency
        args:
        - name: service-name
          value: billionmail-core
```

## 7. Backup e Disaster Recovery

### 7.1 Velero Configuration

```yaml
# velero-backup.yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: billionmail-daily-backup
  namespace: velero
spec:
  schedule: "0 2 * * *"
  template:
    includedNamespaces:
    - billionmail-prod
    storageLocation: aws-s3
    ttl: 720h0m0s
---
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: aws-s3
  namespace: velero
spec:
  provider: aws
  objectStorage:
    bucket: billionmail-backups
    prefix: kubernetes
  config:
    region: us-west-2
```

## 8. Auto-scaling

### 8.1 Horizontal Pod Autoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: billionmail-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: billionmail-api
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

### 8.2 Vertical Pod Autoscaler

```yaml
# vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: billionmail-core-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: billionmail-core
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: billionmail-core
      maxAllowed:
        cpu: 2
        memory: 4Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

## 9. CI/CD Pipeline

### 9.1 GitOps com ArgoCD

```yaml
# argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: billionmail-prod
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/billionmail/k8s-manifests
    targetRevision: HEAD
    path: overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: billionmail-prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

### 9.2 Pipeline de Build

```yaml
# .github/workflows/build-deploy.yml
name: Build and Deploy
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
    
    - name: Login to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Build and push
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: |
          ghcr.io/billionmail/api:latest
          ghcr.io/billionmail/api:${{ github.sha }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
    
    - name: Update manifest
      run: |
        sed -i 's|ghcr.io/billionmail/api:.*|ghcr.io/billionmail/api:${{ github.sha }}|' k8s/overlays/production/kustomization.yaml
        git config --local user.email "action@github.com"
        git config --local user.name "GitHub Action"
        git add k8s/overlays/production/kustomization.yaml
        git commit -m "Update image tag to ${{ github.sha }}"
        git push
```

## 10. Implementação Faseada

### Fase 1: Containerização Básica (Semanas 1-2)
- Containerizar serviços existentes
- Implementar health checks
- Configurar registry privado

### Fase 2: Orquestração Kubernetes (Semanas 3-4)
- Deploy em cluster Kubernetes
- Configurar namespaces e RBAC
- Implementar network policies

### Fase 3: Service Mesh e Segurança (Semanas 5-6)
- Implementar Istio
- Configurar mTLS
- Implementar políticas de segurança

### Fase 4: Observabilidade e CI/CD (Semanas 7-8)
- Configurar monitoring completo
- Implementar GitOps
- Configurar auto-scaling

## Conclusão

Esta estratégia de containerização e orquestração fornece uma base sólida para o BillionMail, garantindo segurança, escalabilidade e alta disponibilidade através de práticas modernas de DevOps e cloud-native technologies.