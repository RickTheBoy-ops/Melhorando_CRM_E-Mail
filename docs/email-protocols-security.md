# Melhorias de Segurança nos Protocolos de Email

## Visão Geral

Este documento especifica as melhorias de segurança para os protocolos SMTP, IMAP e POP3 no BillionMail, implementando as melhores práticas de segurança e conformidade com padrões modernos.

## SMTP (Simple Mail Transfer Protocol) - Melhorias

### 1. Configuração Segura do Postfix

```bash
# /etc/postfix/main.cf - Configuração Hardened

# TLS/SSL Configuration
smtpd_tls_security_level = encrypt
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, SRP, CAMELLIA, SEED
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high

# Certificate Configuration
smtpd_tls_cert_file = /etc/ssl/certs/mail.crt
smtpd_tls_key_file = /etc/ssl/private/mail.key
smtpd_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtpd_tls_dh1024_param_file = /etc/ssl/certs/dh2048.pem
smtpd_tls_dh512_param_file = /etc/ssl/certs/dh512.pem

# SMTP Authentication
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous
smtpd_sasl_mechanism_filter = !gssapi, !login, !anonymous
smtpd_sasl_authenticated_header = yes

# Rate Limiting and Anti-Abuse
smtpd_client_connection_count_limit = 10
smtpd_client_connection_rate_limit = 30
smtpd_client_message_rate_limit = 100
smtpd_client_recipient_rate_limit = 200
smtpd_client_event_limit_exceptions = ${mynetworks}

# Recipient Restrictions
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    permit

# Header Checks
header_checks = regexp:/etc/postfix/header_checks
mime_header_checks = regexp:/etc/postfix/mime_header_checks
nested_header_checks = regexp:/etc/postfix/nested_header_checks
body_checks = regexp:/etc/postfix/body_checks

# Message Size Limits
message_size_limit = 52428800  # 50MB
mailbox_size_limit = 1073741824  # 1GB

# DANE Support
smtp_dns_support_level = dnssec
smtp_tls_security_level = dane
smtp_tls_dane_insecure_mx_policy = may
```

### 2. MTA-STS (Mail Transfer Agent Strict Transport Security)

```yaml
# mta-sts.txt configuration
version: STSv1
mode: enforce
max_age: 604800
mx: mail.billionmail.com
mx: backup.billionmail.com
```

```go
// internal/service/email/mta_sts.go
package email

import (
    "context"
    "fmt"
    "net/http"
    "time"
)

type MTASTSService struct {
    domain     string
    policy     *MTASTSPolicy
    httpClient *http.Client
}

type MTASTSPolicy struct {
    Version string   `json:"version"`
    Mode    string   `json:"mode"`
    MaxAge  int      `json:"max_age"`
    MX      []string `json:"mx"`
}

func (m *MTASTSService) GeneratePolicy() string {
    return fmt.Sprintf(`version: %s
mode: %s
max_age: %d
%s`,
        m.policy.Version,
        m.policy.Mode,
        m.policy.MaxAge,
        m.formatMXRecords(),
    )
}

func (m *MTASTSService) ValidateIncomingConnection(ctx context.Context, senderDomain string) error {
    // Verificar se o domínio remetente suporta MTA-STS
    policy, err := m.fetchMTASTSPolicy(senderDomain)
    if err != nil {
        return fmt.Errorf("failed to fetch MTA-STS policy: %w", err)
    }

    if policy.Mode == "enforce" {
        // Validar que a conexão está usando TLS
        if !m.isConnectionSecure(ctx) {
            return fmt.Errorf("MTA-STS policy violation: insecure connection")
        }
    }

    return nil
}
```

### 3. DKIM, SPF e DMARC Avançados

```go
// internal/service/email/authentication.go
package email

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "strings"
)

type EmailAuthenticator struct {
    dkimSigner   *DKIMSigner
    spfValidator *SPFValidator
    dmarcPolicy  *DMARCPolicy
}

type DKIMSigner struct {
    domain     string
    selector   string
    privateKey *rsa.PrivateKey
    algorithm  string
}

func (d *DKIMSigner) SignMessage(message []byte, headers []string) (string, error) {
    // Implementação de assinatura DKIM com algoritmo RSA-SHA256
    canonicalizedHeaders := d.canonicalizeHeaders(message, headers)
    canonicalizedBody := d.canonicalizeBody(message)
    
    bodyHash := d.hashBody(canonicalizedBody)
    
    dkimHeader := fmt.Sprintf(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=",
        d.domain,
        d.selector,
        strings.Join(headers, ":"),
        bodyHash,
    )
    
    signature, err := d.signData(canonicalizedHeaders + dkimHeader)
    if err != nil {
        return "", err
    }
    
    return dkimHeader + signature, nil
}

type SPFValidator struct {
    dnsResolver DNSResolver
}

func (s *SPFValidator) ValidateSPF(senderIP, domain string) (*SPFResult, error) {
    spfRecord, err := s.dnsResolver.LookupTXT(domain)
    if err != nil {
        return &SPFResult{Result: "temperror"}, err
    }
    
    for _, record := range spfRecord {
        if strings.HasPrefix(record, "v=spf1") {
            return s.evaluateSPFRecord(record, senderIP, domain)
        }
    }
    
    return &SPFResult{Result: "none"}, nil
}

type DMARCPolicy struct {
    Policy      string `json:"p"`
    SubPolicy   string `json:"sp,omitempty"`
    Alignment   string `json:"adkim,omitempty"`
    SPFAlignment string `json:"aspf,omitempty"`
    Percentage  int    `json:"pct,omitempty"`
    ReportURI   string `json:"rua,omitempty"`
    ForensicURI string `json:"ruf,omitempty"`
}

func (d *DMARCPolicy) EvaluateMessage(dkimResult, spfResult *AuthResult) *DMARCResult {
    // Implementar lógica de avaliação DMARC
    aligned := d.checkAlignment(dkimResult, spfResult)
    
    result := &DMARCResult{
        Policy:    d.Policy,
        Aligned:   aligned,
        Action:    d.determineAction(aligned),
    }
    
    return result
}
```

## IMAP (Internet Message Access Protocol) - Melhorias

### 1. Configuração Segura do Dovecot

```bash
# /etc/dovecot/conf.d/10-ssl.conf
ssl = required
ssl_cert = </etc/ssl/certs/mail.crt
ssl_key = </etc/ssl/private/mail.key
ssl_ca = </etc/ssl/certs/ca-certificates.crt
ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1
ssl_cipher_list = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/ssl/certs/dh2048.pem

# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login oauthbearer xoauth2
auth_policy_server_url = http://localhost:8080/auth/policy
auth_policy_server_api_header = Authorization: Bearer <token>
auth_policy_hash_nonce = <random_string>

# Rate limiting
auth_policy_request_attributes = login=%{requested_username} pwhash=%{hashed_password} remote=%{rip} device_id=%{client_id}
auth_failure_delay = 2 secs
auth_policy_reject_on_fail = yes

# /etc/dovecot/conf.d/20-imap.conf
protocol imap {
  mail_plugins = $mail_plugins imap_quota imap_acl notify replication
  imap_client_workarounds = delay-newmail tb-extra-mailbox-sep tb-lsub-flags
  imap_idle_notify_interval = 2 mins
  imap_max_line_length = 64k
  
  # Security settings
  imap_capability = +XLIST +SPECIAL-USE +NAMESPACE
  imap_metadata = yes
}
```

### 2. OAuth 2.0 Authentication para IMAP

```go
// internal/service/email/imap_oauth.go
package email

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "strings"
    "time"
)

type IMAPOAuthHandler struct {
    tokenValidator *TokenValidator
    userStore      *UserStore
}

type OAuthToken struct {
    AccessToken  string    `json:"access_token"`
    TokenType    string    `json:"token_type"`
    ExpiresIn    int       `json:"expires_in"`
    RefreshToken string    `json:"refresh_token"`
    Scope        string    `json:"scope"`
    IssuedAt     time.Time `json:"issued_at"`
}

func (h *IMAPOAuthHandler) HandleXOAUTH2(ctx context.Context, authData string) (*AuthResult, error) {
    // Decodificar dados de autenticação XOAUTH2
    decoded, err := base64.StdEncoding.DecodeString(authData)
    if err != nil {
        return nil, fmt.Errorf("invalid base64 encoding: %w", err)
    }
    
    // Parse do formato XOAUTH2
    parts := strings.Split(string(decoded), "\x01")
    if len(parts) < 2 {
        return nil, fmt.Errorf("invalid XOAUTH2 format")
    }
    
    authString := parts[0]
    token := h.extractTokenFromAuthString(authString)
    
    // Validar token OAuth
    claims, err := h.tokenValidator.ValidateAccessToken(token)
    if err != nil {
        return nil, fmt.Errorf("token validation failed: %w", err)
    }
    
    // Verificar escopo necessário para IMAP
    if !h.hasRequiredScope(claims.Scope, "mail.read") {
        return nil, fmt.Errorf("insufficient scope for IMAP access")
    }
    
    user, err := h.userStore.GetByID(claims.UserID)
    if err != nil {
        return nil, fmt.Errorf("user not found: %w", err)
    }
    
    return &AuthResult{
        Success:  true,
        UserID:   user.ID,
        Username: user.Username,
        Scope:    claims.Scope,
    }, nil
}

func (h *IMAPOAuthHandler) HandleOAuthBearer(ctx context.Context, token string) (*AuthResult, error) {
    // Validar token Bearer
    claims, err := h.tokenValidator.ValidateAccessToken(token)
    if err != nil {
        return nil, fmt.Errorf("bearer token validation failed: %w", err)
    }
    
    // Verificar se o token não expirou
    if time.Now().After(claims.ExpiresAt) {
        return nil, fmt.Errorf("token expired")
    }
    
    user, err := h.userStore.GetByID(claims.UserID)
    if err != nil {
        return nil, fmt.Errorf("user not found: %w", err)
    }
    
    return &AuthResult{
        Success:  true,
        UserID:   user.ID,
        Username: user.Username,
        Scope:    claims.Scope,
    }, nil
}
```

### 3. Criptografia de Mensagens em Repouso

```go
// internal/service/email/encryption.go
package email

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "io"
)

type MessageEncryption struct {
    keyDerivation *KeyDerivation
    gcm          cipher.AEAD
}

type EncryptedMessage struct {
    Nonce      []byte `json:"nonce"`
    Ciphertext []byte `json:"ciphertext"`
    KeyID      string `json:"key_id"`
    Algorithm  string `json:"algorithm"`
}

func NewMessageEncryption(masterKey []byte) (*MessageEncryption, error) {
    block, err := aes.NewCipher(masterKey)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    return &MessageEncryption{
        keyDerivation: NewKeyDerivation(),
        gcm:          gcm,
    }, nil
}

func (me *MessageEncryption) EncryptMessage(userID string, message []byte) (*EncryptedMessage, error) {
    // Derivar chave específica do usuário
    userKey := me.keyDerivation.DeriveUserKey(userID)
    
    // Gerar nonce aleatório
    nonce := make([]byte, me.gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    
    // Criptografar mensagem
    ciphertext := me.gcm.Seal(nil, nonce, message, nil)
    
    return &EncryptedMessage{
        Nonce:      nonce,
        Ciphertext: ciphertext,
        KeyID:      me.keyDerivation.GetKeyID(userID),
        Algorithm:  "AES-256-GCM",
    }, nil
}

func (me *MessageEncryption) DecryptMessage(userID string, encrypted *EncryptedMessage) ([]byte, error) {
    // Verificar se temos a chave correta
    if encrypted.KeyID != me.keyDerivation.GetKeyID(userID) {
        return nil, fmt.Errorf("key mismatch")
    }
    
    // Derivar chave do usuário
    userKey := me.keyDerivation.DeriveUserKey(userID)
    
    // Descriptografar
    plaintext, err := me.gcm.Open(nil, encrypted.Nonce, encrypted.Ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }
    
    return plaintext, nil
}

type KeyDerivation struct {
    masterKey []byte
    salt      []byte
}

func (kd *KeyDerivation) DeriveUserKey(userID string) []byte {
    h := sha256.New()
    h.Write(kd.masterKey)
    h.Write([]byte(userID))
    h.Write(kd.salt)
    return h.Sum(nil)
}
```

## POP3 - Melhorias de Segurança

### 1. Configuração Segura POP3

```bash
# /etc/dovecot/conf.d/20-pop3.conf
protocol pop3 {
  mail_plugins = $mail_plugins
  pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
  pop3_uidl_format = %08Xu%08Xv
  pop3_fast_size_lookups = yes
  pop3_lock_session = yes
  
  # Security settings
  pop3_enable_last = no
  pop3_reuse_xuidl = yes
  pop3_save_uidl = yes
}

# Disable insecure POP3 (port 110)
service pop3-login {
  inet_listener pop3 {
    port = 0
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
```

### 2. Rate Limiting e Proteção contra Ataques

```go
// internal/service/email/pop3_security.go
package email

import (
    "context"
    "fmt"
    "sync"
    "time"
)

type POP3SecurityManager struct {
    rateLimiter    *RateLimiter
    failureTracker *FailureTracker
    ipBlocklist    *IPBlocklist
}

type RateLimiter struct {
    connections map[string]*ConnectionInfo
    mutex       sync.RWMutex
    maxConn     int
    timeWindow  time.Duration
}

type ConnectionInfo struct {
    Count     int
    FirstSeen time.Time
    LastSeen  time.Time
    Blocked   bool
}

func (rl *RateLimiter) AllowConnection(clientIP string) bool {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    now := time.Now()
    info, exists := rl.connections[clientIP]
    
    if !exists {
        rl.connections[clientIP] = &ConnectionInfo{
            Count:     1,
            FirstSeen: now,
            LastSeen:  now,
            Blocked:   false,
        }
        return true
    }
    
    // Reset counter if time window passed
    if now.Sub(info.FirstSeen) > rl.timeWindow {
        info.Count = 1
        info.FirstSeen = now
        info.Blocked = false
    } else {
        info.Count++
    }
    
    info.LastSeen = now
    
    if info.Count > rl.maxConn {
        info.Blocked = true
        return false
    }
    
    return !info.Blocked
}

type FailureTracker struct {
    failures map[string]*FailureInfo
    mutex    sync.RWMutex
}

type FailureInfo struct {
    Count      int
    LastFailed time.Time
    BlockUntil time.Time
}

func (ft *FailureTracker) RecordFailure(clientIP string) {
    ft.mutex.Lock()
    defer ft.mutex.Unlock()
    
    now := time.Now()
    info, exists := ft.failures[clientIP]
    
    if !exists {
        ft.failures[clientIP] = &FailureInfo{
            Count:      1,
            LastFailed: now,
        }
        return
    }
    
    info.Count++
    info.LastFailed = now
    
    // Progressive blocking
    switch {
    case info.Count >= 10:
        info.BlockUntil = now.Add(24 * time.Hour)
    case info.Count >= 5:
        info.BlockUntil = now.Add(1 * time.Hour)
    case info.Count >= 3:
        info.BlockUntil = now.Add(15 * time.Minute)
    }
}

func (ft *FailureTracker) IsBlocked(clientIP string) bool {
    ft.mutex.RLock()
    defer ft.mutex.RUnlock()
    
    info, exists := ft.failures[clientIP]
    if !exists {
        return false
    }
    
    return time.Now().Before(info.BlockUntil)
}
```

## Monitoramento e Alertas

### 1. Métricas de Segurança

```go
// internal/service/monitoring/email_security.go
package monitoring

import (
    "context"
    "time"
    "github.com/prometheus/client_golang/prometheus"
)

type EmailSecurityMetrics struct {
    authFailures    prometheus.Counter
    tlsConnections  prometheus.Counter
    spamDetected    prometheus.Counter
    virusDetected   prometheus.Counter
    rateLimitHits   prometheus.Counter
    dkimFailures    prometheus.Counter
    spfFailures     prometheus.Counter
    dmarcFailures   prometheus.Counter
}

func NewEmailSecurityMetrics() *EmailSecurityMetrics {
    return &EmailSecurityMetrics{
        authFailures: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_auth_failures_total",
            Help: "Total number of authentication failures",
        }),
        tlsConnections: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_tls_connections_total",
            Help: "Total number of TLS connections",
        }),
        spamDetected: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_spam_detected_total",
            Help: "Total number of spam messages detected",
        }),
        virusDetected: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_virus_detected_total",
            Help: "Total number of virus messages detected",
        }),
        rateLimitHits: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_rate_limit_hits_total",
            Help: "Total number of rate limit hits",
        }),
        dkimFailures: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_dkim_failures_total",
            Help: "Total number of DKIM validation failures",
        }),
        spfFailures: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_spf_failures_total",
            Help: "Total number of SPF validation failures",
        }),
        dmarcFailures: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "email_dmarc_failures_total",
            Help: "Total number of DMARC validation failures",
        }),
    }
}
```

### 2. Alertas de Segurança

```yaml
# prometheus/alerts/email-security.yml
groups:
- name: email-security
  rules:
  - alert: HighAuthenticationFailureRate
    expr: rate(email_auth_failures_total[5m]) > 10
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate detected"
      description: "Authentication failure rate is {{ $value }} failures per second"
  
  - alert: TLSConnectionDrop
    expr: rate(email_tls_connections_total[5m]) < 0.8 * rate(email_tls_connections_total[1h] offset 1h)
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Significant drop in TLS connections"
      description: "TLS connection rate has dropped significantly"
  
  - alert: SpamSurge
    expr: rate(email_spam_detected_total[5m]) > 50
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Spam surge detected"
      description: "Spam detection rate is {{ $value }} messages per second"
  
  - alert: VirusDetected
    expr: increase(email_virus_detected_total[5m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Virus detected in email"
      description: "{{ $value }} virus(es) detected in the last 5 minutes"
```

Essas melhorias nos protocolos de email garantem comunicação segura, autenticação robusta e proteção contra ameaças modernas, estabelecendo uma base sólida para a segurança do sistema de email corporativo.