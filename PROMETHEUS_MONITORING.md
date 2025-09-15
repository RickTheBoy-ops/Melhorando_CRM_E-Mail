# Prometheus Monitoring Guide

This document provides examples of Prometheus queries and alerts for monitoring the BillionMail microservices.

## Available Metrics

### Auth Service Metrics (Port 8001)

- `auth_request_duration_seconds` - Histogram of request durations
- `auth_registrations_total` - Counter of user registrations
- `auth_token_validations_total` - Counter of token validations
- `auth_logins_total` - Counter of login attempts

### Email Service Metrics (Port 8002)

- `email_processing_duration_seconds` - Histogram of email processing times
- `email_sent_total` - Counter of emails sent
- `email_failed_total` - Counter of failed emails
- `email_queue_size` - Gauge of current queue size

## Prometheus Queries Examples

### Request Rate Monitoring

```promql
# Auth service request rate (requests per second)
rate(auth_request_duration_seconds_count[5m])

# Email service processing rate
rate(email_processing_duration_seconds_count[5m])
```

### Latency Monitoring

```promql
# 95th percentile response time for auth service
histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m]))

# 99th percentile email processing time
histogram_quantile(0.99, rate(email_processing_duration_seconds_bucket[5m]))

# Average response time
rate(auth_request_duration_seconds_sum[5m]) / rate(auth_request_duration_seconds_count[5m])
```

### Error Rate Monitoring

```promql
# Email failure rate
rate(email_failed_total[5m]) / rate(email_sent_total[5m]) * 100

# Registration success rate
rate(auth_registrations_total[5m])
```

### Queue Monitoring

```promql
# Current email queue size
email_queue_size

# Queue growth rate
deriv(email_queue_size[5m])
```

### Service Health

```promql
# Service uptime (assuming up metric exists)
up{job="auth-service"}
up{job="email-service"}

# Request volume by service
sum(rate(auth_request_duration_seconds_count[5m])) by (instance)
sum(rate(email_processing_duration_seconds_count[5m])) by (instance)
```

## Alert Rules

### High Latency Alerts

```yaml
groups:
- name: billionmail_latency
  rules:
  - alert: AuthServiceHighLatency
    expr: histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m])) > 0.5
    for: 2m
    labels:
      severity: warning
      service: auth-service
    annotations:
      summary: "Auth service high latency detected"
      description: "95th percentile latency is {{ $value }}s for auth service"

  - alert: EmailServiceHighLatency
    expr: histogram_quantile(0.95, rate(email_processing_duration_seconds_bucket[5m])) > 2.0
    for: 2m
    labels:
      severity: warning
      service: email-service
    annotations:
      summary: "Email service high processing time"
      description: "95th percentile email processing time is {{ $value }}s"
```

### Error Rate Alerts

```yaml
- name: billionmail_errors
  rules:
  - alert: HighEmailFailureRate
    expr: rate(email_failed_total[5m]) / rate(email_sent_total[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
      service: email-service
    annotations:
      summary: "High email failure rate detected"
      description: "Email failure rate is {{ $value | humanizePercentage }} over the last 5 minutes"

  - alert: AuthServiceDown
    expr: up{job="auth-service"} == 0
    for: 1m
    labels:
      severity: critical
      service: auth-service
    annotations:
      summary: "Auth service is down"
      description: "Auth service has been down for more than 1 minute"
```

### Queue Alerts

```yaml
- name: billionmail_queues
  rules:
  - alert: EmailQueueBacklog
    expr: email_queue_size > 1000
    for: 5m
    labels:
      severity: warning
      service: email-service
    annotations:
      summary: "Email queue backlog detected"
      description: "Email queue size is {{ $value }} messages"

  - alert: EmailQueueGrowthRate
    expr: deriv(email_queue_size[10m]) > 50
    for: 5m
    labels:
      severity: warning
      service: email-service
    annotations:
      summary: "Email queue growing rapidly"
      description: "Email queue is growing at {{ $value }} messages per minute"
```

### Resource Usage Alerts

```yaml
- name: billionmail_resources
  rules:
  - alert: HighRequestRate
    expr: rate(auth_request_duration_seconds_count[5m]) > 100
    for: 2m
    labels:
      severity: warning
      service: auth-service
    annotations:
      summary: "High request rate on auth service"
      description: "Auth service is receiving {{ $value }} requests per second"
```

## Grafana Dashboard Queries

### Request Rate Panel
```promql
sum(rate(auth_request_duration_seconds_count[5m])) by (instance)
sum(rate(email_processing_duration_seconds_count[5m])) by (instance)
```

### Response Time Panel
```promql
histogram_quantile(0.50, rate(auth_request_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(auth_request_duration_seconds_bucket[5m]))
```

### Service Status Panel
```promql
up{job=~"auth-service|email-service"}
```

## Correlation ID Tracing

With structured logging enabled, you can trace requests across services using correlation IDs:

```bash
# Search logs by correlation ID
docker logs email-service | jq 'select(.correlation_id == "abc-123-def")'
docker logs auth-service | jq 'select(.correlation_id == "abc-123-def")'
```

## Log Analysis Queries

### Error Log Analysis
```bash
# Count errors by service
docker logs auth-service | jq 'select(.level == "error")' | wc -l
docker logs email-service | jq 'select(.level == "error")' | wc -l

# Get recent errors with context
docker logs auth-service --since 1h | jq 'select(.level == "error") | {time, message, correlation_id}'
```

### Performance Analysis
```bash
# Analyze request durations
docker logs auth-service | jq 'select(.duration) | .duration' | sort -n

# Find slow requests
docker logs auth-service | jq 'select(.duration and (.duration | tonumber) > 1000)'
```

## Setup Instructions

1. **Start Services with Monitoring**:
   ```bash
   # Auth Service
   LOG_LEVEL=info LOG_FORMAT=json go run . # Port 8001
   
   # Email Service  
   LOG_LEVEL=info LOG_FORMAT=json go run . # Port 8002
   ```

2. **Configure Prometheus** (`prometheus.yml`):
   ```yaml
   scrape_configs:
     - job_name: 'auth-service'
       static_configs:
         - targets: ['localhost:8001']
       metrics_path: '/metrics'
       scrape_interval: 15s
   
     - job_name: 'email-service'
       static_configs:
         - targets: ['localhost:8002']
       metrics_path: '/metrics'
       scrape_interval: 15s
   ```

3. **Test Metrics Endpoints**:
   ```bash
   curl http://localhost:8001/metrics
   curl http://localhost:8002/metrics
   ```

4. **Test Health Endpoints**:
   ```bash
   curl http://localhost:8001/health
   curl http://localhost:8002/health
   ```

## Troubleshooting

- **No metrics appearing**: Check if services are running and `/metrics` endpoints are accessible
- **Missing correlation IDs**: Ensure `LOG_FORMAT=json` environment variable is set
- **High memory usage**: Consider adjusting histogram buckets in metric definitions
- **Alert fatigue**: Tune alert thresholds based on baseline performance metrics

## Best Practices

1. **Metric Naming**: Follow Prometheus naming conventions (snake_case, descriptive suffixes)
2. **Label Usage**: Use labels for dimensions but avoid high cardinality
3. **Alert Tuning**: Start with loose thresholds and tighten based on observed behavior
4. **Dashboard Design**: Group related metrics and use consistent time ranges
5. **Log Correlation**: Always include correlation IDs in structured logs for traceability