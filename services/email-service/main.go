package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Configuração global do logrus
func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	level := os.Getenv("LOG_LEVEL")
	if level == "debug" {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}

type EmailService struct {
	smtpPool       *SMTPPool
	redisClient    *redis.Client
	metrics        *Metrics
	workerPool     *WorkerPool
	rateLimiter    *RateLimiter
	circuitBreaker *CircuitBreaker
	templates      map[string]*EmailTemplate
	templatesMu    sync.RWMutex
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rateLimit int
	burst     int
}

type CircuitBreaker struct {
	failureCount    int
	lastFailureTime time.Time
	state          string // "closed", "open", "half-open"
	mu             sync.RWMutex
	failureThreshold int
	timeout         time.Duration
}

type SMTPPool struct {
	host     string
	port     string
	username string
	password string
	pool     chan *smtp.Client
	mu       sync.Mutex
	maxConns int
}

// P0 RACE CONDITION FIX: Thread-safe WorkerPool
type WorkerPool struct {
	jobQueue    chan EmailJob
	workerQueue chan chan EmailJob
	workers     []*Worker
	maxWorkers  int
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
	running     bool
}

type Worker struct {
	id          int
	jobChannel  chan EmailJob
	workerQueue chan chan EmailJob
	quitChan    chan bool
	service     *EmailService
}

type EmailJob struct {
	ID            string            `json:"id"`
	CorrelationID string            `json:"correlation_id"`
	To            []string          `json:"to"`
	From          string            `json:"from"`
	Subject       string            `json:"subject"`
	Body          string            `json:"body"`
	HTMLBody      string            `json:"html_body,omitempty"`
	Template      string            `json:"template,omitempty"`
	TemplateData  map[string]interface{} `json:"template_data,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Attachments   []Attachment      `json:"attachments,omitempty"`
	Priority      int               `json:"priority"`
	ScheduledAt   *time.Time        `json:"scheduled_at,omitempty"`
	RetryCount    int               `json:"retry_count"`
	MaxRetries    int               `json:"max_retries"`
	CreatedAt     time.Time         `json:"created_at"`
	NextRetry     time.Time         `json:"next_retry"`
	FailureReason string            `json:"failure_reason"`
	FailedAt      time.Time         `json:"failed_at"`
	Status        string            `json:"status"`
}

// P0 RACE CONDITION FIX: Idempotency with job fingerprint
func (job *EmailJob) GenerateFingerprint() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s-%s-%s",
		strings.Join(job.To, ","),
		job.Subject,
		job.Body)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

type EmailTemplate struct {
	Name        string `json:"name"`
	Subject     string `json:"subject"`
	HTMLContent string `json:"html_content"`
	TextContent string `json:"text_content"`
}

type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
}

type BulkEmailRequest struct {
	Emails    []EmailJob `json:"emails" binding:"required"`
	BatchSize int        `json:"batch_size,omitempty"`
}

type EmailResponse struct {
	JobID     string `json:"job_id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	QueuedAt  int64  `json:"queued_at"`
}

type Metrics struct {
	emailsSent       prometheus.Counter
	emailsFailed     prometheus.Counter
	emailsQueued     prometheus.Counter
	processingTime   prometheus.Histogram
	queueSize        prometheus.Gauge
	smtpConnections  prometheus.Gauge
	retryAttempts    prometheus.Counter
}

// P0 RACE CONDITION FIX: Redis Distributed Lock Implementation
type DistributedLock struct {
	redis *redis.Client
	key   string
	value string
	ttl   time.Duration
}

func NewDistributedLock(redisClient *redis.Client, key, value string, ttl time.Duration) *DistributedLock {
	return &DistributedLock{
		redis: redisClient,
		key:   key,
		value: value,
		ttl:   ttl,
	}
}

func (dl *DistributedLock) Acquire() bool {
	ctx := context.Background()
	result := dl.redis.SetNX(ctx, dl.key, dl.value, dl.ttl)
	return result.Val()
}

func (dl *DistributedLock) Release() error {
	ctx := context.Background()
	// Lua script para release atômico - só remove se o valor for o nosso
	script := `if redis.call("get",KEYS[1]) == ARGV[1] then return redis.call("del",KEYS[1]) else return 0 end`
	result := dl.redis.Eval(ctx, script, []string{dl.key}, dl.value)
	return result.Err()
}

func (dl *DistributedLock) Extend(newTTL time.Duration) error {
	ctx := context.Background()
	// Lua script para estender TTL apenas se o lock ainda for nosso
	script := `if redis.call("get",KEYS[1]) == ARGV[1] then return redis.call("expire",KEYS[1],ARGV[2]) else return 0 end`
	result := dl.redis.Eval(ctx, script, []string{dl.key}, dl.value, int(newTTL.Seconds()))
	return result.Err()
}

// P0 SECURITY FIX: Docker Secrets Management Functions
// Eliminates hardcoded credentials vulnerability
func readSecret(secretFile string) (string, error) {
	if secretFile == "" {
		return "", fmt.Errorf("secret file path not provided")
	}
	
	content, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %w", err)
	}
	
	return strings.TrimSpace(string(content)), nil
}

func getSecureEnv(envVar, secretFile string) (string, error) {
	// Priority 1: Docker Secret (production)
	if secretFile != "" {
		if secret, readErr := readSecret(secretFile); readErr == nil {
			return secret, nil
		}
	}
	
	// Priority 2: Environment variable (development)
	if val := os.Getenv(envVar); val != "" && !strings.HasPrefix(val, "CHANGE_ME") {
		return val, nil
	}
	
	return "", fmt.Errorf("no secure credential found for %s", envVar)
}

// Helper function to get environment variable as integer with default value
func getEnvAsInt(envVar string, defaultValue int) int {
	if val := os.Getenv(envVar); val != "" {
		if intVal, parseErr := strconv.Atoi(val); parseErr == nil {
			return intVal
		}
	}
	return defaultValue
}

func NewRateLimiter(rateLimit, burst int) *RateLimiter {
	return &RateLimiter{
		limiters:  make(map[string]*rate.Limiter),
		rateLimit: rateLimit,
		burst:     burst,
	}
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		limiter = rate.NewLimiter(rate.Limit(rl.rateLimit), rl.burst)
		rl.limiters[key] = limiter
		rl.mu.Unlock()
	}

	return limiter
}

func (rl *RateLimiter) Allow(key string) bool {
	return rl.getLimiter(key).Allow()
}

func (rl *RateLimiter) extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "unknown"
	}
	return strings.ToLower(parts[1])
}

func NewCircuitBreaker(failureThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            "closed",
		failureThreshold: failureThreshold,
		timeout:          timeout,
	}
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "open" {
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = "half-open"
			cb.failureCount = 0
		} else {
			return fmt.Errorf("circuit breaker is open")
		}
	}

	err := fn()
	if err != nil {
		cb.failureCount++
		cb.lastFailureTime = time.Now()
		if cb.failureCount >= cb.failureThreshold {
			cb.state = "open"
		}
		return err
	}

	if cb.state == "half-open" {
		cb.state = "closed"
	}
	cb.failureCount = 0
	return nil
}

func NewMetrics() *Metrics {
	m := &Metrics{
		emailsSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "emails_sent_total",
			Help: "Total number of emails sent successfully",
		}),
		emailsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "emails_failed_total",
			Help: "Total number of emails that failed to send",
		}),
		emailsQueued: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "emails_queued_total",
			Help: "Total number of emails queued for sending",
		}),
		processingTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "email_processing_duration_seconds",
			Help:    "Time taken to process and send an email",
			Buckets: prometheus.DefBuckets,
		}),
		queueSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "email_queue_size",
			Help: "Current number of emails in the queue",
		}),
		smtpConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_connections_active",
			Help: "Number of active SMTP connections",
		}),
		retryAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "email_retry_attempts_total",
			Help: "Total number of email retry attempts",
		}),
	}

	// Register metrics
	prometheus.MustRegister(m.emailsSent)
	prometheus.MustRegister(m.emailsFailed)
	prometheus.MustRegister(m.emailsQueued)
	prometheus.MustRegister(m.processingTime)
	prometheus.MustRegister(m.queueSize)
	prometheus.MustRegister(m.smtpConnections)
	prometheus.MustRegister(m.retryAttempts)

	return m
}

func NewSMTPPool(host, port, username, password string, maxConns int) *SMTPPool {
	return &SMTPPool{
		host:     host,
		port:     port,
		username: username,
		password: password,
		pool:     make(chan *smtp.Client, maxConns),
		maxConns: maxConns,
	}
}

func (p *SMTPPool) Get() (*smtp.Client, error) {
	select {
	case client := <-p.pool:
		return client, nil
	default:
		// Create new connection
		auth := smtp.PlainAuth("", p.username, p.password, p.host)
		client, err := smtp.Dial(p.host + ":" + p.port)
		if err != nil {
			return nil, err
		}
		if err := client.Auth(auth); err != nil {
			client.Close()
			return nil, err
		}
		return client, nil
	}
}

func (p *SMTPPool) Put(client *smtp.Client) {
	select {
	case p.pool <- client:
		// Successfully returned to pool
	default:
		// Pool is full, close the connection
		client.Close()
	}
}

func NewWorkerPool(maxWorkers int, service *EmailService) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		jobQueue:    make(chan EmailJob, maxWorkers*10),
		workerQueue: make(chan chan EmailJob, maxWorkers),
		maxWorkers:  maxWorkers,
		ctx:         ctx,
		cancel:      cancel,
		wg:          sync.WaitGroup{},
		mu:          sync.RWMutex{},
		running:     false,
	}
}

func (wp *WorkerPool) Start(service *EmailService) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	
	if wp.running {
		logrus.WithFields(logrus.Fields{
		"component": "worker_pool",
		"status":    "already_running",
	}).Warn("WorkerPool already running")
		return
	}
	
	wp.running = true
	
	// Start workers
	for i := 0; i < wp.maxWorkers; i++ {
		worker := &Worker{
			id:          i + 1,
			jobChannel:  make(chan EmailJob),
			workerQueue: wp.workerQueue,
			quitChan:    make(chan bool),
			service:     service,
		}
		wp.workers = append(wp.workers, worker)
		
		// Adicionar ao WaitGroup antes de iniciar goroutine
		wp.wg.Add(1)
		go func(w *Worker) {
			defer wp.wg.Done()
			w.StartRedisWorker()
		}(worker)
	}

	// Start dispatcher
	wp.wg.Add(1)
	go func() {
		defer wp.wg.Done()
		wp.dispatch()
	}()
	
	logrus.WithFields(logrus.Fields{
		"component":    "worker_pool",
		"max_workers":  wp.maxWorkers,
		"status":       "started",
	}).Info("WorkerPool started")
}

func (wp *WorkerPool) dispatch() {
	for {
		select {
		case job := <-wp.jobQueue:
			// Get available worker
			go func(job EmailJob) {
				workerJobQueue := <-wp.workerQueue
				workerJobQueue <- job
			}(job)
		case <-wp.ctx.Done():
			return
		}
	}
}

func (wp *WorkerPool) AddJob(job EmailJob) {
	wp.jobQueue <- job
}

// P0 RACE CONDITION FIX: Proper WorkerPool synchronization
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	
	if !wp.running {
		logrus.WithFields(logrus.Fields{
			"component": "worker_pool",
			"status":    "already_stopped",
		}).Warn("WorkerPool already stopped")
		return
	}
	
	logrus.WithFields(logrus.Fields{
		"component": "worker_pool",
		"action":    "stopping",
		"workers":   len(wp.workers),
	}).Info("Stopping WorkerPool gracefully")
	
	// Fechar canal de jobs para sinalizar parada
	close(wp.jobQueue)
	
	// Parar todos os workers
	for _, worker := range wp.workers {
		worker.Stop()
	}
	
	// Aguardar todos workers terminarem gracefully
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		logrus.WithFields(logrus.Fields{
			"component": "worker_pool",
			"status":    "stopped_gracefully",
		}).Info("All workers stopped gracefully")
	case <-time.After(30 * time.Second):
		logrus.WithFields(logrus.Fields{
			"component": "worker_pool",
			"status":    "timeout_forced_shutdown",
		}).Warn("Force stopping workers after timeout")
	}
	
	wp.running = false
}

func (w *Worker) Start() {
	go func() {
		for {
			// Register worker in the worker queue
			w.workerQueue <- w.jobChannel

			select {
			case job := <-w.jobChannel:
				// Process the job
				w.processEmail(job)
			case <-w.quitChan:
				return
			}
		}
	}()
}

// P0 RACE CONDITION FIX: Optimized worker loop with atomic processing
func (w *Worker) StartRedisWorker() {
	go func() {
		for {
			select {
			case <-w.quitChan:
				logrus.WithFields(logrus.Fields{
					"component": "worker",
					"worker_id": w.id,
					"action":    "shutting_down",
				}).Info("Worker shutting down gracefully")
				return
			default:
				// Novo padrão: dequeue atômico com processamento em goroutine
				job, _ := w.service.dequeueEmailAtomic("email_queue")
				if job != nil {
					go w.processJobAtomic(*job)
				} else {
					// Tentar retry queue se main queue vazia
					retryJob, _ := w.service.dequeueEmailAtomic("retry_queue")
					if retryJob != nil {
						// Check if it's time to retry
						if time.Now().After(retryJob.NextRetry) {
							go w.processJobAtomic(*retryJob)
						} else {
							// Put back in retry queue
							w.service.enqueueEmail(*retryJob, "retry_queue")
							w.service.releaseJobLock(retryJob.ID)
						}
					} else {
						// Sleep otimizado conforme especificação
						time.Sleep(50 * time.Millisecond)
					}
				}
			}
		}
	}()
}

func (w *Worker) Stop() {
	go func() {
		w.quitChan <- true
	}()
}

// P0 RACE CONDITION FIX: Processamento atômico com todas as verificações de segurança
func (w *Worker) processJobAtomic(job EmailJob) {
	start := time.Now()
	defer func() {
		w.service.metrics.processingTime.Observe(time.Since(start).Seconds())
		// SEMPRE liberar job lock no final
		if err := w.service.releaseJobLock(job.ID); err != nil {
			logrus.WithFields(logrus.Fields{
				"component": "worker",
				"worker_id": w.id,
				"job_id":    job.ID,
				"error":     err.Error(),
			}).Warn("Failed to release job lock")
		}
	}()

	// 1. Confirmar que o lock já foi adquirido
	ctx := context.Background()
	lockKey := fmt.Sprintf("job_processing:%s", job.ID)
	lockExists := w.service.redisClient.Exists(ctx, lockKey).Val()
	if lockExists == 0 {
		logrus.WithFields(logrus.Fields{
			"component": "worker",
			"worker_id": w.id,
			"job_id":    job.ID,
		}).Warn("Job lock not found, skipping processing")
		return
	}

	// 2. Verificar se job já foi processado (idempotência)
	if w.service.isJobAlreadyProcessed(job.ID) {
		logrus.WithFields(logrus.Fields{
			"component": "worker",
			"worker_id": w.id,
			"job_id":    job.ID,
		}).Info("Job already processed, skipping")
		return
	}

	// 3. Verificar fingerprint para evitar duplicatas
	fingerprint := w.service.generateFingerprint(job)
	if w.service.isDuplicate(fingerprint) {
		logrus.WithFields(logrus.Fields{
			"component": "worker",
			"worker_id": w.id,
			"job_id":    job.ID,
			"fingerprint": fingerprint,
		}).Info("Duplicate email detected, skipping")
		return
	}

	// 4. Marcar status como "processing" via HSETNX
	if !w.service.setJobStatusIfNotExists(job.ID, "processing", "Email is being processed") {
		logrus.WithFields(logrus.Fields{
			"component": "worker",
			"worker_id": w.id,
			"job_id":    job.ID,
		}).Info("Job being processed by another worker, skipping")
		return
	}

	// 5. Marcar fingerprint como processado
	w.service.markProcessed(fingerprint)

	// 6. Processar o email
	w.processEmailInternal(job)
}

// P0 RACE CONDITION FIX: Safe email processing with lock cleanup


// P0 RACE CONDITION FIX: Lógica interna de processamento de email
func (w *Worker) processEmailInternal(job EmailJob) {
	// Check if email is scheduled for later
	if job.ScheduledAt != nil && job.ScheduledAt.After(time.Now()) {
		// Re-queue for later
		job.NextRetry = *job.ScheduledAt
		w.service.enqueueEmail(job, "retry_queue")
		w.service.updateJobStatusAtomic(job.ID, "scheduled", "Email rescheduled for later")
		return
	}

	// Use circuit breaker for SMTP operations
	err := w.service.circuitBreaker.Call(func() error {
		// Get SMTP client from pool
		client, err := w.service.smtpPool.Get()
		if err != nil {
			return fmt.Errorf("failed to get SMTP client: %w", err)
		}
		defer w.service.smtpPool.Put(client)

		w.service.metrics.smtpConnections.Inc()
		defer w.service.metrics.smtpConnections.Dec()

		// Send email
		return w.sendEmail(client, job)
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"component":      "worker",
			"worker_id":      w.id,
			"job_id":         job.ID,
			"correlation_id": job.CorrelationID,
			"to":             job.To,
			"subject":        job.Subject,
			"error":          err.Error(),
		}).Error("Failed to send email")
		w.service.metrics.emailsFailed.Inc()
		
		// Retry logic
		if job.RetryCount < job.MaxRetries {
			w.service.moveToRetryQueue(job)
			w.service.updateJobStatusAtomic(job.ID, "retrying", fmt.Sprintf("Retry %d/%d scheduled after error: %v", job.RetryCount+1, job.MaxRetries, err))
		} else {
			w.service.moveToFailedQueue(job, err.Error())
			w.service.updateJobStatusAtomic(job.ID, "failed", fmt.Sprintf("Max retries exceeded: %v", err))
		}
		return
	}

	w.service.metrics.emailsSent.Inc()
	logrus.WithFields(logrus.Fields{
		"component":      "worker",
		"worker_id":      w.id,
		"job_id":         job.ID,
		"correlation_id": job.CorrelationID,
		"to":             job.To,
		"subject":        job.Subject,
	}).Info("Successfully sent email")

	// Update job status in Redis
	w.service.updateJobStatusAtomic(job.ID, "sent", "Email sent successfully")
}

// Legacy function for backward compatibility
func (w *Worker) processEmail(job EmailJob) {
	w.processJobAtomic(job)
}

func (w *Worker) sendEmail(client *smtp.Client, job EmailJob) error {
	// Set sender
	if err := client.Mail(job.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, to := range job.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", to, err)
		}
	}

	// Get data writer
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer wc.Close()

	// Write email headers and body
	message := w.buildEmailMessage(job)
	if _, err := wc.Write([]byte(message)); err != nil {
		return fmt.Errorf("failed to write email data: %w", err)
	}

	return nil
}

func (w *Worker) buildEmailMessage(job EmailJob) string {
	message := fmt.Sprintf("From: %s\r\n", job.From)
	message += fmt.Sprintf("To: %s\r\n", job.To[0]) // Simplified for multiple recipients
	message += fmt.Sprintf("Subject: %s\r\n", job.Subject)
	message += "MIME-Version: 1.0\r\n"

	// Add custom headers
	for key, value := range job.Headers {
		message += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	if job.HTMLBody != "" {
		message += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
		message += job.HTMLBody
	} else {
		message += "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
		message += job.Body
	}

	return message
}



func NewEmailService() (*EmailService, error) {
	// =======================================================
	// SECURE REDIS CONNECTION - P0 VULNERABILITY FIX
	// =======================================================
	// 🔒 Using Docker Secrets for Redis credentials
	
	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	// Get Redis password securely from Docker Secret
	redisPassword, err := getSecureEnv("REDIS_PASSWORD", "/run/secrets/redis_password")
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"component": "redis_config",
			"error":     err.Error(),
			"warning":   "using_empty_password",
		}).Warn("Redis password not found, using empty password")
		redisPassword = ""
	}

	// =======================================================
	// REDIS CONNECTION POOL OPTIMIZATION - HIGH VOLUME
	// =======================================================
	// 🚀 Optimized Redis connection pool for high-volume email processing
	
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		
		// Connection Pool Settings
		PoolSize:        getEnvAsInt("REDIS_POOL_SIZE", 50),        // Max connections
		MinIdleConns:    getEnvAsInt("REDIS_MIN_IDLE", 10),         // Min idle connections
		
		// Connection Timeouts
		DialTimeout:     time.Duration(getEnvAsInt("REDIS_DIAL_TIMEOUT", 5)) * time.Second,
		ReadTimeout:     time.Duration(getEnvAsInt("REDIS_READ_TIMEOUT", 3)) * time.Second,
		WriteTimeout:    time.Duration(getEnvAsInt("REDIS_WRITE_TIMEOUT", 3)) * time.Second,
		
		// Connection Lifecycle
		MaxConnAge:      time.Duration(getEnvAsInt("REDIS_MAX_CONN_AGE", 300)) * time.Second,  // 5 min
		PoolTimeout:     time.Duration(getEnvAsInt("REDIS_POOL_TIMEOUT", 4)) * time.Second,
		IdleTimeout:     time.Duration(getEnvAsInt("REDIS_IDLE_TIMEOUT", 300)) * time.Second, // 5 min
		
		// Health Check
		IdleCheckFrequency: time.Duration(getEnvAsInt("REDIS_HEALTH_CHECK", 60)) * time.Second,
		
		// Retry Configuration
		MaxRetries:      getEnvAsInt("REDIS_MAX_RETRIES", 3),
		MinRetryBackoff: time.Duration(getEnvAsInt("REDIS_MIN_RETRY_BACKOFF", 8)) * time.Millisecond,
		MaxRetryBackoff: time.Duration(getEnvAsInt("REDIS_MAX_RETRY_BACKOFF", 512)) * time.Millisecond,
	})

	logrus.WithFields(logrus.Fields{
		"component": "redis_config",
		"security":  "docker_secrets_enabled",
		"addr":      redisAddr,
	}).Info("Redis configured securely with Docker Secrets")

	// Test Redis connection with pool stats
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Log Redis pool statistics
	poolStats := rdb.PoolStats()
	logrus.WithFields(logrus.Fields{
		"component":     "redis_pool",
		"status":        "connected",
		"pool_stats": map[string]interface{}{
			"hits":         poolStats.Hits,
			"misses":       poolStats.Misses,
			"timeouts":     poolStats.Timeouts,
			"total_conns":  poolStats.TotalConns,
			"idle_conns":   poolStats.IdleConns,
			"stale_conns":  poolStats.StaleConns,
		},
		"pool_config": map[string]interface{}{
			"pool_size":     getEnvAsInt("REDIS_POOL_SIZE", 50),
			"min_idle":      getEnvAsInt("REDIS_MIN_IDLE", 10),
			"max_idle":      getEnvAsInt("REDIS_MAX_IDLE", 20),
			"dial_timeout":  getEnvAsInt("REDIS_DIAL_TIMEOUT", 5),
			"read_timeout":  getEnvAsInt("REDIS_READ_TIMEOUT", 3),
			"write_timeout": getEnvAsInt("REDIS_WRITE_TIMEOUT", 3),
		},
	}).Info("Redis connection pool initialized successfully")

	// =======================================================
	// SECURE SMTP CONFIGURATION - P0 VULNERABILITY FIX
	// =======================================================
	// 🔒 Using Docker Secrets for SMTP credentials
	
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "postfix"
	}
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}
	
	// Get SMTP credentials securely from Docker Secrets
	smtpUser, err := getSecureEnv("SMTP_USER", "/run/secrets/smtp_user")
	if err != nil {
		// Fallback to default for development
		smtpUser = "noreply@billionmail.com"
		logrus.WithFields(logrus.Fields{
			"component": "smtp_config",
			"warning":   "using_fallback_user",
		}).Warn("SMTP user not found in secrets, using fallback")
	}
	
	smtpPass, err := getSecureEnv("SMTP_PASS", "/run/secrets/smtp_password")
	if err != nil {
		return nil, fmt.Errorf("SMTP password credential not found: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"component": "smtp_config",
		"user":      smtpUser,
		"host":      smtpHost,
		"port":      smtpPort,
		"security":  "docker_secrets_enabled",
	}).Info("SMTP configured securely with Docker Secrets")

	maxConns, _ := strconv.Atoi(os.Getenv("SMTP_MAX_CONNECTIONS"))
	if maxConns == 0 {
		maxConns = 10
	}

	maxWorkers, _ := strconv.Atoi(os.Getenv("MAX_WORKERS"))
	if maxWorkers == 0 {
		maxWorkers = 20
	}

	// Rate limiting configuration
	rateLimit, _ := strconv.Atoi(os.Getenv("RATE_LIMIT_PER_MINUTE"))
	if rateLimit == 0 {
		rateLimit = 60 // 60 emails per minute per domain
	}

	batchSize, _ := strconv.Atoi(os.Getenv("BATCH_SIZE"))
	if batchSize == 0 {
		batchSize = 100
	}

	// Circuit breaker configuration
	failureThreshold, _ := strconv.Atoi(os.Getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD"))
	if failureThreshold == 0 {
		failureThreshold = 5
	}

	circuitTimeout := 30 * time.Second
	if timeoutStr := os.Getenv("CIRCUIT_BREAKER_TIMEOUT"); timeoutStr != "" {
		if parsed, parseErr := time.ParseDuration(timeoutStr); parseErr == nil {
			circuitTimeout = parsed
		}
	}

	service := &EmailService{
		smtpPool:       NewSMTPPool(smtpHost, smtpPort, smtpUser, smtpPass, maxConns),
		redisClient:    rdb,
		metrics:        NewMetrics(),
		rateLimiter:    NewRateLimiter(rateLimit, rateLimit*2),
		circuitBreaker: NewCircuitBreaker(failureThreshold, circuitTimeout),
		templates:      make(map[string]*EmailTemplate),
	}

	// Load default templates
	service.loadDefaultTemplates()

	service.workerPool = NewWorkerPool(maxWorkers, service)
	service.workerPool.Start(service)

	return service, nil
}

// P0 RACE CONDITION FIX: Atomic job status operations
func (s *EmailService) updateJobStatusAtomic(jobID, status, message string) error {
	ctx := context.Background()
	statusKey := fmt.Sprintf("email_job:%s", jobID)
	
	// Lua script para update atômico de status
	script := `
		redis.call('HMSET', KEYS[1], 'status', ARGV[1], 'message', ARGV[2], 'updated_at', ARGV[3])
		redis.call('EXPIRE', KEYS[1], 86400)
		return 'OK'
	`
	
	result := s.redisClient.Eval(ctx, script, []string{statusKey}, status, message, time.Now().Unix())
	return result.Err()
}

func (s *EmailService) setJobStatusIfNotExists(jobID, status, message string) bool {
	ctx := context.Background()
	statusKey := fmt.Sprintf("email_job:%s", jobID)
	
	// Lua script para set status apenas se não existir
	script := `
		local exists = redis.call('EXISTS', KEYS[1])
		if exists == 0 then
			redis.call('HMSET', KEYS[1], 'status', ARGV[1], 'message', ARGV[2], 'updated_at', ARGV[3])
			redis.call('EXPIRE', KEYS[1], 86400)
			return 1
		else
			return 0
		end
	`
	
	result := s.redisClient.Eval(ctx, script, []string{statusKey}, status, message, time.Now().Unix())
	return result.Val().(int64) == 1
}

func (s *EmailService) getJobStatusValue(jobID string) (string, error) {
	ctx := context.Background()
	statusKey := fmt.Sprintf("email_job:%s", jobID)
	status := s.redisClient.HGet(ctx, statusKey, "status").Val()
	return status, nil
}

func (s *EmailService) releaseJobLock(jobID string) error {
	ctx := context.Background()
	lockKey := fmt.Sprintf("job_processing:%s", jobID)
	return s.redisClient.Del(ctx, lockKey).Err()
}

// P0 RACE CONDITION FIX: Duplicate job detection with fingerprint
func (s *EmailService) isDuplicateJob(job EmailJob) bool {
	fingerprint := job.GenerateFingerprint()
	key := fmt.Sprintf("email_fingerprint:%s", fingerprint)
	
	// Check se já processamos este email nas últimas 24h
	ctx := context.Background()
	exists := s.redisClient.Exists(ctx, key).Val()
	if exists > 0 {
		return true
	}
	
	// Marcar como processado
	s.redisClient.Set(ctx, key, "processed", 24*time.Hour)
	return false
}

// Legacy function for backward compatibility
func (s *EmailService) updateJobStatus(jobID, status, message string) {
	s.updateJobStatusAtomic(jobID, status, message)
}

func (s *EmailService) enqueueEmail(job EmailJob, queueName string) error {
	ctx := context.Background()
	jobData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	return s.redisClient.LPush(ctx, queueName, jobData).Err()
}

// P0 RACE CONDITION FIX: Atomic dequeue with distributed lock
func (s *EmailService) dequeueEmailAtomic(queueName string) (*EmailJob, error) {
	ctx := context.Background()
	
	// Lua script para operação atômica RPOP + SETNX com TTL em milissegundos
	script := `
		local data = redis.call('RPOP', KEYS[1])
		if not data then return nil end
		local job = cjson.decode(data)
		local lockKey = 'job_processing:' .. job.id
		if redis.call('SETNX', lockKey, ARGV[1]) == 1 then
			redis.call('PEXPIRE', lockKey, 300000)
			return data
		else
			redis.call('LPUSH', KEYS[1], data)
			return nil
		end
	`
	
	workerID := fmt.Sprintf("worker_%d_%d", time.Now().UnixNano(), rand.Int())
	result := s.redisClient.Eval(ctx, script, []string{queueName}, workerID)
	
	if result.Err() != nil || result.Val() == nil {
		return nil, nil // Sem job disponível
	}
	
	var job EmailJob
	err := json.Unmarshal([]byte(result.Val().(string)), &job)
	return &job, err
}



func (s *EmailService) moveToRetryQueue(job EmailJob) error {
	job.RetryCount++
	job.NextRetry = time.Now().Add(time.Duration(job.RetryCount*job.RetryCount) * time.Minute)
	return s.enqueueEmail(job, "retry_queue")
}

func (s *EmailService) moveToFailedQueue(job EmailJob, reason string) error {
	job.FailureReason = reason
	job.FailedAt = time.Now()
	return s.enqueueEmail(job, "failed_queue")
}

// Template functions
func (s *EmailService) loadDefaultTemplates() {
	s.templatesMu.Lock()
	defer s.templatesMu.Unlock()

	// Welcome template
	s.templates["welcome"] = &EmailTemplate{
		Name:    "welcome",
		Subject: "Welcome to {{.CompanyName}}!",
		HTMLContent: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h1 style="color: #2c3e50;">Welcome {{.UserName}}!</h1>
        <p>Thank you for joining {{.CompanyName}}. We're excited to have you on board!</p>
        <p>Your account has been successfully created with the email: <strong>{{.Email}}</strong></p>
        <div style="margin: 30px 0;">
            <a href="{{.LoginURL}}" style="background-color: #3498db; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px;">Get Started</a>
        </div>
        <p>If you have any questions, feel free to contact our support team.</p>
        <p>Best regards,<br>The {{.CompanyName}} Team</p>
    </div>
</body>
</html>`,
		TextContent: `Welcome {{.UserName}}!

Thank you for joining {{.CompanyName}}. We're excited to have you on board!

Your account has been successfully created with the email: {{.Email}}

Get started: {{.LoginURL}}

If you have any questions, feel free to contact our support team.

Best regards,
The {{.CompanyName}} Team`,
	}

	// Password reset template
	s.templates["password_reset"] = &EmailTemplate{
		Name:    "password_reset",
		Subject: "Reset Your Password - {{.CompanyName}}",
		HTMLContent: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h1 style="color: #e74c3c;">Password Reset Request</h1>
        <p>Hello {{.UserName}},</p>
        <p>We received a request to reset your password for your {{.CompanyName}} account.</p>
        <div style="margin: 30px 0;">
            <a href="{{.ResetURL}}" style="background-color: #e74c3c; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px;">Reset Password</a>
        </div>
        <p>This link will expire in {{.ExpirationTime}} minutes.</p>
        <p>If you didn't request this password reset, please ignore this email.</p>
        <p>Best regards,<br>The {{.CompanyName}} Team</p>
    </div>
</body>
</html>`,
		TextContent: `Password Reset Request

Hello {{.UserName}},

We received a request to reset your password for your {{.CompanyName}} account.

Reset your password: {{.ResetURL}}

This link will expire in {{.ExpirationTime}} minutes.

If you didn't request this password reset, please ignore this email.

Best regards,
The {{.CompanyName}} Team`,
	}
}

func (s *EmailService) renderTemplate(templateName string, data map[string]interface{}) (string, string, string, error) {
	s.templatesMu.RLock()
	tmpl, exists := s.templates[templateName]
	s.templatesMu.RUnlock()

	if !exists {
		return "", "", "", fmt.Errorf("template '%s' not found", templateName)
	}

	// Render subject
	subjectTmpl, err := template.New("subject").Parse(tmpl.Subject)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse subject template: %w", err)
	}
	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return "", "", "", fmt.Errorf("failed to render subject: %w", err)
	}

	// Render HTML content
	htmlTmpl, err := template.New("html").Parse(tmpl.HTMLContent)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse HTML template: %w", err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", "", fmt.Errorf("failed to render HTML: %w", err)
	}

	// Render text content
	textTmpl, err := template.New("text").Parse(tmpl.TextContent)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse text template: %w", err)
	}
	var textBuf bytes.Buffer
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return "", "", "", fmt.Errorf("failed to render text: %w", err)
	}

	return subjectBuf.String(), htmlBuf.String(), textBuf.String(), nil
}

// HTTP Handlers
func (s *EmailService) sendSingleEmail(c *gin.Context) {
	var job EmailJob
	if err := c.ShouldBindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	// Rate limiting by domain
	if len(job.To) > 0 {
		domain := s.rateLimiter.extractDomain(job.To[0])
		if !s.rateLimiter.Allow(domain) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": fmt.Sprintf("Rate limit exceeded for domain: %s", domain),
				"code":  "RATE_LIMIT_EXCEEDED",
				"retry_after": 60,
			})
			return
		}
	}

	// Process template if specified
	if job.Template != "" && job.TemplateData != nil {
		subject, htmlBody, textBody, err := s.renderTemplate(job.Template, job.TemplateData)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Template rendering failed: %v", err),
				"code":  "TEMPLATE_ERROR",
			})
			return
		}
		job.Subject = subject
		job.HTMLBody = htmlBody
		job.Body = textBody
	}

	// Set defaults
	if job.ID == "" {
		job.ID = fmt.Sprintf("email_%d", time.Now().UnixNano())
	}
	if job.MaxRetries == 0 {
		job.MaxRetries = 3
	}
	job.CreatedAt = time.Now()

	// P0 RACE CONDITION FIX: Check for duplicate emails
	if s.isDuplicateJob(job) {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Duplicate email detected",
			"code":  "DUPLICATE_EMAIL",
			"job_id": job.ID,
		})
		return
	}

	// Add to Redis queue
	job.Status = "queued"
	if err := s.enqueueEmail(job, "email_queue"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to queue email",
			"code":  "QUEUE_ERROR",
		})
		return
	}
	s.updateJobStatus(job.ID, "queued", "Email queued for processing")

	s.metrics.emailsQueued.Inc()
	s.metrics.queueSize.Inc()

	c.JSON(http.StatusAccepted, EmailResponse{
		JobID:    job.ID,
		Status:   "queued",
		Message:  "Email queued for processing",
		QueuedAt: time.Now().Unix(),
	})
}

func (s *EmailService) sendBulkEmails(c *gin.Context) {
	var req BulkEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	if req.BatchSize == 0 {
		req.BatchSize = 100
	}

	jobIDs := make([]string, 0, len(req.Emails))
	rateLimitedEmails := make([]string, 0)

	for i, job := range req.Emails {
		// Rate limiting by domain
		if len(job.To) > 0 {
			domain := s.rateLimiter.extractDomain(job.To[0])
			if !s.rateLimiter.Allow(domain) {
				rateLimitedEmails = append(rateLimitedEmails, domain)
				continue
			}
		}

		// Set defaults
		if job.ID == "" {
			job.ID = fmt.Sprintf("bulk_email_%d_%d", time.Now().UnixNano(), i)
		}
		if job.MaxRetries == 0 {
			job.MaxRetries = 3
		}
		job.CreatedAt = time.Now()

		job.Status = "queued"
		if err := s.enqueueEmail(job, "email_queue"); err != nil {
			logrus.WithFields(logrus.Fields{
		"component":      "email_service",
		"job_id":         job.ID,
		"correlation_id": job.CorrelationID,
		"to":             job.To,
		"subject":        job.Subject,
		"error":          err.Error(),
	}).Error("Failed to queue email")
			continue
		}
		s.updateJobStatus(job.ID, "queued", "Email queued for bulk processing")
		jobIDs = append(jobIDs, job.ID)
	}

	s.metrics.emailsQueued.Add(float64(len(jobIDs)))
	s.metrics.queueSize.Add(float64(len(jobIDs)))

	response := gin.H{
		"message":   fmt.Sprintf("Queued %d emails for processing", len(jobIDs)),
		"job_ids":   jobIDs,
		"queued_at": time.Now().Unix(),
	}

	if len(rateLimitedEmails) > 0 {
		response["rate_limited_domains"] = rateLimitedEmails
		response["rate_limited_count"] = len(rateLimitedEmails)
	}

	c.JSON(http.StatusAccepted, response)
}

func (s *EmailService) getJobStatus(c *gin.Context) {
	jobID := c.Param("id")
	if jobID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Job ID is required",
			"code":  "MISSING_JOB_ID",
		})
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("email_job:%s", jobID)
	
	result := s.redisClient.HGetAll(ctx, key)
	if result.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get job status",
			"code":  "REDIS_ERROR",
		})
		return
	}

	jobData := result.Val()
	if len(jobData) == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Job not found",
			"code":  "JOB_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, jobData)
}

// P0 RACE CONDITION FIX: Verificação de status idempotente
func (s *EmailService) isJobAlreadyProcessed(jobID string) bool {
	ctx := context.Background()
	statusKey := fmt.Sprintf("email_job:%s", jobID)
	existing := s.redisClient.HGet(ctx, statusKey, "status").Val()
	return existing == "sent" || existing == "processing"
}

// P0 RACE CONDITION FIX: Sistema de fingerprint para detectar duplicatas
func (s *EmailService) generateFingerprint(job EmailJob) string {
	h := sha256.New()
	for _, to := range job.To {
		h.Write([]byte(to))
	}
	h.Write([]byte(job.Subject))
	h.Write([]byte(job.Body))
	h.Write([]byte(job.HTMLBody))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *EmailService) isDuplicate(fingerprint string) bool {
	ctx := context.Background()
	fingerprintKey := fmt.Sprintf("email_fingerprint:%s", fingerprint)
	exists := s.redisClient.Exists(ctx, fingerprintKey).Val()
	return exists > 0
}

func (s *EmailService) markProcessed(fingerprint string) {
	ctx := context.Background()
	fingerprintKey := fmt.Sprintf("email_fingerprint:%s", fingerprint)
	// Marcar como processado por 24 horas
	s.redisClient.SetEX(ctx, fingerprintKey, "processed", 24*time.Hour)
}

// P0 RACE CONDITION FIX: Cleanup automático de locks expirados e jobs órfãos
func (s *EmailService) startCleanupWorker() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Cleanup a cada 5 minutos
		defer ticker.Stop()
		
		for range ticker.C {
			s.cleanupExpiredLocks()
			s.cleanupOrphanedJobs()
		}
	}()
}

func (s *EmailService) cleanupExpiredLocks() {
	ctx := context.Background()
	
	// Script Lua para encontrar e remover locks expirados
	script := `
		local keys = redis.call('KEYS', 'job_processing:*')
		local expired = 0
		for i = 1, #keys do
			local ttl = redis.call('TTL', keys[i])
			if ttl == -1 then  -- Lock sem TTL (órfão)
				redis.call('DEL', keys[i])
				expired = expired + 1
			end
		end
		return expired
	`
	
	result := s.redisClient.Eval(ctx, script, []string{})
	if result.Err() == nil {
		expiredCount := result.Val()
		if expiredCount.(int64) > 0 {
			logrus.WithFields(logrus.Fields{
				"component": "cleanup",
				"expired_locks": expiredCount,
			}).Info("Cleaned up expired locks")
		}
	}
}

func (s *EmailService) cleanupOrphanedJobs() {
	ctx := context.Background()
	
	// Script Lua para encontrar jobs órfãos (sem lock correspondente)
	script := `
		local statusKeys = redis.call('KEYS', 'email_job:*')
		local orphaned = 0
		for i = 1, #statusKeys do
			local jobId = string.match(statusKeys[i], 'email_job:(.+)')
			local status = redis.call('HGET', statusKeys[i], 'status')
			local lockKey = 'job_processing:' .. jobId
			
			-- Se status é 'processing' mas não há lock, limpar
			if status == 'processing' and redis.call('EXISTS', lockKey) == 0 then
				redis.call('HSET', statusKeys[i], 'status', 'failed', 'message', 'Job orphaned - no processing lock found')
				orphaned = orphaned + 1
			end
		end
		return orphaned
	`
	
	result := s.redisClient.Eval(ctx, script, []string{})
	if result.Err() == nil {
		orphanedCount := result.Val()
		if orphanedCount.(int64) > 0 {
			logrus.WithFields(logrus.Fields{
				"component": "cleanup",
				"orphaned_jobs": orphanedCount,
			}).Info("Cleaned up orphaned jobs")
		}
	}
}

func (s *EmailService) healthCheck(c *gin.Context) {
	// Check Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.redisClient.Ping(ctx).Err(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  "Redis connection failed",
		})
		return
	}

	// Get queue sizes
	emailQueueSize := s.redisClient.LLen(ctx, "email_queue").Val()
	retryQueueSize := s.redisClient.LLen(ctx, "retry_queue").Val()
	failedQueueSize := s.redisClient.LLen(ctx, "failed_queue").Val()

	// Get Redis pool statistics
	poolStats := s.redisClient.PoolStats()

	healthStatus := gin.H{
		"status":           "healthy",
		"timestamp":        time.Now().Unix(),
		"service":          "email-service",
		"email_queue_size": emailQueueSize,
		"retry_queue_size": retryQueueSize,
		"failed_queue_size": failedQueueSize,
		"circuit_breaker":  s.circuitBreaker.state,
		"redis_pool": gin.H{
			"pool_stats": gin.H{
				"hits":         poolStats.Hits,
				"misses":       poolStats.Misses,
				"timeouts":     poolStats.Timeouts,
				"total_conns":  poolStats.TotalConns,
				"idle_conns":   poolStats.IdleConns,
				"stale_conns":  poolStats.StaleConns,
			},
			"pool_config": gin.H{
				"pool_size":     getEnvAsInt("REDIS_POOL_SIZE", 50),
				"min_idle":      getEnvAsInt("REDIS_MIN_IDLE", 10),
				"max_idle":      getEnvAsInt("REDIS_MAX_IDLE", 20),
				"dial_timeout":  getEnvAsInt("REDIS_DIAL_TIMEOUT", 5),
				"read_timeout":  getEnvAsInt("REDIS_READ_TIMEOUT", 3),
				"write_timeout": getEnvAsInt("REDIS_WRITE_TIMEOUT", 3),
			},
		},
	}

	c.JSON(http.StatusOK, healthStatus)
}

func (s *EmailService) getStats(c *gin.Context) {
	ctx := context.Background()

	// Get queue sizes
	emailQueueSize := s.redisClient.LLen(ctx, "email_queue").Val()
	retryQueueSize := s.redisClient.LLen(ctx, "retry_queue").Val()
	failedQueueSize := s.redisClient.LLen(ctx, "failed_queue").Val()

	// Get metrics from Prometheus (simplified)
	stats := gin.H{
		"timestamp": time.Now().Unix(),
		"queues": gin.H{
			"email_queue":  emailQueueSize,
			"retry_queue":  retryQueueSize,
			"failed_queue": failedQueueSize,
		},
		"circuit_breaker": gin.H{
			"state":          s.circuitBreaker.state,
			"failure_count":  s.circuitBreaker.failureCount,
			"last_failure":   s.circuitBreaker.lastFailureTime.Unix(),
		},
		"rate_limiter": gin.H{
			"active_domains": len(s.rateLimiter.limiters),
			"rate_limit":     s.rateLimiter.rateLimit,
			"burst":          s.rateLimiter.burst,
		},
	}

	c.JSON(http.StatusOK, stats)
}

// LoggingMiddleware creates a middleware for structured logging with correlation IDs
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Get or generate correlation ID
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}
		
		// Set correlation ID in response header
		c.Header("X-Correlation-ID", correlationID)
		
		// Store correlation ID in context
		c.Set("correlation_id", correlationID)
		
		// Log request start
		logrus.WithFields(logrus.Fields{
			"correlation_id": correlationID,
			"method":        c.Request.Method,
			"path":          c.Request.URL.Path,
			"query":         c.Request.URL.RawQuery,
			"user_agent":    c.Request.UserAgent(),
			"remote_addr":   c.ClientIP(),
		}).Info("Request started")
		
		// Process request
		c.Next()
		
		// Log request completion
		duration := time.Since(start)
		logrus.WithFields(logrus.Fields{
			"correlation_id": correlationID,
			"method":        c.Request.Method,
			"path":          c.Request.URL.Path,
			"status":        c.Writer.Status(),
			"duration_ms":   duration.Milliseconds(),
			"response_size": c.Writer.Size(),
		}).Info("Request completed")
	}
}

func main() {
	// Initialize service
	service, err := NewEmailService()
	if err != nil {
		log.Fatal("Failed to initialize email service:", err)
	}
	defer service.redisClient.Close()
	defer service.workerPool.Stop()

	// Start worker pool
	service.workerPool.Start(service)
	
	// Start cleanup worker para locks expirados e jobs órfãos
	service.startCleanupWorker()

	// Set Gin mode
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Add logging middleware
	router.Use(LoggingMiddleware())

	// Health check
	router.GET("/health", service.healthCheck)

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Email routes
	email := router.Group("/email")
	{
		email.POST("/send", service.sendSingleEmail)
		email.POST("/bulk", service.sendBulkEmails)
		email.GET("/status/:id", service.getJobStatus)
		email.GET("/stats", service.getStats)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8002"
	}

	logrus.WithFields(logrus.Fields{
		"service": "email-service",
		"port":    port,
	}).Info("Email service starting")
	
	logrus.WithFields(logrus.Fields{
		"service": "email-service",
		"endpoints": []string{
			"POST /email/send - Send single email",
			"POST /email/bulk - Send bulk emails",
			"GET /email/status/:id - Get job status",
			"GET /email/stats - Get service statistics",
			"GET /health - Health check",
			"GET /metrics - Prometheus metrics",
		},
	}).Info("Available endpoints")

	// Graceful shutdown setup
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}