package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type EmailService struct {
	smtpPool    *SMTPPool
	redisClient *redis.Client
	metrics     *Metrics
	workerPool  *WorkerPool
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

type WorkerPool struct {
	jobQueue    chan EmailJob
	workerQueue chan chan EmailJob
	workers     []*Worker
	maxWorkers  int
	ctx         context.Context
	cancel      context.CancelFunc
}

type Worker struct {
	id          int
	jobChannel  chan EmailJob
	workerQueue chan chan EmailJob
	quitChan    chan bool
	service     *EmailService
}

type EmailJob struct {
	ID          string            `json:"id"`
	To          []string          `json:"to"`
	From        string            `json:"from"`
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Attachments []Attachment      `json:"attachments,omitempty"`
	Priority    int               `json:"priority"`
	ScheduledAt *time.Time        `json:"scheduled_at,omitempty"`
	RetryCount  int               `json:"retry_count"`
	MaxRetries  int               `json:"max_retries"`
	CreatedAt   time.Time         `json:"created_at"`
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
	}
}

func (wp *WorkerPool) Start(service *EmailService) {
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
		go worker.Start()
	}

	// Start dispatcher
	go wp.dispatch()
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

func (wp *WorkerPool) Stop() {
	wp.cancel()
	for _, worker := range wp.workers {
		worker.Stop()
	}
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

func (w *Worker) Stop() {
	go func() {
		w.quitChan <- true
	}()
}

func (w *Worker) processEmail(job EmailJob) {
	start := time.Now()
	defer func() {
		w.service.metrics.processingTime.Observe(time.Since(start).Seconds())
	}()

	// Check if email is scheduled for later
	if job.ScheduledAt != nil && job.ScheduledAt.After(time.Now()) {
		// Re-queue for later
		time.Sleep(time.Until(*job.ScheduledAt))
	}

	// Get SMTP client from pool
	client, err := w.service.smtpPool.Get()
	if err != nil {
		log.Printf("Worker %d: Failed to get SMTP client: %v", w.id, err)
		w.handleEmailFailure(job, err)
		return
	}
	defer w.service.smtpPool.Put(client)

	w.service.metrics.smtpConnections.Inc()
	defer w.service.metrics.smtpConnections.Dec()

	// Send email
	if err := w.sendEmail(client, job); err != nil {
		log.Printf("Worker %d: Failed to send email %s: %v", w.id, job.ID, err)
		w.handleEmailFailure(job, err)
		return
	}

	w.service.metrics.emailsSent.Inc()
	log.Printf("Worker %d: Successfully sent email %s", w.id, job.ID)

	// Update job status in Redis
	w.service.updateJobStatus(job.ID, "sent", "")
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

func (w *Worker) handleEmailFailure(job EmailJob, err error) {
	w.service.metrics.emailsFailed.Inc()

	// Check if we should retry
	if job.RetryCount < job.MaxRetries {
		w.service.metrics.retryAttempts.Inc()
		job.RetryCount++
		
		// Exponential backoff
		delay := time.Duration(job.RetryCount*job.RetryCount) * time.Second
		time.Sleep(delay)
		
		// Re-queue the job
		w.service.workerPool.AddJob(job)
		w.service.updateJobStatus(job.ID, "retrying", fmt.Sprintf("Retry %d/%d: %v", job.RetryCount, job.MaxRetries, err))
	} else {
		w.service.updateJobStatus(job.ID, "failed", err.Error())
	}
}

func NewEmailService() (*EmailService, error) {
	// Redis connection
	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	redisPassword := os.Getenv("REDIS_PASSWORD")

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// SMTP configuration
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "postfix"
	}
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	maxConns, _ := strconv.Atoi(os.Getenv("SMTP_MAX_CONNECTIONS"))
	if maxConns == 0 {
		maxConns = 10
	}

	maxWorkers, _ := strconv.Atoi(os.Getenv("MAX_WORKERS"))
	if maxWorkers == 0 {
		maxWorkers = 20
	}

	service := &EmailService{
		smtpPool:    NewSMTPPool(smtpHost, smtpPort, smtpUser, smtpPass, maxConns),
		redisClient: rdb,
		metrics:     NewMetrics(),
	}

	service.workerPool = NewWorkerPool(maxWorkers, service)
	service.workerPool.Start(service)

	return service, nil
}

func (s *EmailService) updateJobStatus(jobID, status, message string) {
	ctx := context.Background()
	key := fmt.Sprintf("email_job:%s", jobID)
	
	jobData := map[string]interface{}{
		"status":     status,
		"message":    message,
		"updated_at": time.Now().Unix(),
	}

	s.redisClient.HMSet(ctx, key, jobData)
	s.redisClient.Expire(ctx, key, 24*time.Hour) // Keep job data for 24 hours
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

	// Set defaults
	if job.ID == "" {
		job.ID = fmt.Sprintf("email_%d", time.Now().UnixNano())
	}
	if job.MaxRetries == 0 {
		job.MaxRetries = 3
	}
	job.CreatedAt = time.Now()

	// Queue the email
	s.workerPool.AddJob(job)
	s.metrics.emailsQueued.Inc()
	s.metrics.queueSize.Inc()

	// Store job in Redis
	s.updateJobStatus(job.ID, "queued", "Email queued for processing")

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

	jobIDs := make([]string, len(req.Emails))
	for i, job := range req.Emails {
		// Set defaults
		if job.ID == "" {
			job.ID = fmt.Sprintf("bulk_email_%d_%d", time.Now().UnixNano(), i)
		}
		if job.MaxRetries == 0 {
			job.MaxRetries = 3
		}
		job.CreatedAt = time.Now()

		// Queue the email
		s.workerPool.AddJob(job)
		s.updateJobStatus(job.ID, "queued", "Email queued for bulk processing")
		jobIDs[i] = job.ID
	}

	s.metrics.emailsQueued.Add(float64(len(req.Emails)))
	s.metrics.queueSize.Add(float64(len(req.Emails)))

	c.JSON(http.StatusAccepted, gin.H{
		"message":   fmt.Sprintf("Queued %d emails for processing", len(req.Emails)),
		"job_ids":   jobIDs,
		"queued_at": time.Now().Unix(),
	})
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

	c.JSON(http.StatusOK, gin.H{
		"status":       "healthy",
		"timestamp":    time.Now().Unix(),
		"service":      "email-service",
		"queue_size":   len(s.workerPool.jobQueue),
		"active_workers": len(s.workerPool.workers),
	})
}

func main() {
	// Initialize service
	service, err := NewEmailService()
	if err != nil {
		log.Fatal("Failed to initialize email service:", err)
	}
	defer service.redisClient.Close()
	defer service.workerPool.Stop()

	// Set Gin mode
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

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
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8002"
	}

	log.Printf("Email service starting on port %s", port)
	log.Fatal(router.Run(":" + port))
}