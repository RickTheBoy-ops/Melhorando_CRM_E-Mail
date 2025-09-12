package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CampaignService struct {
	db          *pgxpool.Pool
	redisClient *redis.Client
	metrics     *CampaignMetrics
	emailClient *EmailClient
}

type Campaign struct {
	ID          int64     `json:"id" db:"id"`
	Name        string    `json:"name" db:"name" binding:"required"`
	Subject     string    `json:"subject" db:"subject" binding:"required"`
	FromEmail   string    `json:"from_email" db:"from_email" binding:"required,email"`
	FromName    string    `json:"from_name" db:"from_name"`
	TemplateID  *int64    `json:"template_id" db:"template_id"`
	Content     string    `json:"content" db:"content"`
	HTMLContent string    `json:"html_content" db:"html_content"`
	Status      string    `json:"status" db:"status"`
	ScheduledAt *time.Time `json:"scheduled_at" db:"scheduled_at"`
	SentAt      *time.Time `json:"sent_at" db:"sent_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	UserID      int64     `json:"user_id" db:"user_id"`
	SegmentID   *int64    `json:"segment_id" db:"segment_id"`
	TotalEmails int       `json:"total_emails" db:"total_emails"`
	SentEmails  int       `json:"sent_emails" db:"sent_emails"`
	OpenRate    float64   `json:"open_rate" db:"open_rate"`
	ClickRate   float64   `json:"click_rate" db:"click_rate"`
}

type Segment struct {
	ID          int64     `json:"id" db:"id"`
	Name        string    `json:"name" db:"name" binding:"required"`
	Description string    `json:"description" db:"description"`
	Conditions  string    `json:"conditions" db:"conditions"` // JSON string with filter conditions
	UserID      int64     `json:"user_id" db:"user_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	ContactCount int      `json:"contact_count" db:"contact_count"`
}

type CampaignStats struct {
	CampaignID    int64   `json:"campaign_id"`
	TotalSent     int     `json:"total_sent"`
	Delivered     int     `json:"delivered"`
	Opened        int     `json:"opened"`
	Clicked       int     `json:"clicked"`
	Bounced       int     `json:"bounced"`
	Unsubscribed  int     `json:"unsubscribed"`
	OpenRate      float64 `json:"open_rate"`
	ClickRate     float64 `json:"click_rate"`
	BounceRate    float64 `json:"bounce_rate"`
	UnsubscribeRate float64 `json:"unsubscribe_rate"`
}

type EmailClient struct {
	baseURL string
	client  *http.Client
}

type BulkEmailRequest struct {
	Emails []EmailJob `json:"emails"`
}

type EmailJob struct {
	ID         string            `json:"id"`
	To         []string          `json:"to"`
	From       string            `json:"from"`
	Subject    string            `json:"subject"`
	Body       string            `json:"body"`
	HTMLBody   string            `json:"html_body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Priority   int               `json:"priority"`
	MaxRetries int               `json:"max_retries"`
}

type CampaignMetrics struct {
	campaignsCreated   prometheus.Counter
	campaignsSent      prometheus.Counter
	campaignsFailed    prometheus.Counter
	processingTime     prometheus.Histogram
	activeCampaigns    prometheus.Gauge
	scheduledCampaigns prometheus.Gauge
}

func NewCampaignMetrics() *CampaignMetrics {
	m := &CampaignMetrics{
		campaignsCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaigns_created_total",
			Help: "Total number of campaigns created",
		}),
		campaignsSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaigns_sent_total",
			Help: "Total number of campaigns sent",
		}),
		campaignsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaigns_failed_total",
			Help: "Total number of campaigns that failed to send",
		}),
		processingTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "campaign_processing_duration_seconds",
			Help:    "Time taken to process and send a campaign",
			Buckets: prometheus.DefBuckets,
		}),
		activeCampaigns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "active_campaigns",
			Help: "Number of currently active campaigns",
		}),
		scheduledCampaigns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "scheduled_campaigns",
			Help: "Number of scheduled campaigns",
		}),
	}

	// Register metrics
	prometheus.MustRegister(m.campaignsCreated)
	prometheus.MustRegister(m.campaignsSent)
	prometheus.MustRegister(m.campaignsFailed)
	prometheus.MustRegister(m.processingTime)
	prometheus.MustRegister(m.activeCampaigns)
	prometheus.MustRegister(m.scheduledCampaigns)

	return m
}

func NewEmailClient(baseURL string) *EmailClient {
	return &EmailClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (ec *EmailClient) SendBulkEmails(emails []EmailJob) error {
	req := BulkEmailRequest{Emails: emails}
	
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal email request: %w", err)
	}

	resp, err := ec.client.Post(ec.baseURL+"/email/bulk", "application/json", 
		bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send bulk emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("email service returned status %d", resp.StatusCode)
	}

	return nil
}

func NewCampaignService() (*CampaignService, error) {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://user:password@postgres:5432/billionmail?sslmode=disable"
	}

	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test database connection
	if err := db.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Redis connection
	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Email service client
	emailServiceURL := os.Getenv("EMAIL_SERVICE_URL")
	if emailServiceURL == "" {
		emailServiceURL = "http://email-service:8002"
	}

	service := &CampaignService{
		db:          db,
		redisClient: rdb,
		metrics:     NewCampaignMetrics(),
		emailClient: NewEmailClient(emailServiceURL),
	}

	// Initialize database tables
	if err := service.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	// Start campaign scheduler
	go service.campaignScheduler()

	return service, nil
}

func (cs *CampaignService) initTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS campaigns (
			id BIGSERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			subject VARCHAR(500) NOT NULL,
			from_email VARCHAR(255) NOT NULL,
			from_name VARCHAR(255),
			template_id BIGINT,
			content TEXT,
			html_content TEXT,
			status VARCHAR(50) DEFAULT 'draft',
			scheduled_at TIMESTAMP,
			sent_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			user_id BIGINT NOT NULL,
			segment_id BIGINT,
			total_emails INTEGER DEFAULT 0,
			sent_emails INTEGER DEFAULT 0,
			open_rate DECIMAL(5,2) DEFAULT 0,
			click_rate DECIMAL(5,2) DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS segments (
			id BIGSERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			conditions JSONB,
			user_id BIGINT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			contact_count INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS campaign_stats (
			id BIGSERIAL PRIMARY KEY,
			campaign_id BIGINT NOT NULL REFERENCES campaigns(id),
			contact_id BIGINT NOT NULL,
			email VARCHAR(255) NOT NULL,
			status VARCHAR(50) DEFAULT 'sent',
			sent_at TIMESTAMP DEFAULT NOW(),
			delivered_at TIMESTAMP,
			opened_at TIMESTAMP,
			clicked_at TIMESTAMP,
			bounced_at TIMESTAMP,
			unsubscribed_at TIMESTAMP,
			UNIQUE(campaign_id, contact_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_scheduled ON campaigns(scheduled_at)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_user ON campaigns(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_segments_user ON segments(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_stats_campaign ON campaign_stats(campaign_id)`,
	}

	for _, query := range queries {
		if _, err := cs.db.Exec(context.Background(), query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

func (cs *CampaignService) campaignScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cs.processScheduledCampaigns()
	}
}

func (cs *CampaignService) processScheduledCampaigns() {
	ctx := context.Background()
	
	query := `
		SELECT id, name, subject, from_email, from_name, content, html_content, 
		       user_id, segment_id, scheduled_at
		FROM campaigns 
		WHERE status = 'scheduled' AND scheduled_at <= NOW()
	`
	
	rows, err := cs.db.Query(ctx, query)
	if err != nil {
		log.Printf("Failed to query scheduled campaigns: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var campaign Campaign
		err := rows.Scan(
			&campaign.ID, &campaign.Name, &campaign.Subject,
			&campaign.FromEmail, &campaign.FromName,
			&campaign.Content, &campaign.HTMLContent,
			&campaign.UserID, &campaign.SegmentID, &campaign.ScheduledAt,
		)
		if err != nil {
			log.Printf("Failed to scan campaign: %v", err)
			continue
		}

		go cs.sendCampaign(campaign)
	}
}

func (cs *CampaignService) sendCampaign(campaign Campaign) {
	start := time.Now()
	defer func() {
		cs.metrics.processingTime.Observe(time.Since(start).Seconds())
	}()

	ctx := context.Background()
	
	// Update campaign status to sending
	_, err := cs.db.Exec(ctx, 
		"UPDATE campaigns SET status = 'sending', updated_at = NOW() WHERE id = $1",
		campaign.ID)
	if err != nil {
		log.Printf("Failed to update campaign status: %v", err)
		return
	}

	// Get contacts for the campaign
	contacts, err := cs.getCampaignContacts(campaign)
	if err != nil {
		log.Printf("Failed to get campaign contacts: %v", err)
		cs.updateCampaignStatus(campaign.ID, "failed")
		cs.metrics.campaignsFailed.Inc()
		return
	}

	if len(contacts) == 0 {
		log.Printf("No contacts found for campaign %d", campaign.ID)
		cs.updateCampaignStatus(campaign.ID, "completed")
		return
	}

	// Prepare emails
	emails := make([]EmailJob, len(contacts))
	for i, contact := range contacts {
		emails[i] = EmailJob{
			ID:         fmt.Sprintf("campaign_%d_contact_%d", campaign.ID, contact.ID),
			To:         []string{contact.Email},
			From:       campaign.FromEmail,
			Subject:    campaign.Subject,
			Body:       campaign.Content,
			HTMLBody:   campaign.HTMLContent,
			Priority:   1,
			MaxRetries: 3,
			Headers: map[string]string{
				"X-Campaign-ID": strconv.FormatInt(campaign.ID, 10),
				"X-Contact-ID":  strconv.FormatInt(contact.ID, 10),
			},
		}
	}

	// Send emails via email service
	if err := cs.emailClient.SendBulkEmails(emails); err != nil {
		log.Printf("Failed to send campaign emails: %v", err)
		cs.updateCampaignStatus(campaign.ID, "failed")
		cs.metrics.campaignsFailed.Inc()
		return
	}

	// Update campaign statistics
	cs.updateCampaignStats(campaign.ID, len(contacts))
	cs.updateCampaignStatus(campaign.ID, "sent")
	cs.metrics.campaignsSent.Inc()

	log.Printf("Successfully sent campaign %d to %d contacts", campaign.ID, len(contacts))
}

type Contact struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (cs *CampaignService) getCampaignContacts(_ Campaign) ([]Contact, error) {
	// This is a simplified version - in a real implementation,
	// you would query the contact-service or have a local contacts table
	// For now, we'll return mock data
	return []Contact{
		{ID: 1, Email: "user1@example.com", Name: "User 1"},
		{ID: 2, Email: "user2@example.com", Name: "User 2"},
	}, nil
}

func (cs *CampaignService) updateCampaignStatus(campaignID int64, status string) {
	ctx := context.Background()
	query := "UPDATE campaigns SET status = $1, updated_at = NOW()"
	
	if status == "sent" {
		query += ", sent_at = NOW()"
	}
	
	query += " WHERE id = $2"
	
	_, err := cs.db.Exec(ctx, query, status, campaignID)
	if err != nil {
		log.Printf("Failed to update campaign status: %v", err)
	}
}

func (cs *CampaignService) updateCampaignStats(campaignID int64, totalEmails int) {
	ctx := context.Background()
	_, err := cs.db.Exec(ctx,
		"UPDATE campaigns SET total_emails = $1, sent_emails = $1, updated_at = NOW() WHERE id = $2",
		totalEmails, campaignID)
	if err != nil {
		log.Printf("Failed to update campaign stats: %v", err)
	}
}

// HTTP Handlers
func (cs *CampaignService) createCampaign(c *gin.Context) {
	var campaign Campaign
	if err := c.ShouldBindJSON(&campaign); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	// Set defaults
	campaign.Status = "draft"
	campaign.CreatedAt = time.Now()
	campaign.UpdatedAt = time.Now()

	// Insert campaign
	ctx := context.Background()
	query := `
		INSERT INTO campaigns (name, subject, from_email, from_name, template_id, 
		                      content, html_content, status, scheduled_at, user_id, segment_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at
	`
	
	err := cs.db.QueryRow(ctx, query,
		campaign.Name, campaign.Subject, campaign.FromEmail, campaign.FromName,
		campaign.TemplateID, campaign.Content, campaign.HTMLContent,
		campaign.Status, campaign.ScheduledAt, campaign.UserID, campaign.SegmentID,
	).Scan(&campaign.ID, &campaign.CreatedAt, &campaign.UpdatedAt)
	
	if err != nil {
		log.Printf("Failed to create campaign: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create campaign",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	cs.metrics.campaignsCreated.Inc()
	c.JSON(http.StatusCreated, campaign)
}

func (cs *CampaignService) getCampaigns(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID is required",
			"code":  "MISSING_USER_ID",
		})
		return
	}

	ctx := context.Background()
	query := `
		SELECT id, name, subject, from_email, from_name, template_id, content, 
		       html_content, status, scheduled_at, sent_at, created_at, updated_at,
		       user_id, segment_id, total_emails, sent_emails, open_rate, click_rate
		FROM campaigns 
		WHERE user_id = $1 
		ORDER BY created_at DESC
	`
	
	rows, err := cs.db.Query(ctx, query, userID)
	if err != nil {
		log.Printf("Failed to get campaigns: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get campaigns",
			"code":  "DATABASE_ERROR",
		})
		return
	}
	defer rows.Close()

	var campaigns []Campaign
	for rows.Next() {
		var campaign Campaign
		err := rows.Scan(
			&campaign.ID, &campaign.Name, &campaign.Subject,
			&campaign.FromEmail, &campaign.FromName, &campaign.TemplateID,
			&campaign.Content, &campaign.HTMLContent, &campaign.Status,
			&campaign.ScheduledAt, &campaign.SentAt, &campaign.CreatedAt,
			&campaign.UpdatedAt, &campaign.UserID, &campaign.SegmentID,
			&campaign.TotalEmails, &campaign.SentEmails, &campaign.OpenRate,
			&campaign.ClickRate,
		)
		if err != nil {
			log.Printf("Failed to scan campaign: %v", err)
			continue
		}
		campaigns = append(campaigns, campaign)
	}

	c.JSON(http.StatusOK, campaigns)
}

func (cs *CampaignService) getCampaign(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Campaign ID is required",
			"code":  "MISSING_CAMPAIGN_ID",
		})
		return
	}

	ctx := context.Background()
	query := `
		SELECT id, name, subject, from_email, from_name, template_id, content, 
		       html_content, status, scheduled_at, sent_at, created_at, updated_at,
		       user_id, segment_id, total_emails, sent_emails, open_rate, click_rate
		FROM campaigns 
		WHERE id = $1
	`
	
	var campaign Campaign
	err := cs.db.QueryRow(ctx, query, id).Scan(
		&campaign.ID, &campaign.Name, &campaign.Subject,
		&campaign.FromEmail, &campaign.FromName, &campaign.TemplateID,
		&campaign.Content, &campaign.HTMLContent, &campaign.Status,
		&campaign.ScheduledAt, &campaign.SentAt, &campaign.CreatedAt,
		&campaign.UpdatedAt, &campaign.UserID, &campaign.SegmentID,
		&campaign.TotalEmails, &campaign.SentEmails, &campaign.OpenRate,
		&campaign.ClickRate,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Campaign not found",
				"code":  "CAMPAIGN_NOT_FOUND",
			})
		} else {
			log.Printf("Failed to get campaign: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get campaign",
				"code":  "DATABASE_ERROR",
			})
		}
		return
	}

	c.JSON(http.StatusOK, campaign)
}

func (cs *CampaignService) sendCampaignNow(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Campaign ID is required",
			"code":  "MISSING_CAMPAIGN_ID",
		})
		return
	}

	// Get campaign
	ctx := context.Background()
	var campaign Campaign
	query := `
		SELECT id, name, subject, from_email, from_name, content, html_content, 
		       status, user_id, segment_id
		FROM campaigns 
		WHERE id = $1
	`
	
	err := cs.db.QueryRow(ctx, query, id).Scan(
		&campaign.ID, &campaign.Name, &campaign.Subject,
		&campaign.FromEmail, &campaign.FromName,
		&campaign.Content, &campaign.HTMLContent,
		&campaign.Status, &campaign.UserID, &campaign.SegmentID,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Campaign not found",
				"code":  "CAMPAIGN_NOT_FOUND",
			})
		} else {
			log.Printf("Failed to get campaign: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get campaign",
				"code":  "DATABASE_ERROR",
			})
		}
		return
	}

	if campaign.Status != "draft" && campaign.Status != "scheduled" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Campaign cannot be sent in current status",
			"code":  "INVALID_STATUS",
		})
		return
	}

	// Send campaign asynchronously
	go cs.sendCampaign(campaign)

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Campaign queued for sending",
		"status":  "sending",
	})
}

func (cs *CampaignService) getCampaignStats(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Campaign ID is required",
			"code":  "MISSING_CAMPAIGN_ID",
		})
		return
	}

	ctx := context.Background()
	query := `
		SELECT 
			COUNT(*) as total_sent,
			COUNT(CASE WHEN delivered_at IS NOT NULL THEN 1 END) as delivered,
			COUNT(CASE WHEN opened_at IS NOT NULL THEN 1 END) as opened,
			COUNT(CASE WHEN clicked_at IS NOT NULL THEN 1 END) as clicked,
			COUNT(CASE WHEN bounced_at IS NOT NULL THEN 1 END) as bounced,
			COUNT(CASE WHEN unsubscribed_at IS NOT NULL THEN 1 END) as unsubscribed
		FROM campaign_stats 
		WHERE campaign_id = $1
	`
	
	var stats CampaignStats
	var totalSent, delivered, opened, clicked, bounced, unsubscribed int
	
	err := cs.db.QueryRow(ctx, query, id).Scan(
		&totalSent, &delivered, &opened, &clicked, &bounced, &unsubscribed,
	)
	
	if err != nil {
		log.Printf("Failed to get campaign stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get campaign stats",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	// Calculate rates
	stats.TotalSent = totalSent
	stats.Delivered = delivered
	stats.Opened = opened
	stats.Clicked = clicked
	stats.Bounced = bounced
	stats.Unsubscribed = unsubscribed

	if totalSent > 0 {
		stats.OpenRate = float64(opened) / float64(totalSent) * 100
		stats.ClickRate = float64(clicked) / float64(totalSent) * 100
		stats.BounceRate = float64(bounced) / float64(totalSent) * 100
		stats.UnsubscribeRate = float64(unsubscribed) / float64(totalSent) * 100
	}

	c.JSON(http.StatusOK, stats)
}

func (cs *CampaignService) healthCheck(c *gin.Context) {
	// Check database connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cs.db.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  "Database connection failed",
		})
		return
	}

	// Check Redis connection
	if err := cs.redisClient.Ping(ctx).Err(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  "Redis connection failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   "campaign-service",
	})
}

func main() {
	// Initialize service
	service, err := NewCampaignService()
	if err != nil {
		log.Fatal("Failed to initialize campaign service:", err)
	}
	defer service.db.Close()
	defer service.redisClient.Close()

	// Set Gin mode
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Health check
	router.GET("/health", service.healthCheck)

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Campaign routes
	campaigns := router.Group("/campaigns")
	{
		campaigns.POST("/", service.createCampaign)
		campaigns.GET("/", service.getCampaigns)
		campaigns.GET("/:id", service.getCampaign)
		campaigns.POST("/:id/send", service.sendCampaignNow)
		campaigns.GET("/:id/stats", service.getCampaignStats)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8003"
	}

	log.Printf("Campaign service starting on port %s", port)
	log.Fatal(router.Run(":" + port))
}