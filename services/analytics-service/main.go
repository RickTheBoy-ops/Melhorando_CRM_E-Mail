package main

import (
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// EmailEvent represents an email tracking event
type EmailEvent struct {
	ID         int       `json:"id" db:"id"`
	EmailID    string    `json:"email_id" db:"email_id"`
	CampaignID int       `json:"campaign_id" db:"campaign_id"`
	ContactID  int       `json:"contact_id" db:"contact_id"`
	EventType  string    `json:"event_type" db:"event_type"` // sent, delivered, opened, clicked, bounced, unsubscribed
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	URL        string    `json:"url" db:"url"`
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`
}

// CampaignStats represents campaign statistics
type CampaignStats struct {
	CampaignID      int     `json:"campaign_id"`
	CampaignName    string  `json:"campaign_name"`
	TotalSent       int     `json:"total_sent"`
	TotalDelivered  int     `json:"total_delivered"`
	TotalOpened     int     `json:"total_opened"`
	TotalClicked    int     `json:"total_clicked"`
	TotalBounced    int     `json:"total_bounced"`
	TotalUnsubscribed int   `json:"total_unsubscribed"`
	OpenRate        float64 `json:"open_rate"`
	ClickRate       float64 `json:"click_rate"`
	BounceRate      float64 `json:"bounce_rate"`
	UnsubscribeRate float64 `json:"unsubscribe_rate"`
	CreatedAt       time.Time `json:"created_at"`
}

// DashboardMetrics represents real-time dashboard metrics
type DashboardMetrics struct {
	TotalEmailsSent     int64   `json:"total_emails_sent"`
	TotalEmailsDelivered int64  `json:"total_emails_delivered"`
	TotalEmailsOpened   int64   `json:"total_emails_opened"`
	TotalEmailsClicked  int64   `json:"total_emails_clicked"`
	OverallOpenRate     float64 `json:"overall_open_rate"`
	OverallClickRate    float64 `json:"overall_click_rate"`
	ActiveCampaigns     int64   `json:"active_campaigns"`
	TotalContacts       int64   `json:"total_contacts"`
	RecentActivity      []EmailEvent `json:"recent_activity"`
}

// TimeSeriesData represents time-based analytics data
type TimeSeriesData struct {
	Timestamp time.Time `json:"timestamp"`
	Sent      int       `json:"sent"`
	Delivered int       `json:"delivered"`
	Opened    int       `json:"opened"`
	Clicked   int       `json:"clicked"`
	Bounced   int       `json:"bounced"`
}

// AnalyticsService handles analytics operations
type AnalyticsService struct {
	db    *sql.DB
	redis *redis.Client
}

// Prometheus metrics
var (
	eventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "analytics_events_processed_total",
			Help: "Total number of analytics events processed",
		},
		[]string{"event_type", "status"},
	)

	reportsGenerated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "analytics_reports_generated_total",
			Help: "Total number of reports generated",
		},
		[]string{"report_type", "status"},
	)

	queryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "analytics_query_duration_seconds",
			Help: "Duration of analytics queries",
		},
		[]string{"query_type"},
	)

	cacheHitRate = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "analytics_cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"cache_type"},
	)
)

func init() {
	prometheus.MustRegister(eventsProcessed)
	prometheus.MustRegister(reportsGenerated)
	prometheus.MustRegister(queryDuration)
	prometheus.MustRegister(cacheHitRate)
}

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://billionmail_user:billionmail_pass@postgres:5432/billionmail_analytics?sslmode=disable"
	}

	config, err := pgx.ParseConfig(dbURL)
	if err != nil {
		log.Fatal("Failed to parse database URL:", err)
	}

	db := stdlib.OpenDB(*config)
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Redis connection
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   3, // Use DB 3 for analytics
	})

	// Test Redis connection
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	// Initialize database schema
	if err := initSchema(db); err != nil {
		log.Fatal("Failed to initialize database schema:", err)
	}

	service := &AnalyticsService{
		db:    db,
		redis: rdb,
	}

	// Start background workers
	go service.processEventQueue()
	go service.updateRealTimeMetrics()
	go service.generatePeriodicReports()

	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "analytics-service"})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Analytics endpoints
	v1 := router.Group("/api/v1")
	{
		// Event tracking
		v1.POST("/events", service.trackEvent)
		v1.POST("/events/bulk", service.trackBulkEvents)

		// Campaign analytics
		v1.GET("/campaigns/:id/stats", service.getCampaignStats)
		v1.GET("/campaigns/:id/timeline", service.getCampaignTimeline)
		v1.GET("/campaigns/:id/heatmap", service.getCampaignHeatmap)

		// Dashboard metrics
		v1.GET("/dashboard", service.getDashboardMetrics)
		v1.GET("/dashboard/realtime", service.getRealtimeMetrics)

		// Reports
		v1.GET("/reports/summary", service.getSummaryReport)
		v1.GET("/reports/performance", service.getPerformanceReport)
		v1.GET("/reports/engagement", service.getEngagementReport)
		v1.GET("/reports/trends", service.getTrendsReport)

		// Time-series data
		v1.GET("/timeseries/hourly", service.getHourlyTimeSeries)
		v1.GET("/timeseries/daily", service.getDailyTimeSeries)
		v1.GET("/timeseries/weekly", service.getWeeklyTimeSeries)

		// Advanced analytics
		v1.GET("/analytics/cohort", service.getCohortAnalysis)
		v1.GET("/analytics/funnel", service.getFunnelAnalysis)
		v1.GET("/analytics/segmentation", service.getSegmentationAnalysis)

		// Export endpoints
		v1.GET("/export/campaign/:id", service.exportCampaignData)
		v1.GET("/export/events", service.exportEventData)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8005"
	}

	log.Printf("Analytics service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func initSchema(db *sql.DB) error {
	schema := `
	-- Email events table
	CREATE TABLE IF NOT EXISTS email_events (
		id SERIAL PRIMARY KEY,
		email_id VARCHAR(255) NOT NULL,
		campaign_id INTEGER,
		contact_id INTEGER,
		event_type VARCHAR(50) NOT NULL,
		user_agent TEXT,
		ip_address INET,
		url TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Campaign statistics materialized view
	CREATE MATERIALIZED VIEW IF NOT EXISTS campaign_stats AS
	SELECT 
		c.id as campaign_id,
		c.name as campaign_name,
		COUNT(CASE WHEN e.event_type = 'sent' THEN 1 END) as total_sent,
		COUNT(CASE WHEN e.event_type = 'delivered' THEN 1 END) as total_delivered,
		COUNT(CASE WHEN e.event_type = 'opened' THEN 1 END) as total_opened,
		COUNT(CASE WHEN e.event_type = 'clicked' THEN 1 END) as total_clicked,
		COUNT(CASE WHEN e.event_type = 'bounced' THEN 1 END) as total_bounced,
		COUNT(CASE WHEN e.event_type = 'unsubscribed' THEN 1 END) as total_unsubscribed,
		CASE WHEN COUNT(CASE WHEN e.event_type = 'delivered' THEN 1 END) > 0 
			THEN ROUND(COUNT(CASE WHEN e.event_type = 'opened' THEN 1 END)::numeric / COUNT(CASE WHEN e.event_type = 'delivered' THEN 1 END) * 100, 2)
			ELSE 0 END as open_rate,
		CASE WHEN COUNT(CASE WHEN e.event_type = 'opened' THEN 1 END) > 0 
			THEN ROUND(COUNT(CASE WHEN e.event_type = 'clicked' THEN 1 END)::numeric / COUNT(CASE WHEN e.event_type = 'opened' THEN 1 END) * 100, 2)
			ELSE 0 END as click_rate,
		CASE WHEN COUNT(CASE WHEN e.event_type = 'sent' THEN 1 END) > 0 
			THEN ROUND(COUNT(CASE WHEN e.event_type = 'bounced' THEN 1 END)::numeric / COUNT(CASE WHEN e.event_type = 'sent' THEN 1 END) * 100, 2)
			ELSE 0 END as bounce_rate,
		c.created_at
	FROM campaigns c
	LEFT JOIN email_events e ON c.id = e.campaign_id
	GROUP BY c.id, c.name, c.created_at;

	-- Time-series aggregation table
	CREATE TABLE IF NOT EXISTS email_stats_hourly (
		id SERIAL PRIMARY KEY,
		hour_timestamp TIMESTAMP NOT NULL,
		campaign_id INTEGER,
		sent_count INTEGER DEFAULT 0,
		delivered_count INTEGER DEFAULT 0,
		opened_count INTEGER DEFAULT 0,
		clicked_count INTEGER DEFAULT 0,
		bounced_count INTEGER DEFAULT 0,
		unsubscribed_count INTEGER DEFAULT 0,
		UNIQUE(hour_timestamp, campaign_id)
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_email_events_campaign_id ON email_events(campaign_id);
	CREATE INDEX IF NOT EXISTS idx_email_events_contact_id ON email_events(contact_id);
	CREATE INDEX IF NOT EXISTS idx_email_events_event_type ON email_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_email_events_timestamp ON email_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_email_events_email_id ON email_events(email_id);
	CREATE INDEX IF NOT EXISTS idx_email_stats_hourly_timestamp ON email_stats_hourly(hour_timestamp);
	CREATE INDEX IF NOT EXISTS idx_email_stats_hourly_campaign ON email_stats_hourly(campaign_id);
	`

	_, err := db.Exec(schema)
	return err
}

func (s *AnalyticsService) processEventQueue() {
	for {
		// Process events from Redis queue
		result, err := s.redis.BRPop(context.Background(), 5*time.Second, "analytics:events").Result()
		if err != nil {
			if err != redis.Nil {
				log.Printf("Error processing event queue: %v", err)
			}
			continue
		}

		if len(result) < 2 {
			continue
		}

		var event EmailEvent
		if err := json.Unmarshal([]byte(result[1]), &event); err != nil {
			log.Printf("Error unmarshaling event: %v", err)
			continue
		}

		if err := s.storeEvent(event); err != nil {
			log.Printf("Error storing event: %v", err)
			eventsProcessed.WithLabelValues(event.EventType, "error").Inc()
		} else {
			eventsProcessed.WithLabelValues(event.EventType, "success").Inc()
		}
	}
}

func (s *AnalyticsService) updateRealTimeMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update real-time metrics in Redis
		ctx := context.Background()
		
		// Get recent event counts
		query := `
			SELECT event_type, COUNT(*) 
			FROM email_events 
			WHERE timestamp >= NOW() - INTERVAL '1 hour'
			GROUP BY event_type
		`
		
		rows, err := s.db.Query(query)
		if err != nil {
			log.Printf("Error updating real-time metrics: %v", err)
			continue
		}
		
		metrics := make(map[string]int)
		for rows.Next() {
			var eventType string
			var count int
			rows.Scan(&eventType, &count)
			metrics[eventType] = count
		}
		rows.Close()
		
		// Store in Redis with expiration
		metricsJSON, _ := json.Marshal(metrics)
		s.redis.Set(ctx, "analytics:realtime:metrics", metricsJSON, time.Minute*5)
	}
}

func (s *AnalyticsService) generatePeriodicReports() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Refresh materialized view
		_, err := s.db.Exec("REFRESH MATERIALIZED VIEW campaign_stats")
		if err != nil {
			log.Printf("Error refreshing campaign stats: %v", err)
		}

		// Aggregate hourly statistics
		s.aggregateHourlyStats()
	}
}

func (s *AnalyticsService) aggregateHourlyStats() {
	query := `
		INSERT INTO email_stats_hourly (hour_timestamp, campaign_id, sent_count, delivered_count, opened_count, clicked_count, bounced_count, unsubscribed_count)
		SELECT 
			DATE_TRUNC('hour', timestamp) as hour_timestamp,
			campaign_id,
			COUNT(CASE WHEN event_type = 'sent' THEN 1 END) as sent_count,
			COUNT(CASE WHEN event_type = 'delivered' THEN 1 END) as delivered_count,
			COUNT(CASE WHEN event_type = 'opened' THEN 1 END) as opened_count,
			COUNT(CASE WHEN event_type = 'clicked' THEN 1 END) as clicked_count,
			COUNT(CASE WHEN event_type = 'bounced' THEN 1 END) as bounced_count,
			COUNT(CASE WHEN event_type = 'unsubscribed' THEN 1 END) as unsubscribed_count
		FROM email_events 
		WHERE timestamp >= DATE_TRUNC('hour', NOW() - INTERVAL '1 hour')
			AND timestamp < DATE_TRUNC('hour', NOW())
		GROUP BY DATE_TRUNC('hour', timestamp), campaign_id
		ON CONFLICT (hour_timestamp, campaign_id) DO UPDATE SET
			sent_count = EXCLUDED.sent_count,
			delivered_count = EXCLUDED.delivered_count,
			opened_count = EXCLUDED.opened_count,
			clicked_count = EXCLUDED.clicked_count,
			bounced_count = EXCLUDED.bounced_count,
			unsubscribed_count = EXCLUDED.unsubscribed_count
	`
	
	_, err := s.db.Exec(query)
	if err != nil {
		log.Printf("Error aggregating hourly stats: %v", err)
	}
}

func (s *AnalyticsService) storeEvent(event EmailEvent) error {
	query := `
		INSERT INTO email_events (email_id, campaign_id, contact_id, event_type, user_agent, ip_address, url, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	
	_, err := s.db.Exec(query, event.EmailID, event.CampaignID, event.ContactID, 
		event.EventType, event.UserAgent, event.IPAddress, event.URL, event.Timestamp)
	return err
}

func (s *AnalyticsService) trackEvent(c *gin.Context) {
	var event EmailEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		eventsProcessed.WithLabelValues("unknown", "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	event.Timestamp = time.Now()

	// Queue event for processing
	eventJSON, _ := json.Marshal(event)
	err := s.redis.LPush(context.Background(), "analytics:events", eventJSON).Err()
	if err != nil {
		eventsProcessed.WithLabelValues(event.EventType, "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to queue event"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"message": "Event queued for processing"})
}

func (s *AnalyticsService) trackBulkEvents(c *gin.Context) {
	var events []EmailEvent
	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	pipe := s.redis.Pipeline()

	for _, event := range events {
		event.Timestamp = time.Now()
		eventJSON, _ := json.Marshal(event)
		pipe.LPush(ctx, "analytics:events", eventJSON)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to queue events"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"message": fmt.Sprintf("%d events queued for processing", len(events))})
}

func (s *AnalyticsService) getCampaignStats(c *gin.Context) {
	start := time.Now()
	defer func() {
		queryDuration.WithLabelValues("campaign_stats").Observe(time.Since(start).Seconds())
	}()

	campaignID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid campaign ID"})
		return
	}

	// Try cache first
	cacheKey := fmt.Sprintf("analytics:campaign:%d:stats", campaignID)
	cachedStats, err := s.redis.Get(context.Background(), cacheKey).Result()
	if err == nil {
		cacheHitRate.WithLabelValues("campaign_stats").Inc()
		var stats CampaignStats
		if json.Unmarshal([]byte(cachedStats), &stats) == nil {
			c.JSON(http.StatusOK, stats)
			return
		}
	}

	var stats CampaignStats
	query := `
		SELECT campaign_id, campaign_name, total_sent, total_delivered, total_opened, 
			total_clicked, total_bounced, total_unsubscribed, open_rate, click_rate, bounce_rate, created_at
		FROM campaign_stats 
		WHERE campaign_id = $1
	`

	err = s.db.QueryRow(query, campaignID).Scan(
		&stats.CampaignID, &stats.CampaignName, &stats.TotalSent, &stats.TotalDelivered,
		&stats.TotalOpened, &stats.TotalClicked, &stats.TotalBounced, &stats.TotalUnsubscribed,
		&stats.OpenRate, &stats.ClickRate, &stats.BounceRate, &stats.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Campaign not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch campaign stats"})
		}
		return
	}

	// Calculate unsubscribe rate
	if stats.TotalSent > 0 {
		stats.UnsubscribeRate = float64(stats.TotalUnsubscribed) / float64(stats.TotalSent) * 100
	}

	// Cache the result
	statsJSON, _ := json.Marshal(stats)
	s.redis.Set(context.Background(), cacheKey, statsJSON, time.Minute*5)

	reportsGenerated.WithLabelValues("campaign_stats", "success").Inc()
	c.JSON(http.StatusOK, stats)
}

func (s *AnalyticsService) getDashboardMetrics(c *gin.Context) {
	start := time.Now()
	defer func() {
		queryDuration.WithLabelValues("dashboard").Observe(time.Since(start).Seconds())
	}()

	// Try cache first
	cacheKey := "analytics:dashboard:metrics"
	cachedMetrics, err := s.redis.Get(context.Background(), cacheKey).Result()
	if err == nil {
		cacheHitRate.WithLabelValues("dashboard").Inc()
		var metrics DashboardMetrics
		if json.Unmarshal([]byte(cachedMetrics), &metrics) == nil {
			c.JSON(http.StatusOK, metrics)
			return
		}
	}

	var metrics DashboardMetrics

	// Get overall statistics
	query := `
		SELECT 
			COUNT(CASE WHEN event_type = 'sent' THEN 1 END) as total_sent,
			COUNT(CASE WHEN event_type = 'delivered' THEN 1 END) as total_delivered,
			COUNT(CASE WHEN event_type = 'opened' THEN 1 END) as total_opened,
			COUNT(CASE WHEN event_type = 'clicked' THEN 1 END) as total_clicked
		FROM email_events
		WHERE timestamp >= CURRENT_DATE - INTERVAL '30 days'
	`

	err = s.db.QueryRow(query).Scan(
		&metrics.TotalEmailsSent, &metrics.TotalEmailsDelivered,
		&metrics.TotalEmailsOpened, &metrics.TotalEmailsClicked)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dashboard metrics"})
		return
	}

	// Calculate rates
	if metrics.TotalEmailsDelivered > 0 {
		metrics.OverallOpenRate = float64(metrics.TotalEmailsOpened) / float64(metrics.TotalEmailsDelivered) * 100
	}
	if metrics.TotalEmailsOpened > 0 {
		metrics.OverallClickRate = float64(metrics.TotalEmailsClicked) / float64(metrics.TotalEmailsOpened) * 100
	}

	// Get active campaigns count (placeholder - would need campaigns table)
	metrics.ActiveCampaigns = 0

	// Get total contacts (placeholder - would need contacts table)
	metrics.TotalContacts = 0

	// Get recent activity
	recentQuery := `
		SELECT id, email_id, campaign_id, contact_id, event_type, user_agent, ip_address, url, timestamp
		FROM email_events
		ORDER BY timestamp DESC
		LIMIT 10
	`

	rows, err := s.db.Query(recentQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var event EmailEvent
			rows.Scan(&event.ID, &event.EmailID, &event.CampaignID, &event.ContactID,
				&event.EventType, &event.UserAgent, &event.IPAddress, &event.URL, &event.Timestamp)
			metrics.RecentActivity = append(metrics.RecentActivity, event)
		}
	}

	// Cache the result
	metricsJSON, _ := json.Marshal(metrics)
	s.redis.Set(context.Background(), cacheKey, metricsJSON, time.Minute*2)

	reportsGenerated.WithLabelValues("dashboard", "success").Inc()
	c.JSON(http.StatusOK, metrics)
}

func (s *AnalyticsService) getRealtimeMetrics(c *gin.Context) {
	// Get real-time metrics from Redis
	metricsJSON, err := s.redis.Get(context.Background(), "analytics:realtime:metrics").Result()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"metrics": map[string]int{}})
		return
	}

	var metrics map[string]int
	if err := json.Unmarshal([]byte(metricsJSON), &metrics); err != nil {
		c.JSON(http.StatusOK, gin.H{"metrics": map[string]int{}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}

func (s *AnalyticsService) getHourlyTimeSeries(c *gin.Context) {
	start := time.Now()
	defer func() {
		queryDuration.WithLabelValues("hourly_timeseries").Observe(time.Since(start).Seconds())
	}()

	campaignID := c.Query("campaign_id")
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))

	var query string
	var args []interface{}

	if campaignID != "" {
		query = `
			SELECT hour_timestamp, sent_count, delivered_count, opened_count, clicked_count, bounced_count
			FROM email_stats_hourly
			WHERE campaign_id = $1 AND hour_timestamp >= NOW() - INTERVAL '%d hours'
			ORDER BY hour_timestamp
		`
		query = fmt.Sprintf(query, hours)
		args = append(args, campaignID)
	} else {
		query = `
			SELECT hour_timestamp, 
				SUM(sent_count) as sent_count,
				SUM(delivered_count) as delivered_count,
				SUM(opened_count) as opened_count,
				SUM(clicked_count) as clicked_count,
				SUM(bounced_count) as bounced_count
			FROM email_stats_hourly
			WHERE hour_timestamp >= NOW() - INTERVAL '%d hours'
			GROUP BY hour_timestamp
			ORDER BY hour_timestamp
		`
		query = fmt.Sprintf(query, hours)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch time series data"})
		return
	}
	defer rows.Close()

	var timeSeries []TimeSeriesData
	for rows.Next() {
		var data TimeSeriesData
		err := rows.Scan(&data.Timestamp, &data.Sent, &data.Delivered, &data.Opened, &data.Clicked, &data.Bounced)
		if err != nil {
			continue
		}
		timeSeries = append(timeSeries, data)
	}

	reportsGenerated.WithLabelValues("hourly_timeseries", "success").Inc()
	c.JSON(http.StatusOK, gin.H{"timeseries": timeSeries})
}

func (s *AnalyticsService) getSummaryReport(c *gin.Context) {
	start := time.Now()
	defer func() {
		queryDuration.WithLabelValues("summary_report").Observe(time.Since(start).Seconds())
	}()

	dateFrom := c.DefaultQuery("from", time.Now().AddDate(0, 0, -30).Format("2006-01-02"))
	dateTo := c.DefaultQuery("to", time.Now().Format("2006-01-02"))

	query := `
		SELECT 
			COUNT(CASE WHEN event_type = 'sent' THEN 1 END) as total_sent,
			COUNT(CASE WHEN event_type = 'delivered' THEN 1 END) as total_delivered,
			COUNT(CASE WHEN event_type = 'opened' THEN 1 END) as total_opened,
			COUNT(CASE WHEN event_type = 'clicked' THEN 1 END) as total_clicked,
			COUNT(CASE WHEN event_type = 'bounced' THEN 1 END) as total_bounced,
			COUNT(CASE WHEN event_type = 'unsubscribed' THEN 1 END) as total_unsubscribed,
			COUNT(DISTINCT campaign_id) as total_campaigns,
			COUNT(DISTINCT contact_id) as unique_recipients
		FROM email_events
		WHERE DATE(timestamp) BETWEEN $1 AND $2
	`

	var report struct {
		TotalSent         int `json:"total_sent"`
		TotalDelivered    int `json:"total_delivered"`
		TotalOpened       int `json:"total_opened"`
		TotalClicked      int `json:"total_clicked"`
		TotalBounced      int `json:"total_bounced"`
		TotalUnsubscribed int `json:"total_unsubscribed"`
		TotalCampaigns    int `json:"total_campaigns"`
		UniqueRecipients  int `json:"unique_recipients"`
		DateFrom          string `json:"date_from"`
		DateTo            string `json:"date_to"`
	}

	err := s.db.QueryRow(query, dateFrom, dateTo).Scan(
		&report.TotalSent, &report.TotalDelivered, &report.TotalOpened,
		&report.TotalClicked, &report.TotalBounced, &report.TotalUnsubscribed,
		&report.TotalCampaigns, &report.UniqueRecipients)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate summary report"})
		return
	}

	report.DateFrom = dateFrom
	report.DateTo = dateTo

	reportsGenerated.WithLabelValues("summary_report", "success").Inc()
	c.JSON(http.StatusOK, report)
}

// Placeholder implementations for other endpoints
func (s *AnalyticsService) getCampaignTimeline(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Campaign timeline endpoint - implementation pending"})
}

func (s *AnalyticsService) getCampaignHeatmap(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Campaign heatmap endpoint - implementation pending"})
}

func (s *AnalyticsService) getPerformanceReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Performance report endpoint - implementation pending"})
}

func (s *AnalyticsService) getEngagementReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Engagement report endpoint - implementation pending"})
}

func (s *AnalyticsService) getTrendsReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Trends report endpoint - implementation pending"})
}

func (s *AnalyticsService) getDailyTimeSeries(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Daily time series endpoint - implementation pending"})
}

func (s *AnalyticsService) getWeeklyTimeSeries(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Weekly time series endpoint - implementation pending"})
}

func (s *AnalyticsService) getCohortAnalysis(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Cohort analysis endpoint - implementation pending"})
}

func (s *AnalyticsService) getFunnelAnalysis(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Funnel analysis endpoint - implementation pending"})
}

func (s *AnalyticsService) getSegmentationAnalysis(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Segmentation analysis endpoint - implementation pending"})
}

func (s *AnalyticsService) exportCampaignData(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Campaign data export endpoint - implementation pending"})
}

func (s *AnalyticsService) exportEventData(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Event data export endpoint - implementation pending"})
}