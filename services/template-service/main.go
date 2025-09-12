package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	htmlTemplate "html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	textTemplate "text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// EmailTemplate represents an email template
type EmailTemplate struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Subject     string    `json:"subject" db:"subject"`
	HTMLContent string    `json:"html_content" db:"html_content"`
	TextContent string    `json:"text_content" db:"text_content"`
	Category    string    `json:"category" db:"category"`
	Tags        []string  `json:"tags" db:"tags"`
	Variables   []string  `json:"variables" db:"variables"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	Version     int       `json:"version" db:"version"`
	CreatedBy   int       `json:"created_by" db:"created_by"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// TemplateVersion represents a template version history
type TemplateVersion struct {
	ID          int       `json:"id" db:"id"`
	TemplateID  int       `json:"template_id" db:"template_id"`
	Version     int       `json:"version" db:"version"`
	Subject     string    `json:"subject" db:"subject"`
	HTMLContent string    `json:"html_content" db:"html_content"`
	TextContent string    `json:"text_content" db:"text_content"`
	Changelog   string    `json:"changelog" db:"changelog"`
	CreatedBy   int       `json:"created_by" db:"created_by"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// TemplateCategory represents template categories
type TemplateCategory struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Color       string    `json:"color" db:"color"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// RenderRequest represents a template render request
type RenderRequest struct {
	TemplateID int                    `json:"template_id"`
	Variables  map[string]interface{} `json:"variables"`
	Format     string                 `json:"format"` // html, text, both
}

// RenderResponse represents a template render response
type RenderResponse struct {
	Subject     string `json:"subject"`
	HTMLContent string `json:"html_content,omitempty"`
	TextContent string `json:"text_content,omitempty"`
	RenderedAt  time.Time `json:"rendered_at"`
}

// TemplatePreview represents a template preview
type TemplatePreview struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Subject  string `json:"subject"`
	Category string `json:"category"`
	Tags     []string `json:"tags"`
	Version  int    `json:"version"`
	IsActive bool   `json:"is_active"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TemplateStats represents template usage statistics
type TemplateStats struct {
	TemplateID    int `json:"template_id"`
	UsageCount    int `json:"usage_count"`
	LastUsed      *time.Time `json:"last_used"`
	SuccessRate   float64 `json:"success_rate"`
	AverageRating float64 `json:"average_rating"`
}

// TemplateService handles template operations
type TemplateService struct {
	db    *sql.DB
	redis *redis.Client
}

// Prometheus metrics
var (
	templatesCreated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "templates_created_total",
			Help: "Total number of templates created",
		},
		[]string{"category", "status"},
	)

	templatesRendered = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "templates_rendered_total",
			Help: "Total number of templates rendered",
		},
		[]string{"template_id", "format", "status"},
	)

	renderDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "template_render_duration_seconds",
			Help: "Duration of template rendering",
		},
		[]string{"template_id", "format"},
	)

	cacheHitRate = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "template_cache_hits_total",
			Help: "Total number of template cache hits",
		},
		[]string{"cache_type"},
	)
)

func init() {
	prometheus.MustRegister(templatesCreated)
	prometheus.MustRegister(templatesRendered)
	prometheus.MustRegister(renderDuration)
	prometheus.MustRegister(cacheHitRate)
}

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://billionmail_user:billionmail_pass@postgres:5432/billionmail_templates?sslmode=disable"
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
		DB:   4, // Use DB 4 for templates
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

	service := &TemplateService{
		db:    db,
		redis: rdb,
	}

	// Start background workers
	go service.updateTemplateStats()
	go service.cleanupOldVersions()

	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "template-service"})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Template endpoints
	v1 := router.Group("/api/v1")
	{
		// Template CRUD operations
		v1.POST("/templates", service.createTemplate)
		v1.GET("/templates", service.listTemplates)
		v1.GET("/templates/:id", service.getTemplate)
		v1.PUT("/templates/:id", service.updateTemplate)
		v1.DELETE("/templates/:id", service.deleteTemplate)

		// Template versions
		v1.GET("/templates/:id/versions", service.getTemplateVersions)
		v1.GET("/templates/:id/versions/:version", service.getTemplateVersion)
		v1.POST("/templates/:id/versions", service.createTemplateVersion)
		v1.POST("/templates/:id/revert/:version", service.revertToVersion)

		// Template rendering
		v1.POST("/templates/render", service.renderTemplate)
		v1.POST("/templates/:id/render", service.renderTemplateByID)
		v1.POST("/templates/:id/preview", service.previewTemplate)

		// Template categories
		v1.GET("/categories", service.listCategories)
		v1.POST("/categories", service.createCategory)
		v1.PUT("/categories/:id", service.updateCategory)
		v1.DELETE("/categories/:id", service.deleteCategory)

		// Template management
		v1.POST("/templates/:id/clone", service.cloneTemplate)
		v1.POST("/templates/:id/activate", service.activateTemplate)
		v1.POST("/templates/:id/deactivate", service.deactivateTemplate)
		v1.POST("/templates/bulk-update", service.bulkUpdateTemplates)

		// Template analytics
		v1.GET("/templates/:id/stats", service.getTemplateStats)
		v1.GET("/templates/popular", service.getPopularTemplates)
		v1.GET("/templates/recent", service.getRecentTemplates)

		// Template validation
		v1.POST("/templates/validate", service.validateTemplate)
		v1.POST("/templates/:id/test", service.testTemplate)

		// Template export/import
		v1.GET("/templates/:id/export", service.exportTemplate)
		v1.POST("/templates/import", service.importTemplate)
		v1.POST("/templates/bulk-import", service.bulkImportTemplates)

		// Template search
		v1.GET("/templates/search", service.searchTemplates)
		v1.GET("/templates/tags", service.getTemplateTags)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8006"
	}

	log.Printf("Template service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func initSchema(db *sql.DB) error {
	schema := `
	-- Template categories table
	CREATE TABLE IF NOT EXISTS template_categories (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		color VARCHAR(7) DEFAULT '#007bff',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Email templates table
	CREATE TABLE IF NOT EXISTS email_templates (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		subject VARCHAR(500) NOT NULL,
		html_content TEXT NOT NULL,
		text_content TEXT,
		category VARCHAR(100) REFERENCES template_categories(name) ON UPDATE CASCADE,
		tags TEXT[], -- Array of tags
		variables TEXT[], -- Array of variable names
		is_active BOOLEAN DEFAULT true,
		version INTEGER DEFAULT 1,
		created_by INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Template versions table
	CREATE TABLE IF NOT EXISTS template_versions (
		id SERIAL PRIMARY KEY,
		template_id INTEGER REFERENCES email_templates(id) ON DELETE CASCADE,
		version INTEGER NOT NULL,
		subject VARCHAR(500) NOT NULL,
		html_content TEXT NOT NULL,
		text_content TEXT,
		changelog TEXT,
		created_by INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(template_id, version)
	);

	-- Template usage statistics
	CREATE TABLE IF NOT EXISTS template_stats (
		id SERIAL PRIMARY KEY,
		template_id INTEGER REFERENCES email_templates(id) ON DELETE CASCADE,
		usage_count INTEGER DEFAULT 0,
		last_used TIMESTAMP,
		success_count INTEGER DEFAULT 0,
		failure_count INTEGER DEFAULT 0,
		total_rating INTEGER DEFAULT 0,
		rating_count INTEGER DEFAULT 0,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(template_id)
	);

	-- Template render cache
	CREATE TABLE IF NOT EXISTS template_render_cache (
		id SERIAL PRIMARY KEY,
		template_id INTEGER REFERENCES email_templates(id) ON DELETE CASCADE,
		variables_hash VARCHAR(64) NOT NULL,
		rendered_subject TEXT,
		rendered_html TEXT,
		rendered_text TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '1 hour'),
		UNIQUE(template_id, variables_hash)
	);

	-- Insert default categories
	INSERT INTO template_categories (name, description, color) VALUES 
		('Welcome', 'Welcome and onboarding emails', '#28a745'),
		('Newsletter', 'Regular newsletter templates', '#007bff'),
		('Promotional', 'Marketing and promotional emails', '#ffc107'),
		('Transactional', 'Order confirmations, receipts, etc.', '#6c757d'),
		('Notification', 'System notifications and alerts', '#17a2b8')
	ON CONFLICT (name) DO NOTHING;

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_email_templates_category ON email_templates(category);
	CREATE INDEX IF NOT EXISTS idx_email_templates_is_active ON email_templates(is_active);
	CREATE INDEX IF NOT EXISTS idx_email_templates_created_at ON email_templates(created_at);
	CREATE INDEX IF NOT EXISTS idx_email_templates_tags ON email_templates USING GIN(tags);
	CREATE INDEX IF NOT EXISTS idx_template_versions_template_id ON template_versions(template_id);
	CREATE INDEX IF NOT EXISTS idx_template_stats_template_id ON template_stats(template_id);
	CREATE INDEX IF NOT EXISTS idx_template_render_cache_expires ON template_render_cache(expires_at);

	-- Function to update updated_at timestamp
	CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $$
	BEGIN
		NEW.updated_at = CURRENT_TIMESTAMP;
		RETURN NEW;
	END;
	$$ language 'plpgsql';

	-- Trigger to automatically update updated_at
	DROP TRIGGER IF EXISTS update_email_templates_updated_at ON email_templates;
	CREATE TRIGGER update_email_templates_updated_at
		BEFORE UPDATE ON email_templates
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

	DROP TRIGGER IF EXISTS update_template_stats_updated_at ON template_stats;
	CREATE TRIGGER update_template_stats_updated_at
		BEFORE UPDATE ON template_stats
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
	`

	_, err := db.Exec(schema)
	return err
}

func (s *TemplateService) updateTemplateStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Clean up expired cache entries
		_, err := s.db.Exec("DELETE FROM template_render_cache WHERE expires_at < CURRENT_TIMESTAMP")
		if err != nil {
			log.Printf("Error cleaning up render cache: %v", err)
		}

		// Update template statistics from Redis counters
		ctx := context.Background()
		keys, err := s.redis.Keys(ctx, "template:stats:*").Result()
		if err != nil {
			continue
		}

		for _, key := range keys {
			parts := strings.Split(key, ":")
			if len(parts) != 3 {
				continue
			}

			templateID, err := strconv.Atoi(parts[2])
			if err != nil {
				continue
			}

			count, err := s.redis.Get(ctx, key).Int()
			if err != nil {
				continue
			}

			// Update database stats
			query := `
				INSERT INTO template_stats (template_id, usage_count, last_used)
				VALUES ($1, $2, CURRENT_TIMESTAMP)
				ON CONFLICT (template_id) DO UPDATE SET
					usage_count = template_stats.usage_count + $2,
					last_used = CURRENT_TIMESTAMP
			`
			s.db.Exec(query, templateID, count)

			// Reset Redis counter
			s.redis.Del(ctx, key)
		}
	}
}

func (s *TemplateService) cleanupOldVersions() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Keep only the last 10 versions of each template
		query := `
			DELETE FROM template_versions 
			WHERE id IN (
				SELECT id FROM (
					SELECT id, ROW_NUMBER() OVER (PARTITION BY template_id ORDER BY version DESC) as rn
					FROM template_versions
				) t WHERE rn > 10
			)
		`
		_, err := s.db.Exec(query)
		if err != nil {
			log.Printf("Error cleaning up old template versions: %v", err)
		}
	}
}

func (s *TemplateService) createTemplate(c *gin.Context) {
	var template EmailTemplate
	if err := c.ShouldBindJSON(&template); err != nil {
		templatesCreated.WithLabelValues("unknown", "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if template.Name == "" || template.Subject == "" || template.HTMLContent == "" {
		templatesCreated.WithLabelValues(template.Category, "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name, subject, and HTML content are required"})
		return
	}

	// Extract variables from template content
	template.Variables = extractVariables(template.HTMLContent, template.TextContent, template.Subject)

	query := `
		INSERT INTO email_templates (name, subject, html_content, text_content, category, tags, variables, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`

	err := s.db.QueryRow(query, template.Name, template.Subject, template.HTMLContent,
		template.TextContent, template.Category, template.Tags, template.Variables, template.CreatedBy).Scan(
		&template.ID, &template.CreatedAt, &template.UpdatedAt)

	if err != nil {
		templatesCreated.WithLabelValues(template.Category, "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create template"})
		return
	}

	// Create initial version
	versionQuery := `
		INSERT INTO template_versions (template_id, version, subject, html_content, text_content, changelog, created_by)
		VALUES ($1, 1, $2, $3, $4, 'Initial version', $5)
	`
	s.db.Exec(versionQuery, template.ID, template.Subject, template.HTMLContent, template.TextContent, template.CreatedBy)

	// Initialize stats
	statsQuery := `INSERT INTO template_stats (template_id) VALUES ($1)`
	s.db.Exec(statsQuery, template.ID)

	templatesCreated.WithLabelValues(template.Category, "success").Inc()
	c.JSON(http.StatusCreated, template)
}

func (s *TemplateService) listTemplates(c *gin.Context) {
	category := c.Query("category")
	active := c.Query("active")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	var conditions []string
	var args []interface{}
	argIndex := 1

	if category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, category)
		argIndex++
	}

	if active != "" {
		isActive := active == "true"
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, isActive)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT id, name, subject, category, tags, version, is_active, updated_at
		FROM email_templates
		%s
		ORDER BY updated_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch templates"})
		return
	}
	defer rows.Close()

	var templates []TemplatePreview
	for rows.Next() {
		var template TemplatePreview
		var tags []string
		err := rows.Scan(&template.ID, &template.Name, &template.Subject,
			&template.Category, &tags, &template.Version, &template.IsActive, &template.UpdatedAt)
		if err != nil {
			continue
		}
		template.Tags = tags
		templates = append(templates, template)
	}

	c.JSON(http.StatusOK, gin.H{"templates": templates, "total": len(templates)})
}

func (s *TemplateService) getTemplate(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	// Try cache first
	cacheKey := fmt.Sprintf("template:%d", id)
	cachedTemplate, err := s.redis.Get(context.Background(), cacheKey).Result()
	if err == nil {
		cacheHitRate.WithLabelValues("template").Inc()
		var template EmailTemplate
		if json.Unmarshal([]byte(cachedTemplate), &template) == nil {
			c.JSON(http.StatusOK, template)
			return
		}
	}

	var template EmailTemplate
	query := `
		SELECT id, name, subject, html_content, text_content, category, tags, variables,
			is_active, version, created_by, created_at, updated_at
		FROM email_templates
		WHERE id = $1
	`

	err = s.db.QueryRow(query, id).Scan(
		&template.ID, &template.Name, &template.Subject, &template.HTMLContent,
		&template.TextContent, &template.Category, &template.Tags, &template.Variables,
		&template.IsActive, &template.Version, &template.CreatedBy,
		&template.CreatedAt, &template.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch template"})
		}
		return
	}

	// Cache the result
	templateJSON, _ := json.Marshal(template)
	s.redis.Set(context.Background(), cacheKey, templateJSON, time.Hour)

	c.JSON(http.StatusOK, template)
}

func (s *TemplateService) renderTemplate(c *gin.Context) {
	start := time.Now()

	var request RenderRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		templatesRendered.WithLabelValues("unknown", "unknown", "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	defer func() {
		renderDuration.WithLabelValues(strconv.Itoa(request.TemplateID), request.Format).Observe(time.Since(start).Seconds())
	}()

	// Get template
	var template EmailTemplate
	query := `
		SELECT id, subject, html_content, text_content
		FROM email_templates
		WHERE id = $1 AND is_active = true
	`

	err := s.db.QueryRow(query, request.TemplateID).Scan(
		&template.ID, &template.Subject, &template.HTMLContent, &template.TextContent)

	if err != nil {
		templatesRendered.WithLabelValues(strconv.Itoa(request.TemplateID), request.Format, "error").Inc()
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found or inactive"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch template"})
		}
		return
	}

	// Render template
	response, err := s.renderTemplateContent(template, request.Variables, request.Format)
	if err != nil {
		templatesRendered.WithLabelValues(strconv.Itoa(request.TemplateID), request.Format, "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to render template: " + err.Error()})
		return
	}

	// Update usage stats in Redis
	ctx := context.Background()
	statsKey := fmt.Sprintf("template:stats:%d", request.TemplateID)
	s.redis.Incr(ctx, statsKey)
	s.redis.Expire(ctx, statsKey, time.Hour)

	templatesRendered.WithLabelValues(strconv.Itoa(request.TemplateID), request.Format, "success").Inc()
	c.JSON(http.StatusOK, response)
}

func (s *TemplateService) renderTemplateContent(template EmailTemplate, variables map[string]interface{}, format string) (*RenderResponse, error) {
	response := &RenderResponse{
		RenderedAt: time.Now(),
	}

	// Render subject
	subjectTmpl, err := textTemplate.New("subject").Parse(template.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject template: %v", err)
	}

	var subjectBuf strings.Builder
	if err := subjectTmpl.Execute(&subjectBuf, variables); err != nil {
		return nil, fmt.Errorf("failed to render subject: %v", err)
	}
	response.Subject = subjectBuf.String()

	// Render HTML content if requested
	if format == "html" || format == "both" {
		htmlTmpl, err := htmlTemplate.New("html").Parse(template.HTMLContent)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HTML template: %v", err)
		}

		var htmlBuf strings.Builder
		if err := htmlTmpl.Execute(&htmlBuf, variables); err != nil {
			return nil, fmt.Errorf("failed to render HTML: %v", err)
		}
		response.HTMLContent = htmlBuf.String()
	}

	// Render text content if requested
	if (format == "text" || format == "both") && template.TextContent != "" {
		textTmpl, err := textTemplate.New("text").Parse(template.TextContent)
		if err != nil {
			return nil, fmt.Errorf("failed to parse text template: %v", err)
		}

		var textBuf strings.Builder
		if err := textTmpl.Execute(&textBuf, variables); err != nil {
			return nil, fmt.Errorf("failed to render text: %v", err)
		}
		response.TextContent = textBuf.String()
	}

	return response, nil
}

func extractVariables(htmlContent, textContent, subject string) []string {
	variables := make(map[string]bool)

	// Extract from HTML content
	_, err := htmlTemplate.New("html").Parse(htmlContent)
	if err == nil {
		// This is a simplified extraction - in a real implementation,
		// you'd want to parse the template AST to extract variable names
		// For now, we'll use a simple regex-based approach
	}

	// Extract from text content
	if textContent != "" {
		_, err = textTemplate.New("text").Parse(textContent)
		if err == nil {
			// Similar extraction logic
		}
	}

	// Extract from subject
	_, err = textTemplate.New("subject").Parse(subject)
	if err == nil {
		// Similar extraction logic
	}

	// Convert map to slice
	var result []string
	for variable := range variables {
		result = append(result, variable)
	}

	return result
}

// Placeholder implementations for other endpoints
func (s *TemplateService) updateTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Update template endpoint - implementation pending"})
}

func (s *TemplateService) deleteTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Delete template endpoint - implementation pending"})
}

func (s *TemplateService) getTemplateVersions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Get template versions endpoint - implementation pending"})
}

func (s *TemplateService) getTemplateVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Get template version endpoint - implementation pending"})
}

func (s *TemplateService) createTemplateVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Create template version endpoint - implementation pending"})
}

func (s *TemplateService) revertToVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Revert to version endpoint - implementation pending"})
}

func (s *TemplateService) renderTemplateByID(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Render template by ID endpoint - implementation pending"})
}

func (s *TemplateService) previewTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Preview template endpoint - implementation pending"})
}

func (s *TemplateService) listCategories(c *gin.Context) {
	rows, err := s.db.Query("SELECT id, name, description, color, created_at FROM template_categories ORDER BY name")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch categories"})
		return
	}
	defer rows.Close()

	var categories []TemplateCategory
	for rows.Next() {
		var category TemplateCategory
		rows.Scan(&category.ID, &category.Name, &category.Description, &category.Color, &category.CreatedAt)
		categories = append(categories, category)
	}

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

func (s *TemplateService) createCategory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Create category endpoint - implementation pending"})
}

func (s *TemplateService) updateCategory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Update category endpoint - implementation pending"})
}

func (s *TemplateService) deleteCategory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Delete category endpoint - implementation pending"})
}

func (s *TemplateService) cloneTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Clone template endpoint - implementation pending"})
}

func (s *TemplateService) activateTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Activate template endpoint - implementation pending"})
}

func (s *TemplateService) deactivateTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Deactivate template endpoint - implementation pending"})
}

func (s *TemplateService) bulkUpdateTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Bulk update templates endpoint - implementation pending"})
}

func (s *TemplateService) getTemplateStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Get template stats endpoint - implementation pending"})
}

func (s *TemplateService) getPopularTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Get popular templates endpoint - implementation pending"})
}

func (s *TemplateService) getRecentTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Get recent templates endpoint - implementation pending"})
}

func (s *TemplateService) validateTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Validate template endpoint - implementation pending"})
}

func (s *TemplateService) testTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Test template endpoint - implementation pending"})
}

func (s *TemplateService) exportTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Export template endpoint - implementation pending"})
}

func (s *TemplateService) importTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Import template endpoint - implementation pending"})
}

func (s *TemplateService) bulkImportTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Bulk import templates endpoint - implementation pending"})
}

func (s *TemplateService) searchTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Search templates endpoint - implementation pending"})
}

func (s *TemplateService) getTemplateTags(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Get template tags endpoint - implementation pending"})
}