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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Contact represents a contact in the system
type Contact struct {
	ID          int       `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	FirstName   string    `json:"first_name" db:"first_name"`
	LastName    string    `json:"last_name" db:"last_name"`
	Phone       string    `json:"phone" db:"phone"`
	Company     string    `json:"company" db:"company"`
	Tags        []string  `json:"tags" db:"tags"`
	CustomData  string    `json:"custom_data" db:"custom_data"`
	Subscribed  bool      `json:"subscribed" db:"subscribed"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ContactList represents a contact list
type ContactList struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	UserID      int       `json:"user_id" db:"user_id"`
	ContactCount int      `json:"contact_count" db:"contact_count"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ContactService handles contact operations
type ContactService struct {
	db    *sql.DB
	redis *redis.Client
}

// Prometheus metrics
var (
	contactsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "contacts_total",
			Help: "Total number of contacts processed",
		},
		[]string{"operation", "status"},
	)

	listsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "contact_lists_total",
			Help: "Total number of contact lists processed",
		},
		[]string{"operation", "status"},
	)

	contactOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "contact_operation_duration_seconds",
			Help: "Duration of contact operations",
		},
		[]string{"operation"},
	)

	activeContacts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_contacts_count",
			Help: "Number of active contacts",
		},
	)
)

func init() {
	prometheus.MustRegister(contactsTotal)
	prometheus.MustRegister(listsTotal)
	prometheus.MustRegister(contactOperationDuration)
	prometheus.MustRegister(activeContacts)
}

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://billionmail_user:billionmail_pass@postgres:5432/billionmail_contacts?sslmode=disable"
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
		DB:   2, // Use DB 2 for contacts
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

	service := &ContactService{
		db:    db,
		redis: rdb,
	}

	// Update metrics periodically
	go service.updateMetrics()

	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "contact-service"})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Contact endpoints
	v1 := router.Group("/api/v1")
	{
		// Contact management
		v1.POST("/contacts", service.createContact)
		v1.GET("/contacts", service.getContacts)
		v1.GET("/contacts/:id", service.getContact)
		v1.PUT("/contacts/:id", service.updateContact)
		v1.DELETE("/contacts/:id", service.deleteContact)
		v1.POST("/contacts/bulk", service.bulkImportContacts)
		v1.POST("/contacts/export", service.exportContacts)

		// Contact list management
		v1.POST("/lists", service.createList)
		v1.GET("/lists", service.getLists)
		v1.GET("/lists/:id", service.getList)
		v1.PUT("/lists/:id", service.updateList)
		v1.DELETE("/lists/:id", service.deleteList)

		// List-Contact associations
		v1.POST("/lists/:id/contacts", service.addContactsToList)
		v1.DELETE("/lists/:id/contacts", service.removeContactsFromList)
		v1.GET("/lists/:id/contacts", service.getListContacts)

		// Search and filtering
		v1.GET("/contacts/search", service.searchContacts)
		v1.GET("/contacts/filter", service.filterContacts)

		// Subscription management
		v1.POST("/contacts/:id/subscribe", service.subscribeContact)
		v1.POST("/contacts/:id/unsubscribe", service.unsubscribeContact)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8004"
	}

	log.Printf("Contact service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func initSchema(db *sql.DB) error {
	schema := `
	-- Contacts table
	CREATE TABLE IF NOT EXISTS contacts (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		first_name VARCHAR(100),
		last_name VARCHAR(100),
		phone VARCHAR(20),
		company VARCHAR(100),
		tags TEXT[],
		custom_data JSONB,
		subscribed BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Contact lists table
	CREATE TABLE IF NOT EXISTS contact_lists (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		user_id INTEGER NOT NULL,
		contact_count INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- List-Contact associations
	CREATE TABLE IF NOT EXISTS list_contacts (
		id SERIAL PRIMARY KEY,
		list_id INTEGER REFERENCES contact_lists(id) ON DELETE CASCADE,
		contact_id INTEGER REFERENCES contacts(id) ON DELETE CASCADE,
		added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(list_id, contact_id)
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
	CREATE INDEX IF NOT EXISTS idx_contacts_subscribed ON contacts(subscribed);
	CREATE INDEX IF NOT EXISTS idx_contacts_tags ON contacts USING GIN(tags);
	CREATE INDEX IF NOT EXISTS idx_contacts_custom_data ON contacts USING GIN(custom_data);
	CREATE INDEX IF NOT EXISTS idx_list_contacts_list_id ON list_contacts(list_id);
	CREATE INDEX IF NOT EXISTS idx_list_contacts_contact_id ON list_contacts(contact_id);
	`

	_, err := db.Exec(schema)
	return err
}

func (s *ContactService) updateMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM contacts WHERE subscribed = true").Scan(&count)
		if err == nil {
			activeContacts.Set(float64(count))
		}
	}
}

func (s *ContactService) createContact(c *gin.Context) {
	start := time.Now()
	defer func() {
		contactOperationDuration.WithLabelValues("create").Observe(time.Since(start).Seconds())
	}()

	var contact Contact
	if err := c.ShouldBindJSON(&contact); err != nil {
		contactsTotal.WithLabelValues("create", "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `
		INSERT INTO contacts (email, first_name, last_name, phone, company, tags, custom_data, subscribed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`

	customDataJSON, _ := json.Marshal(contact.CustomData)
	err := s.db.QueryRow(query, contact.Email, contact.FirstName, contact.LastName,
		contact.Phone, contact.Company, contact.Tags, string(customDataJSON), contact.Subscribed).Scan(
		&contact.ID, &contact.CreatedAt, &contact.UpdatedAt)

	if err != nil {
		contactsTotal.WithLabelValues("create", "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create contact"})
		return
	}

	// Cache contact
	contactJSON, _ := json.Marshal(contact)
	s.redis.Set(context.Background(), fmt.Sprintf("contact:%d", contact.ID), contactJSON, time.Hour)

	contactsTotal.WithLabelValues("create", "success").Inc()
	c.JSON(http.StatusCreated, contact)
}

func (s *ContactService) getContacts(c *gin.Context) {
	start := time.Now()
	defer func() {
		contactOperationDuration.WithLabelValues("list").Observe(time.Since(start).Seconds())
	}()

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset := (page - 1) * limit

	query := `
		SELECT id, email, first_name, last_name, phone, company, tags, custom_data, subscribed, created_at, updated_at
		FROM contacts
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		contactsTotal.WithLabelValues("list", "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch contacts"})
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		var customDataJSON string
		err := rows.Scan(&contact.ID, &contact.Email, &contact.FirstName, &contact.LastName,
			&contact.Phone, &contact.Company, &contact.Tags, &customDataJSON, &contact.Subscribed,
			&contact.CreatedAt, &contact.UpdatedAt)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(customDataJSON), &contact.CustomData)
		contacts = append(contacts, contact)
	}

	contactsTotal.WithLabelValues("list", "success").Inc()
	c.JSON(http.StatusOK, gin.H{"contacts": contacts, "page": page, "limit": limit})
}

func (s *ContactService) getContact(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
		return
	}

	// Try cache first
	cacheKey := fmt.Sprintf("contact:%d", id)
	cachedContact, err := s.redis.Get(context.Background(), cacheKey).Result()
	if err == nil {
		var contact Contact
		if json.Unmarshal([]byte(cachedContact), &contact) == nil {
			c.JSON(http.StatusOK, contact)
			return
		}
	}

	// Fetch from database
	var contact Contact
	var customDataJSON string
	query := `
		SELECT id, email, first_name, last_name, phone, company, tags, custom_data, subscribed, created_at, updated_at
		FROM contacts WHERE id = $1
	`
	err = s.db.QueryRow(query, id).Scan(&contact.ID, &contact.Email, &contact.FirstName,
		&contact.LastName, &contact.Phone, &contact.Company, &contact.Tags, &customDataJSON,
		&contact.Subscribed, &contact.CreatedAt, &contact.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Contact not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch contact"})
		}
		return
	}

	json.Unmarshal([]byte(customDataJSON), &contact.CustomData)

	// Cache the result
	contactJSON, _ := json.Marshal(contact)
	s.redis.Set(context.Background(), cacheKey, contactJSON, time.Hour)

	c.JSON(http.StatusOK, contact)
}

func (s *ContactService) updateContact(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
		return
	}

	var contact Contact
	if err = c.ShouldBindJSON(&contact); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `
		UPDATE contacts
		SET email = $1, first_name = $2, last_name = $3, phone = $4, company = $5,
			tags = $6, custom_data = $7, subscribed = $8, updated_at = CURRENT_TIMESTAMP
		WHERE id = $9
		RETURNING updated_at
	`

	customDataJSON, _ := json.Marshal(contact.CustomData)
	err = s.db.QueryRow(query, contact.Email, contact.FirstName, contact.LastName,
		contact.Phone, contact.Company, contact.Tags, string(customDataJSON),
		contact.Subscribed, id).Scan(&contact.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Contact not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update contact"})
		}
		return
	}

	contact.ID = id

	// Update cache
	contactJSON, _ := json.Marshal(contact)
	s.redis.Set(context.Background(), fmt.Sprintf("contact:%d", id), contactJSON, time.Hour)

	c.JSON(http.StatusOK, contact)
}

func (s *ContactService) deleteContact(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
		return
	}

	_, err = s.db.Exec("DELETE FROM contacts WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete contact"})
		return
	}

	// Remove from cache
	s.redis.Del(context.Background(), fmt.Sprintf("contact:%d", id))

	c.JSON(http.StatusOK, gin.H{"message": "Contact deleted successfully"})
}

func (s *ContactService) bulkImportContacts(c *gin.Context) {
	start := time.Now()
	defer func() {
		contactOperationDuration.WithLabelValues("bulk_import").Observe(time.Since(start).Seconds())
	}()

	var contacts []Contact
	if err := c.ShouldBindJSON(&contacts); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	defer tx.Rollback()

	successCount := 0
	errorCount := 0

	for _, contact := range contacts {
		query := `
			INSERT INTO contacts (email, first_name, last_name, phone, company, tags, custom_data, subscribed)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (email) DO UPDATE SET
				first_name = EXCLUDED.first_name,
				last_name = EXCLUDED.last_name,
				phone = EXCLUDED.phone,
				company = EXCLUDED.company,
				tags = EXCLUDED.tags,
				custom_data = EXCLUDED.custom_data,
				updated_at = CURRENT_TIMESTAMP
		`

		customDataJSON, _ := json.Marshal(contact.CustomData)
		_, err := tx.Exec(query, contact.Email, contact.FirstName, contact.LastName,
			contact.Phone, contact.Company, contact.Tags, string(customDataJSON), contact.Subscribed)

		if err != nil {
			errorCount++
		} else {
			successCount++
		}
	}

	if err := tx.Commit(); err != nil {
		contactsTotal.WithLabelValues("bulk_import", "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	contactsTotal.WithLabelValues("bulk_import", "success").Inc()
	c.JSON(http.StatusOK, gin.H{
		"message":       "Bulk import completed",
		"success_count": successCount,
		"error_count":   errorCount,
	})
}

func (s *ContactService) exportContacts(c *gin.Context) {
	listID := c.Query("list_id")
	format := c.DefaultQuery("format", "json")

	var query string
	var args []interface{}

	if listID != "" {
		query = `
			SELECT c.id, c.email, c.first_name, c.last_name, c.phone, c.company, c.tags, c.custom_data, c.subscribed, c.created_at, c.updated_at
			FROM contacts c
			JOIN list_contacts lc ON c.id = lc.contact_id
			WHERE lc.list_id = $1
		`
		args = append(args, listID)
	} else {
		query = `
			SELECT id, email, first_name, last_name, phone, company, tags, custom_data, subscribed, created_at, updated_at
			FROM contacts
		`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export contacts"})
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		var customDataJSON string
		err := rows.Scan(&contact.ID, &contact.Email, &contact.FirstName, &contact.LastName,
			&contact.Phone, &contact.Company, &contact.Tags, &customDataJSON, &contact.Subscribed,
			&contact.CreatedAt, &contact.UpdatedAt)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(customDataJSON), &contact.CustomData)
		contacts = append(contacts, contact)
	}

	if format == "csv" {
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=contacts.csv")
		// CSV export logic would go here
		c.String(http.StatusOK, "CSV export not implemented yet")
	} else {
		c.JSON(http.StatusOK, gin.H{"contacts": contacts})
	}
}

func (s *ContactService) createList(c *gin.Context) {
	var list ContactList
	if err := c.ShouldBindJSON(&list); err != nil {
		listsTotal.WithLabelValues("create", "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `
		INSERT INTO contact_lists (name, description, user_id)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`

	err := s.db.QueryRow(query, list.Name, list.Description, list.UserID).Scan(
		&list.ID, &list.CreatedAt, &list.UpdatedAt)

	if err != nil {
		listsTotal.WithLabelValues("create", "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create list"})
		return
	}

	listsTotal.WithLabelValues("create", "success").Inc()
	c.JSON(http.StatusCreated, list)
}

func (s *ContactService) getLists(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	query := `
		SELECT id, name, description, user_id, contact_count, created_at, updated_at
		FROM contact_lists
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		listsTotal.WithLabelValues("list", "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch lists"})
		return
	}
	defer rows.Close()

	var lists []ContactList
	for rows.Next() {
		var list ContactList
		err := rows.Scan(&list.ID, &list.Name, &list.Description, &list.UserID,
			&list.ContactCount, &list.CreatedAt, &list.UpdatedAt)
		if err != nil {
			continue
		}
		lists = append(lists, list)
	}

	listsTotal.WithLabelValues("list", "success").Inc()
	c.JSON(http.StatusOK, gin.H{"lists": lists})
}

func (s *ContactService) getList(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	var list ContactList
	query := `
		SELECT id, name, description, user_id, contact_count, created_at, updated_at
		FROM contact_lists WHERE id = $1
	`
	err = s.db.QueryRow(query, id).Scan(&list.ID, &list.Name, &list.Description,
		&list.UserID, &list.ContactCount, &list.CreatedAt, &list.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "List not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch list"})
		}
		return
	}

	c.JSON(http.StatusOK, list)
}

func (s *ContactService) updateList(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	var list ContactList
	if err = c.ShouldBindJSON(&list); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `
		UPDATE contact_lists
		SET name = $1, description = $2, updated_at = CURRENT_TIMESTAMP
		WHERE id = $3
		RETURNING updated_at
	`

	err = s.db.QueryRow(query, list.Name, list.Description, id).Scan(&list.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "List not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update list"})
		}
		return
	}

	list.ID = id
	c.JSON(http.StatusOK, list)
}

func (s *ContactService) deleteList(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	_, err = s.db.Exec("DELETE FROM contact_lists WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete list"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "List deleted successfully"})
}

func (s *ContactService) addContactsToList(c *gin.Context) {
	listID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	var request struct {
		ContactIDs []int `json:"contact_ids"`
	}
	if err = c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	defer tx.Rollback()

	for _, contactID := range request.ContactIDs {
		_, err = tx.Exec("INSERT INTO list_contacts (list_id, contact_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
			listID, contactID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add contact to list"})
			return
		}
	}

	// Update contact count
	_, err = tx.Exec(`
		UPDATE contact_lists
		SET contact_count = (SELECT COUNT(*) FROM list_contacts WHERE list_id = $1)
		WHERE id = $1
	`, listID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update contact count"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Contacts added to list successfully"})
}

func (s *ContactService) removeContactsFromList(c *gin.Context) {
	listID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	var request struct {
		ContactIDs []int `json:"contact_ids"`
	}
	if err = c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	defer tx.Rollback()

	for _, contactID := range request.ContactIDs {
		_, err = tx.Exec("DELETE FROM list_contacts WHERE list_id = $1 AND contact_id = $2",
			listID, contactID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove contact from list"})
			return
		}
	}

	// Update contact count
	_, err = tx.Exec(`
		UPDATE contact_lists
		SET contact_count = (SELECT COUNT(*) FROM list_contacts WHERE list_id = $1)
		WHERE id = $1
	`, listID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update contact count"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Contacts removed from list successfully"})
}

func (s *ContactService) getListContacts(c *gin.Context) {
	listID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset := (page - 1) * limit

	query := `
		SELECT c.id, c.email, c.first_name, c.last_name, c.phone, c.company, c.tags, c.custom_data, c.subscribed, c.created_at, c.updated_at
		FROM contacts c
		JOIN list_contacts lc ON c.id = lc.contact_id
		WHERE lc.list_id = $1
		ORDER BY lc.added_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := s.db.Query(query, listID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch list contacts"})
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		var customDataJSON string
		err := rows.Scan(&contact.ID, &contact.Email, &contact.FirstName, &contact.LastName,
			&contact.Phone, &contact.Company, &contact.Tags, &customDataJSON, &contact.Subscribed,
			&contact.CreatedAt, &contact.UpdatedAt)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(customDataJSON), &contact.CustomData)
		contacts = append(contacts, contact)
	}

	c.JSON(http.StatusOK, gin.H{"contacts": contacts, "page": page, "limit": limit})
}

func (s *ContactService) searchContacts(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required"})
		return
	}

	searchQuery := `
		SELECT id, email, first_name, last_name, phone, company, tags, custom_data, subscribed, created_at, updated_at
		FROM contacts
		WHERE email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1 OR company ILIKE $1
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := s.db.Query(searchQuery, "%"+query+"%")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search contacts"})
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		var customDataJSON string
		err := rows.Scan(&contact.ID, &contact.Email, &contact.FirstName, &contact.LastName,
			&contact.Phone, &contact.Company, &contact.Tags, &customDataJSON, &contact.Subscribed,
			&contact.CreatedAt, &contact.UpdatedAt)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(customDataJSON), &contact.CustomData)
		contacts = append(contacts, contact)
	}

	c.JSON(http.StatusOK, gin.H{"contacts": contacts})
}

func (s *ContactService) filterContacts(c *gin.Context) {
	tags := c.QueryArray("tags")
	subscribed := c.Query("subscribed")

	var conditions []string
	var args []interface{}
	argIndex := 1

	if len(tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argIndex))
		args = append(args, tags)
		argIndex++
	}

	if subscribed != "" {
		conditions = append(conditions, fmt.Sprintf("subscribed = $%d", argIndex))
		args = append(args, subscribed == "true")
		argIndex++
	}

	query := "SELECT id, email, first_name, last_name, phone, company, tags, custom_data, subscribed, created_at, updated_at FROM contacts"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to filter contacts"})
		return
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contact Contact
		var customDataJSON string
		err := rows.Scan(&contact.ID, &contact.Email, &contact.FirstName, &contact.LastName,
			&contact.Phone, &contact.Company, &contact.Tags, &customDataJSON, &contact.Subscribed,
			&contact.CreatedAt, &contact.UpdatedAt)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(customDataJSON), &contact.CustomData)
		contacts = append(contacts, contact)
	}

	c.JSON(http.StatusOK, gin.H{"contacts": contacts})
}

func (s *ContactService) subscribeContact(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
		return
	}

	_, err = s.db.Exec("UPDATE contacts SET subscribed = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to subscribe contact"})
		return
	}

	// Remove from cache to force refresh
	s.redis.Del(context.Background(), fmt.Sprintf("contact:%d", id))

	c.JSON(http.StatusOK, gin.H{"message": "Contact subscribed successfully"})
}

func (s *ContactService) unsubscribeContact(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
		return
	}

	_, err = s.db.Exec("UPDATE contacts SET subscribed = false, updated_at = CURRENT_TIMESTAMP WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unsubscribe contact"})
		return
	}

	// Remove from cache to force refresh
	s.redis.Del(context.Background(), fmt.Sprintf("contact:%d", id))

	c.JSON(http.StatusOK, gin.H{"message": "Contact unsubscribed successfully"})
}