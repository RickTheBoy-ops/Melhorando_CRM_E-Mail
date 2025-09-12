package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Notification represents a notification in the system
type Notification struct {
	ID        int       `json:"id" db:"id"`
	UserID    int       `json:"user_id" db:"user_id"`
	Type      string    `json:"type" db:"type"`
	Title     string    `json:"title" db:"title"`
	Message   string    `json:"message" db:"message"`
	Read      bool      `json:"read" db:"read"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NotificationService handles notification operations
type NotificationService struct {
	db    *sql.DB
	redis *redis.Client
}

// Prometheus metrics
var (
	notificationsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notifications_sent_total",
			Help: "Total number of notifications sent",
		},
		[]string{"type", "status"},
	)
)

func init() {
	prometheus.MustRegister(notificationsSent)
}

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://billionmail_user:billionmail_pass@postgres:5432/billionmail_notifications?sslmode=disable"
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
		DB:   4, // Use DB 4 for notifications
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

	service := &NotificationService{
		db:    db,
		redis: rdb,
	}

	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "notification-service"})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Notification endpoints
	v1 := router.Group("/api/v1")
	{
		v1.POST("/notifications", service.createNotification)
		v1.GET("/notifications/:user_id", service.getUserNotifications)
		v1.PUT("/notifications/:id/read", service.markAsRead)
		v1.DELETE("/notifications/:id", service.deleteNotification)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8007"
	}

	log.Printf("Notification service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS notifications (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL,
		type VARCHAR(50) NOT NULL,
		title VARCHAR(255) NOT NULL,
		message TEXT NOT NULL,
		read BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
	CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
	`

	_, err := db.Exec(schema)
	return err
}

func (s *NotificationService) createNotification(c *gin.Context) {
	var notification Notification
	if err := c.ShouldBindJSON(&notification); err != nil {
		notificationsSent.WithLabelValues("unknown", "error").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	notification.CreatedAt = time.Now()

	query := `
		INSERT INTO notifications (user_id, type, title, message, created_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`

	err := s.db.QueryRow(query, notification.UserID, notification.Type,
		notification.Title, notification.Message, notification.CreatedAt).Scan(&notification.ID)

	if err != nil {
		notificationsSent.WithLabelValues(notification.Type, "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create notification"})
		return
	}

	notificationsSent.WithLabelValues(notification.Type, "success").Inc()
	c.JSON(http.StatusCreated, notification)
}

func (s *NotificationService) getUserNotifications(c *gin.Context) {
	userID := c.Param("user_id")

	query := `
		SELECT id, user_id, type, title, message, read, created_at
		FROM notifications
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 50
	`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notifications"})
		return
	}
	defer rows.Close()

	var notifications []Notification
	for rows.Next() {
		var notification Notification
		err := rows.Scan(&notification.ID, &notification.UserID, &notification.Type,
			&notification.Title, &notification.Message, &notification.Read, &notification.CreatedAt)
		if err != nil {
			continue
		}
		notifications = append(notifications, notification)
	}

	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}

func (s *NotificationService) markAsRead(c *gin.Context) {
	id := c.Param("id")

	query := "UPDATE notifications SET read = TRUE WHERE id = $1"
	_, err := s.db.Exec(query, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark notification as read"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Notification marked as read"})
}

func (s *NotificationService) deleteNotification(c *gin.Context) {
	id := c.Param("id")

	query := "DELETE FROM notifications WHERE id = $1"
	_, err := s.db.Exec(query, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete notification"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Notification deleted"})
}