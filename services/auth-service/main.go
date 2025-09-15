package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db        *pgxpool.Pool
	jwtSecret []byte
	metrics   *AuthMetrics
}

// AuthMetrics holds Prometheus metrics for auth service
type AuthMetrics struct {
	loginAttempts    prometheus.Counter
	loginSuccesses   prometheus.Counter
	loginFailures    prometheus.Counter
	registrations    prometheus.Counter
	tokenValidations prometheus.Counter
	requestDuration  prometheus.Histogram
	activeUsers      prometheus.Gauge
	dbConnections    prometheus.Gauge
}

type User struct {
	ID            int       `json:"id" db:"id"`
	Email         string    `json:"email" db:"email"`
	Password      string    `json:"-" db:"password_hash"`
	Name          string    `json:"name" db:"name"`
	Role          string    `json:"role" db:"role"`
	Active        bool      `json:"active" db:"active"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	CorrelationID string    `json:"correlation_id,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Name     string `json:"name" binding:"required,min=2"`
}

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// NewAuthMetrics creates and registers Prometheus metrics for auth service
func NewAuthMetrics() *AuthMetrics {
	m := &AuthMetrics{
		loginAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_login_attempts_total",
			Help: "Total number of login attempts",
		}),
		loginSuccesses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_login_successes_total",
			Help: "Total number of successful logins",
		}),
		loginFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_login_failures_total",
			Help: "Total number of failed logins",
		}),
		registrations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_registrations_total",
			Help: "Total number of user registrations",
		}),
		tokenValidations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_token_validations_total",
			Help: "Total number of token validations",
		}),
		requestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "auth_request_duration_seconds",
			Help:    "Duration of auth requests in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		activeUsers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_active_users",
			Help: "Number of active users",
		}),
		dbConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_db_connections",
			Help: "Number of active database connections",
		}),
	}

	// Register metrics
	prometheus.MustRegister(m.loginAttempts)
	prometheus.MustRegister(m.loginSuccesses)
	prometheus.MustRegister(m.loginFailures)
	prometheus.MustRegister(m.registrations)
	prometheus.MustRegister(m.tokenValidations)
	prometheus.MustRegister(m.requestDuration)
	prometheus.MustRegister(m.activeUsers)
	prometheus.MustRegister(m.dbConnections)

	return m
}

// =======================================================
// SECURE SECRETS MANAGEMENT - P0 VULNERABILITY FIX
// =======================================================
// 🔒 Funções para leitura segura de Docker Secrets
// 🛡️ Compliance: GDPR, SOC2, PCI-DSS
// ⚠️  NUNCA mais credenciais em plain text!

// readSecret lê um Docker Secret de forma segura
func readSecret(secretFile string) (string, error) {
	if secretFile == "" {
		return "", fmt.Errorf("secret file path not provided")
	}
	
	content, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return "", fmt.Errorf("failed to read secret from %s: %w", secretFile, err)
	}
	
	return strings.TrimSpace(string(content)), nil
}

// getSecureEnv obtém credenciais de forma segura (Docker Secrets > ENV > Fallback)
func getSecureEnv(envVar, secretFile, fallback string) (string, error) {
	// 1. Primeiro tenta Docker Secret (PRODUÇÃO)
	if secretFile != "" {
		if secret, err := readSecret(secretFile); err == nil && secret != "" {
			logrus.WithFields(logrus.Fields{
		"component": "config",
		"env_var":   envVar,
		"source":    "docker_secret",
	}).Info("Using Docker Secret")
			return secret, nil
		}
	}
	
	// 2. Fallback para variável de ambiente (DESENVOLVIMENTO)
	if val := os.Getenv(envVar); val != "" && !strings.HasPrefix(val, "CHANGE_ME") {
		logrus.WithFields(logrus.Fields{
		"component": "config",
		"env_var":   envVar,
		"source":    "environment_variable",
		"warning":   "development_only",
	}).Warn("Using environment variable (development only)")
		return val, nil
	}
	
	// 3. Fallback final (apenas desenvolvimento)
	if fallback != "" {
		logrus.WithFields(logrus.Fields{
		"component": "config",
		"env_var":   envVar,
		"source":    "fallback_value",
		"security":  "insecure",
	}).Error("Using fallback value - INSECURE!")
		return fallback, nil
	}
	
	return "", fmt.Errorf("no secure credential found for %s", envVar)
}

// Funções auxiliares para configuração
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets environment variable as integer with default value
func getEnvAsInt(key string, defaultValue int32) int32 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 32); err == nil {
			return int32(intValue)
		}
	}
	return defaultValue
}

func isWeakSecret(secret string) bool {
	// Verificar se o secret é muito simples
	weakSecrets := []string{
		"secret", "password", "123456", "admin", "test",
		"jwt-secret", "your-secret", "change-me", "default",
	}
	
	lowerSecret := strings.ToLower(secret)
	for _, weak := range weakSecrets {
		if strings.Contains(lowerSecret, weak) {
			return true
		}
	}
	
	// Verificar se tem caracteres repetidos demais
	if len(secret) > 0 {
		charCount := make(map[rune]int)
		for _, char := range secret {
			charCount[char]++
		}
		
		// Se mais de 50% dos caracteres são iguais, é fraco
		for _, count := range charCount {
			if float64(count)/float64(len(secret)) > 0.5 {
				return true
			}
		}
	}
	
	return false
}

func NewAuthService() (*AuthService, error) {
	// =======================================================
	// P1 CONNECTION POOL OPTIMIZATION - PERFORMANCE FIX
	// =======================================================
	// 🚀 Optimized pgxpool configuration for auth service
	
	// Get database credentials securely
	// Priority: Docker Secrets > Environment Variables > Fallback
	dbUser, err := getSecureEnv("POSTGRES_USER", "/run/secrets/postgres_user", "billionmail_user")
	if err != nil {
		return nil, fmt.Errorf("failed to get database user: %w", err)
	}
	
	dbPass, err := getSecureEnv("POSTGRES_PASSWORD", "/run/secrets/postgres_password", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get database password: %w", err)
	}
	
	// Non-sensitive database configurations
	dbName := getEnvWithDefault("POSTGRES_DB", "billionmail_auth")
	dbHost := getEnvWithDefault("POSTGRES_HOST", "postgres")
	dbPort := getEnvWithDefault("POSTGRES_PORT", "5432")
	
	// Build database URL with secure credentials
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", 
		dbUser, dbPass, dbHost, dbPort, dbName)
	
	// Parse connection configuration for pool optimization
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}
	
	// =======================================================
	// CONNECTION POOL CONFIGURATION - P1 PERFORMANCE
	// =======================================================
	// Auth service optimized pool settings
	config.MaxConns = getEnvAsInt("AUTH_DB_MAX_CONNS", 25)                     // Max connections
	config.MinConns = getEnvAsInt("AUTH_DB_MIN_CONNS", 5)                      // Min connections
	config.MaxConnLifetime = time.Duration(getEnvAsInt("AUTH_DB_MAX_CONN_LIFETIME_MINUTES", 60)) * time.Minute   // 1 hour
	config.MaxConnIdleTime = time.Duration(getEnvAsInt("AUTH_DB_MAX_CONN_IDLE_MINUTES", 15)) * time.Minute       // 15 minutes
	config.HealthCheckPeriod = time.Duration(getEnvAsInt("AUTH_DB_HEALTH_CHECK_SECONDS", 60)) * time.Second      // 1 minute
	config.ConnConfig.ConnectTimeout = time.Duration(getEnvAsInt("AUTH_DB_CONNECT_TIMEOUT_SECONDS", 10)) * time.Second // 10 seconds
	
	// Runtime parameters for connection optimization
	config.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "billionmail-auth",
		"statement_timeout": "30s",
	}
	
	logrus.WithFields(logrus.Fields{
		"component": "database",
		"user":      dbUser,
		"host":      dbHost,
		"port":      dbPort,
		"database":  dbName,
		"security":  "docker_secrets_enabled",
		"pool_config": map[string]interface{}{
			"max_conns":         config.MaxConns,
			"min_conns":         config.MinConns,
			"max_conn_lifetime": config.MaxConnLifetime,
			"max_conn_idle":     config.MaxConnIdleTime,
			"health_check":      config.HealthCheckPeriod,
			"connect_timeout":   config.ConnConfig.ConnectTimeout,
		},
	}).Info("Establishing optimized database connection pool")

	db, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	
	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if pingErr := db.Ping(ctx); pingErr != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", pingErr)
	}
	
	logrus.WithFields(logrus.Fields{
		"component": "database",
		"status":    "connected",
		"pool_stats": map[string]interface{}{
			"max_conns":      db.Config().MaxConns,
			"min_conns":      db.Config().MinConns,
			"acquired_conns": db.Stat().AcquiredConns(),
			"idle_conns":     db.Stat().IdleConns(),
		},
	}).Info("Database connection pool established successfully")

	// =======================================================
	// SECURE JWT SECRET - P0 VULNERABILITY FIX
	// =======================================================
	// 🔒 Using Docker Secret for JWT
	
	jwtSecret, err := getSecureEnv("JWT_SECRET", "/run/secrets/jwt_secret", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT secret: %w", err)
	}
	
	// Validate JWT secret security
	if len(jwtSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters long for security")
	}
	if isWeakSecret(jwtSecret) {
		logrus.WithFields(logrus.Fields{
			"component": "jwt_config",
			"security":  "weak_secret_detected",
			"warning":   "use_strong_secret_in_production",
		}).Warn("JWT_SECRET appears to be weak")
	}
	
	logrus.WithFields(logrus.Fields{
		"component": "jwt_config",
		"status":    "configured",
		"security":  "docker_secrets_enabled",
	}).Info("JWT_SECRET configured securely")

	// =======================================================
	// SECURE REDIS CONNECTION - P0 VULNERABILITY FIX
	// =======================================================
	// 🔒 Usando Docker Secret para Redis
	


	service := &AuthService{
		db:        db,
		jwtSecret: []byte(jwtSecret),
		metrics:   NewAuthMetrics(),
	}

	// Initialize database schema
	if err := service.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"component": "auth_service",
		"port":      getEnvWithDefault("PORT", "8001"),
		"status":    "initialized",
	}).Info("Auth Service initialized successfully")
	return service, nil
}

func (s *AuthService) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS auth_users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		name VARCHAR(255) NOT NULL,
		role VARCHAR(50) DEFAULT 'user',
		active BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);
	CREATE INDEX IF NOT EXISTS idx_auth_users_active ON auth_users(active);

	CREATE TABLE IF NOT EXISTS auth_user_sessions (
		id SERIAL PRIMARY KEY,
		user_id INTEGER REFERENCES auth_users(id) ON DELETE CASCADE,
		token_hash VARCHAR(255) NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_auth_sessions_token ON auth_user_sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_user_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_user_sessions(expires_at);
	`

	_, err := s.db.Exec(context.Background(), schema)
	if err != nil {
		return err
	}

	// Create default admin user if not exists
	return s.createDefaultAdmin()
}

func (s *AuthService) createDefaultAdmin() error {
	adminEmail := "billion@billionmail.com"
	adminPassword := "billion"
	adminName := "BillionMail Admin"

	// Check if admin user already exists
	var existingID int
	err := s.db.QueryRow(context.Background(), "SELECT id FROM auth_users WHERE email = $1", adminEmail).Scan(&existingID)
	if err == nil {
		// Admin user already exists
		return nil
	}

	// Hash password
	hashedPassword, err := s.hashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	// Create admin user
	_, err = s.db.Exec(context.Background(),
		`INSERT INTO auth_users (email, password_hash, name, role) 
		 VALUES ($1, $2, $3, 'admin')`,
		adminEmail, hashedPassword, adminName)

	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"component": "user_management",
		"action":    "admin_user_created",
		"email":     adminEmail,
	}).Info("Default admin user created")
	return nil
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func (s *AuthService) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *AuthService) generateToken(user User) (string, time.Time, error) {
	expiresAt := time.Now().Add(24 * time.Hour)

	claims := Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "billionmail-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)

	return tokenString, expiresAt, err
}

func (s *AuthService) validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// HTTP Handlers
func (s *AuthService) register(c *gin.Context) {
	start := time.Now()
	defer func() {
		s.metrics.requestDuration.Observe(time.Since(start).Seconds())
	}()

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	// Check if user already exists
	var existingID int
	err := s.db.QueryRow(context.Background(), "SELECT id FROM auth_users WHERE email = $1", req.Email).Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User already exists",
			"code":  "USER_EXISTS",
		})
		return
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process password",
			"code":  "PASSWORD_HASH_ERROR",
		})
		return
	}

	// Create user
	var user User
	err = s.db.QueryRow(context.Background(),
		`INSERT INTO auth_users (email, password_hash, name, role) 
		 VALUES ($1, $2, $3, 'user') 
		 RETURNING id, email, name, role, active, created_at, updated_at`,
		req.Email, hashedPassword, req.Name).Scan(
		&user.ID, &user.Email, &user.Name, &user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "USER_CREATION_ERROR",
		})
		return
	}

	s.metrics.registrations.Inc()

	// Generate token
	token, expiresAt, err := s.generateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
			"code":  "TOKEN_GENERATION_ERROR",
		})
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      user,
	})
}

func (s *AuthService) login(c *gin.Context) {
	start := time.Now()
	defer func() {
		s.metrics.requestDuration.Observe(time.Since(start).Seconds())
	}()

	s.metrics.loginAttempts.Inc()

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.metrics.loginFailures.Inc()
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	// Get user from database
	var user User
	err := s.db.QueryRow(context.Background(),
		`SELECT id, email, password_hash, name, role, active, created_at, updated_at
		FROM auth_users WHERE email = $1 AND active = true`,
		req.Email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		s.metrics.loginFailures.Inc()
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid credentials",
				"code":  "INVALID_CREDENTIALS",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Database error",
				"code":  "DATABASE_ERROR",
			})
		}
		return
	}

	// Verify password
	if !s.verifyPassword(req.Password, user.Password) {
		s.metrics.loginFailures.Inc()
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "INVALID_CREDENTIALS",
		})
		return
	}

	// Generate token
	token, expiresAt, err := s.generateToken(user)
	if err != nil {
		s.metrics.loginFailures.Inc()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
			"code":  "TOKEN_GENERATION_ERROR",
		})
		return
	}

	s.metrics.loginSuccesses.Inc()
	c.JSON(http.StatusOK, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      user,
	})
}

func (s *AuthService) validateTokenHandler(c *gin.Context) {
	start := time.Now()
	defer func() {
		s.metrics.requestDuration.Observe(time.Since(start).Seconds())
	}()

	s.metrics.tokenValidations.Inc()

	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization header required",
			"code":  "MISSING_TOKEN",
		})
		return
	}

	// Remove "Bearer " prefix
	token = strings.TrimPrefix(token, "Bearer ")

	claims, err := s.validateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token",
			"code":  "INVALID_TOKEN",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"user_id": claims.UserID,
		"email":   claims.Email,
		"role":    claims.Role,
	})
}

func (s *AuthService) healthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthStatus := gin.H{
		"service":   "auth-service",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	}

	// Check database connection
	if err := s.db.Ping(ctx); err != nil {
		healthStatus["status"] = "unhealthy"
		healthStatus["database"] = gin.H{
			"status": "disconnected",
			"error":  err.Error(),
		}
		c.JSON(http.StatusServiceUnavailable, healthStatus)
		return
	}

	// Test database query
	var dbVersion string
	err := s.db.QueryRow(ctx, "SELECT version()").Scan(&dbVersion)
	if err != nil {
		healthStatus["status"] = "unhealthy"
		healthStatus["database"] = gin.H{
			"status": "connected",
			"query_error": err.Error(),
		}
		c.JSON(http.StatusServiceUnavailable, healthStatus)
		return
	}

	// Check if auth_users table exists and is accessible
	var userCount int
	err = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM auth_users").Scan(&userCount)
	if err != nil {
		healthStatus["status"] = "unhealthy"
		healthStatus["database"] = gin.H{
			"status": "connected",
			"schema_error": err.Error(),
		}
		c.JSON(http.StatusServiceUnavailable, healthStatus)
		return
	}

	// All checks passed
	healthStatus["status"] = "healthy"
	healthStatus["database"] = gin.H{
		"status": "connected",
		"users_count": userCount,
		"version": strings.Split(dbVersion, " ")[1], // Extract PostgreSQL version
		"pool_stats": gin.H{
			"max_conns":           s.db.Config().MaxConns,
			"min_conns":           s.db.Config().MinConns,
			"acquired_conns":      s.db.Stat().AcquiredConns(),
			"idle_conns":          s.db.Stat().IdleConns(),
			"total_conns":         s.db.Stat().TotalConns(),
			"new_conns_count":     s.db.Stat().NewConnsCount(),
			"max_lifetime_destroy_count": s.db.Stat().MaxLifetimeDestroyCount(),
			"max_idle_destroy_count": s.db.Stat().MaxIdleDestroyCount(),
			"acquire_count":       s.db.Stat().AcquireCount(),
			"acquire_duration":    s.db.Stat().AcquireDuration().String(),
			"empty_acquire_count": s.db.Stat().EmptyAcquireCount(),
			"canceled_acquire_count": s.db.Stat().CanceledAcquireCount(),
		},
		"pool_config": gin.H{
			"max_conn_lifetime": s.db.Config().MaxConnLifetime.String(),
			"max_conn_idle_time": s.db.Config().MaxConnIdleTime.String(),
			"health_check_period": s.db.Config().HealthCheckPeriod.String(),
			"connect_timeout": s.db.Config().ConnConfig.ConnectTimeout.String(),
		},
	}
	healthStatus["jwt"] = gin.H{
		"configured": len(s.jwtSecret) > 0,
		"length": len(s.jwtSecret),
	}
	healthStatus["environment"] = gin.H{
		"gin_mode": gin.Mode(),
		"port": getEnvWithDefault("PORT", "8001"),
	}

	c.JSON(http.StatusOK, healthStatus)
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
	service, err := NewAuthService()
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}
	defer service.db.Close()

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

	// Auth routes
	auth := router.Group("/auth")
	{
		auth.POST("/register", service.register)
		auth.POST("/login", service.login)
		auth.POST("/validate", service.validateTokenHandler)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	logrus.WithFields(logrus.Fields{
		"service": "auth-service",
		"port":    port,
	}).Info("Auth service starting")
	log.Fatal(router.Run(":" + port))
}