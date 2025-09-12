package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db        *pgxpool.Pool
	jwtSecret []byte
}

type User struct {
	ID        int       `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password_hash"`
	Name      string    `json:"name" db:"name"`
	Role      string    `json:"role" db:"role"`
	Active    bool      `json:"active" db:"active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
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

// Funções auxiliares para configuração
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
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
	// Database connection com fallback Docker
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Fallback para ambiente Docker usando nome do container
		dbUser := getEnvWithDefault("DBUSER", "billionmail")
		dbPass := getEnvWithDefault("DBPASS", "NauF7ysRYyt9HTOiOn4JjIAL3QcRZnzj")
		dbName := getEnvWithDefault("DBNAME", "billionmail")
		dbHost := getEnvWithDefault("DB_HOST", "pgsql") // Nome do container Docker
		dbPort := getEnvWithDefault("DB_PORT", "5432")
		
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", 
			dbUser, dbPass, dbHost, dbPort, dbName)
		log.Printf("Using Docker fallback DATABASE_URL: postgres://%s:***@%s:%s/%s", 
			dbUser, dbHost, dbPort, dbName)
	}

	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	log.Println("✅ Database connection established successfully")

	// JWT secret com validação de segurança
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		// Fallback seguro para desenvolvimento
		jwtSecret = "BillionMail_Development_JWT_Secret_Key_2024_Change_In_Production_!@#$%^&*()"
		log.Printf("⚠️  WARNING: Using default JWT_SECRET for development. Change in production!")
	} else {
		// Validar segurança do JWT secret
		if len(jwtSecret) < 32 {
			return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters long for security")
		}
		if isWeakSecret(jwtSecret) {
			log.Printf("⚠️  WARNING: JWT_SECRET appears to be weak. Use a strong, random secret in production!")
		}
		log.Println("✅ JWT_SECRET configured from environment")
	}

	// Redis URL para futuras funcionalidades
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisPass := getEnvWithDefault("REDISPASS", "zKLnZQr3riFpcS2lEy3MOtfncztaCGKp")
		redisURL = fmt.Sprintf("redis://:%s@redis:6379", redisPass)
		log.Printf("Using Docker fallback REDIS_URL: redis://:***@redis:6379")
	}

	service := &AuthService{
		db:        db,
		jwtSecret: []byte(jwtSecret),
	}

	// Initialize database schema
	if err := service.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Printf("🚀 Auth Service initialized successfully on port %s", getEnvWithDefault("PORT", "8001"))
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

	log.Printf("Default admin user created: %s", adminEmail)
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
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
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
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "INVALID_CREDENTIALS",
		})
		return
	}

	// Generate token
	token, expiresAt, err := s.generateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
			"code":  "TOKEN_GENERATION_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      user,
	})
}

func (s *AuthService) validateTokenHandler(c *gin.Context) {
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

	// Health check
	router.GET("/health", service.healthCheck)

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

	log.Printf("Auth service starting on port %s", port)
	log.Fatal(router.Run(":" + port))
}