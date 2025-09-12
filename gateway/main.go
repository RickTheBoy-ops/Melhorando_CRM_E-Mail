package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type Gateway struct {
	limiter  *rate.Limiter
	services map[string]string
}

type TokenValidationResponse struct {
	Valid  bool   `json:"valid"`
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

func NewGateway() *Gateway {
	return &Gateway{
		limiter: rate.NewLimiter(rate.Every(time.Second), 100), // 100 requests per second
		services: map[string]string{
			// 🔧 CONFIGURAÇÃO LOCAL: Usar localhost para desenvolvimento
			"auth-service":         "http://localhost:8001",
			"email-service":        "http://localhost:8002",
			"campaign-service":     "http://localhost:8003",
			"contact-service":      "http://localhost:8004",
			"analytics-service":    "http://localhost:8005",
			"template-service":     "http://localhost:8006",
			"notification-service": "http://localhost:8007",
		},
	}
}

// Rate limiting middleware
func (g *Gateway) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !g.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ✅ CORREÇÃO: Validação real de token com auth-service
func (g *Gateway) validateToken(token string) bool {
	if !strings.HasPrefix(token, "Bearer ") {
		return false
	}

	authServiceURL := g.services["auth-service"]
	if authServiceURL == "" {
		log.Printf("Auth service URL not configured")
		return false
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("POST", authServiceURL+"/auth/validate", nil)
	if err != nil {
		log.Printf("Failed to create validation request: %v", err)
		return false
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to validate token with auth service: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Token validation failed with status: %d", resp.StatusCode)
		return false
	}

	var validationResp TokenValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
		log.Printf("Failed to decode validation response: %v", err)
		return false
	}

	return validationResp.Valid
}

// Authentication middleware
func (g *Gateway) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health checks and auth endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/health") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/v1/auth/login") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/v1/auth/register") ||
			strings.HasPrefix(c.Request.URL.Path, "/auth/login") ||
			strings.HasPrefix(c.Request.URL.Path, "/auth/register") {
			c.Next()
			return
		}

		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
				"code":  "UNAUTHORIZED",
			})
			c.Abort()
			return
		}

		// ✅ CORREÇÃO: Usar validação real
		if !g.validateToken(token) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
				"code":  "INVALID_TOKEN",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Logging middleware
func (g *Gateway) LoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// Health check endpoint
func (g *Gateway) healthCheck(c *gin.Context) {
	servicesHealth := g.checkServicesHealth()

	allHealthy := true
	for _, status := range servicesHealth {
		if status != "healthy" {
			allHealthy = false
			break
		}
	}

	statusCode := http.StatusOK
	if !allHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, gin.H{
		"status":    map[bool]string{true: "healthy", false: "degraded"}[allHealthy],
		"timestamp": time.Now().Unix(),
		"gateway":   "healthy",
		"services":  servicesHealth,
	})
}

// ✅ CORREÇÃO: Check health with proper error handling
func (g *Gateway) checkServicesHealth() map[string]string {
	health := make(map[string]string)

	for serviceName, serviceURL := range g.services {
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		resp, err := client.Get(serviceURL + "/health")
		if err != nil {
			health[serviceName] = "unreachable"
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			health[serviceName] = "healthy"
		} else {
			health[serviceName] = "unhealthy"
		}
	}

	return health
}

// ✅ CORREÇÃO: Proxy melhorado com error handling
func (g *Gateway) proxyToService(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL, exists := g.services[serviceName]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Service not found",
				"code":  "SERVICE_NOT_FOUND",
			})
			return
		}

		target, err := url.Parse(serviceURL)
		if err != nil {
			log.Printf("Failed to parse service URL %s: %v", serviceURL, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid service URL",
				"code":  "INVALID_SERVICE_URL",
			})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Director = func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			
			// Handle different routing patterns
			servicePrefix := strings.Replace(serviceName, "-service", "", 1)
			originalPath := req.URL.Path
			
			if strings.HasPrefix(originalPath, "/api/v1/") {
				// Map /api/v1/auth/* to /auth/*
				req.URL.Path = "/" + servicePrefix + strings.TrimPrefix(originalPath, "/api/v1/"+servicePrefix)
			} else if strings.HasPrefix(originalPath, "/"+servicePrefix+"/") {
				// Keep the full path for direct routes (e.g., /auth/login -> /auth/login)
				req.URL.Path = originalPath
			}
			
			req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
			req.Header.Set("X-Origin-Host", target.Host)
		}

		// ✅ CORREÇÃO: Error handling para proxy
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for service %s: %v", serviceName, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(gin.H{
				"error": "Service unavailable",
				"code":  "SERVICE_UNAVAILABLE",
				"service": serviceName,
			})
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func main() {
	gateway := NewGateway()

	// Set Gin mode
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// CORS middleware
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check endpoint (no auth required)
	router.GET("/health", gateway.healthCheck)

	// Direct service routes (no auth required for login/register)
	router.Any("/auth/*path", gateway.proxyToService("auth-service"))
	router.Any("/email/*path", gateway.proxyToService("email-service"))

	// Global middleware (applied after direct routes)
	router.Use(gateway.LoggingMiddleware())
	router.Use(gateway.RateLimitMiddleware())
	router.Use(gateway.AuthMiddleware())

	// API routes with service proxying
	api := router.Group("/api/v1")
	{
		// Auth service routes
		auth := api.Group("/auth")
		auth.Any("/*path", gateway.proxyToService("auth-service"))

		// Email service routes
		email := api.Group("/email")
		email.Any("/*path", gateway.proxyToService("email-service"))

		// Campaign service routes
		campaigns := api.Group("/campaigns")
		campaigns.Any("/*path", gateway.proxyToService("campaign-service"))

		// Contact service routes
		contacts := api.Group("/contacts")
		contacts.Any("/*path", gateway.proxyToService("contact-service"))

		// Analytics service routes
		analytics := api.Group("/analytics")
		analytics.Any("/*path", gateway.proxyToService("analytics-service"))

		// Template service routes
		templates := api.Group("/templates")
		templates.Any("/*path", gateway.proxyToService("template-service"))

		// Notification service routes
		notifications := api.Group("/notifications")
		notifications.Any("/*path", gateway.proxyToService("notification-service"))
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("✅ API Gateway starting on port %s with Docker service URLs", port)
	log.Printf("🔒 Real token validation enabled")
	log.Printf("🏥 Enhanced health checks active")
	log.Fatal(router.Run(":" + port))
}