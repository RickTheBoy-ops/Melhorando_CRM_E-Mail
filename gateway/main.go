package main

import (
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
	limiter *rate.Limiter
	services map[string]string
}

func NewGateway() *Gateway {
	return &Gateway{
		limiter: rate.NewLimiter(rate.Every(time.Second), 100), // 100 requests per second
		services: map[string]string{
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

// Authentication middleware
func (g *Gateway) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health checks and auth endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/health") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/v1/auth/login") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/v1/auth/register") {
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

		// Validate token with auth service
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
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
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
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"services":  g.checkServicesHealth(),
	})
}

// Check health of all services
func (g *Gateway) checkServicesHealth() map[string]string {
	health := make(map[string]string)
	for service, serviceURL := range g.services {
		resp, err := http.Get(serviceURL + "/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			health[service] = "unhealthy"
		} else {
			health[service] = "healthy"
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	return health
}

// Validate token with auth service
func (g *Gateway) validateToken(token string) bool {
	// TODO: Implement actual token validation with auth service
	// For now, accept any non-empty token
	return strings.HasPrefix(token, "Bearer ")
}

// Proxy requests to appropriate service
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
			// Map /api/v1/auth/* to /auth/*
			servicePrefix := strings.Replace(serviceName, "-service", "", 1)
			req.URL.Path = "/" + servicePrefix + strings.TrimPrefix(req.URL.Path, "/api/v1/"+servicePrefix)
			req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
			req.Header.Set("X-Origin-Host", target.Host)
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

	// Global middleware
	router.Use(gateway.LoggingMiddleware())
	router.Use(gateway.RateLimitMiddleware())
	router.Use(gateway.AuthMiddleware())

	// Health check endpoint
	router.GET("/health", gateway.healthCheck)

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

	log.Printf("API Gateway starting on port %s", port)
	log.Fatal(router.Run(":" + port))
}