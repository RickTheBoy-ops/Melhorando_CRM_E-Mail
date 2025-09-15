package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Connection Pool Monitoring Middleware
// Tracks connection pool metrics for PostgreSQL and Redis

var (
	// PostgreSQL Pool Metrics
	pgPoolActiveConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "postgres_pool_active_connections",
			Help: "Number of active PostgreSQL connections",
		},
		[]string{"service"},
	)

	pgPoolIdleConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "postgres_pool_idle_connections",
			Help: "Number of idle PostgreSQL connections",
		},
		[]string{"service"},
	)

	pgPoolTotalConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "postgres_pool_total_connections",
			Help: "Total number of PostgreSQL connections",
		},
		[]string{"service"},
	)

	// Redis Pool Metrics
	redisPoolHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_pool_hits_total",
			Help: "Total number of Redis pool hits",
		},
		[]string{"service"},
	)

	redisPoolMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_pool_misses_total",
			Help: "Total number of Redis pool misses",
		},
		[]string{"service"},
	)

	redisPoolTimeouts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_pool_timeouts_total",
			Help: "Total number of Redis pool timeouts",
		},
		[]string{"service"},
	)

	redisPoolTotalConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_pool_total_connections",
			Help: "Total number of Redis connections",
		},
		[]string{"service"},
	)

	redisPoolIdleConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "redis_pool_idle_connections",
			Help: "Number of idle Redis connections",
		},
		[]string{"service"},
	)
)

func init() {
	// Register PostgreSQL metrics
	prometheus.MustRegister(pgPoolActiveConns)
	prometheus.MustRegister(pgPoolIdleConns)
	prometheus.MustRegister(pgPoolTotalConns)

	// Register Redis metrics
	prometheus.MustRegister(redisPoolHits)
	prometheus.MustRegister(redisPoolMisses)
	prometheus.MustRegister(redisPoolTimeouts)
	prometheus.MustRegister(redisPoolTotalConns)
	prometheus.MustRegister(redisPoolIdleConns)
}

// PoolMonitoringConfig holds configuration for pool monitoring
type PoolMonitoringConfig struct {
	ServiceName    string
	PgPool         *pgxpool.Pool
	RedisClient    *redis.Client
	UpdateInterval time.Duration
	LogInterval    time.Duration
}

// PoolMonitor manages connection pool monitoring
type PoolMonitor struct {
	config     *PoolMonitoringConfig
	ctx        context.Context
	cancel     context.CancelFunc
	lastPgHits uint64
	lastRedisHits uint64
}

// NewPoolMonitor creates a new pool monitor
func NewPoolMonitor(config *PoolMonitoringConfig) *PoolMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 30 * time.Second
	}
	if config.LogInterval == 0 {
		config.LogInterval = 5 * time.Minute
	}

	return &PoolMonitor{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins monitoring connection pools
func (pm *PoolMonitor) Start() {
	go pm.monitorPools()
}

// Stop stops monitoring
func (pm *PoolMonitor) Stop() {
	pm.cancel()
}

// monitorPools continuously monitors connection pool metrics
func (pm *PoolMonitor) monitorPools() {
	updateTicker := time.NewTicker(pm.config.UpdateInterval)
	logTicker := time.NewTicker(pm.config.LogInterval)
	defer updateTicker.Stop()
	defer logTicker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-updateTicker.C:
			pm.updateMetrics()
		case <-logTicker.C:
			pm.logPoolStats()
		}
	}
}

// updateMetrics updates Prometheus metrics
func (pm *PoolMonitor) updateMetrics() {
	// Update PostgreSQL metrics
	if pm.config.PgPool != nil {
		stats := pm.config.PgPool.Stat()
		pgPoolActiveConns.WithLabelValues(pm.config.ServiceName).Set(float64(stats.AcquiredConns()))
		pgPoolIdleConns.WithLabelValues(pm.config.ServiceName).Set(float64(stats.IdleConns()))
		pgPoolTotalConns.WithLabelValues(pm.config.ServiceName).Set(float64(stats.TotalConns()))
	}

	// Update Redis metrics
	if pm.config.RedisClient != nil {
		stats := pm.config.RedisClient.PoolStats()
		
		// Update counters (only increment by difference)
		if uint64(stats.Hits) > pm.lastRedisHits {
			redisPoolHits.WithLabelValues(pm.config.ServiceName).Add(float64(uint64(stats.Hits) - pm.lastRedisHits))
			pm.lastRedisHits = uint64(stats.Hits)
		}
		
		redisPoolMisses.WithLabelValues(pm.config.ServiceName).Add(float64(stats.Misses))
		redisPoolTimeouts.WithLabelValues(pm.config.ServiceName).Add(float64(stats.Timeouts))
		redisPoolTotalConns.WithLabelValues(pm.config.ServiceName).Set(float64(stats.TotalConns))
		redisPoolIdleConns.WithLabelValues(pm.config.ServiceName).Set(float64(stats.IdleConns))
	}
}

// logPoolStats logs detailed pool statistics
func (pm *PoolMonitor) logPoolStats() {
	fields := logrus.Fields{
		"component": "pool_monitor",
		"service":   pm.config.ServiceName,
		"timestamp": time.Now().Unix(),
	}

	// Add PostgreSQL stats
	if pm.config.PgPool != nil {
		stats := pm.config.PgPool.Stat()
		fields["postgres_pool"] = map[string]interface{}{
			"acquired_conns":    stats.AcquiredConns(),
			"canceled_acquire_count": stats.CanceledAcquireCount(),
			"constructing_conns": stats.ConstructingConns(),
			"empty_acquire_count": stats.EmptyAcquireCount(),
			"idle_conns":        stats.IdleConns(),
			"max_conns":         stats.MaxConns(),
			"total_conns":       stats.TotalConns(),
			"new_conns_count":   stats.NewConnsCount(),
			"max_lifetime_destroy_count": stats.MaxLifetimeDestroyCount(),
			"max_idle_destroy_count": stats.MaxIdleDestroyCount(),
		}
	}

	// Add Redis stats
	if pm.config.RedisClient != nil {
		stats := pm.config.RedisClient.PoolStats()
		fields["redis_pool"] = map[string]interface{}{
			"hits":         stats.Hits,
			"misses":       stats.Misses,
			"timeouts":     stats.Timeouts,
			"total_conns":  stats.TotalConns,
			"idle_conns":   stats.IdleConns,
			"stale_conns":  stats.StaleConns,
		}
	}

	logrus.WithFields(fields).Info("Connection pool statistics")
}

// PoolMonitoringMiddleware creates a Gin middleware for pool monitoring
func PoolMonitoringMiddleware(monitor *PoolMonitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Process request
		c.Next()
		
		// Log request with pool stats if it took too long
		duration := time.Since(start)
		if duration > 1*time.Second {
			fields := logrus.Fields{
				"component":     "slow_request",
				"service":       monitor.config.ServiceName,
				"method":        c.Request.Method,
				"path":          c.Request.URL.Path,
				"duration_ms":   duration.Milliseconds(),
				"status_code":   c.Writer.Status(),
			}
			
			// Add current pool stats for slow requests
			if monitor.config.PgPool != nil {
				stats := monitor.config.PgPool.Stat()
				fields["pg_pool_active"] = stats.AcquiredConns()
				fields["pg_pool_idle"] = stats.IdleConns()
			}
			
			if monitor.config.RedisClient != nil {
				stats := monitor.config.RedisClient.PoolStats()
				fields["redis_pool_active"] = stats.TotalConns - stats.IdleConns
				fields["redis_pool_idle"] = stats.IdleConns
			}
			
			logrus.WithFields(fields).Warn("Slow request detected with pool stats")
		}
	}
}

// GetPoolStatsEndpoint creates an endpoint to expose pool statistics
func GetPoolStatsEndpoint(monitor *PoolMonitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := gin.H{
			"service":   monitor.config.ServiceName,
			"timestamp": time.Now().Unix(),
		}

		// Add PostgreSQL stats
		if monitor.config.PgPool != nil {
			pgStats := monitor.config.PgPool.Stat()
			stats["postgres_pool"] = gin.H{
				"acquired_conns":    pgStats.AcquiredConns(),
				"idle_conns":        pgStats.IdleConns(),
				"total_conns":       pgStats.TotalConns(),
				"max_conns":         pgStats.MaxConns(),
				"constructing_conns": pgStats.ConstructingConns(),
				"new_conns_count":   pgStats.NewConnsCount(),
				"canceled_acquire_count": pgStats.CanceledAcquireCount(),
				"empty_acquire_count": pgStats.EmptyAcquireCount(),
			}
		}

		// Add Redis stats
		if monitor.config.RedisClient != nil {
			redisStats := monitor.config.RedisClient.PoolStats()
			stats["redis_pool"] = gin.H{
				"hits":         redisStats.Hits,
				"misses":       redisStats.Misses,
				"timeouts":     redisStats.Timeouts,
				"total_conns":  redisStats.TotalConns,
				"idle_conns":   redisStats.IdleConns,
				"stale_conns":  redisStats.StaleConns,
			}
		}

		c.JSON(200, stats)
	}
}