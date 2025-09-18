package redis_initialization

import (
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/frame/g"
)

// InitRedisWindowsSimple initialize redis configuration for Windows without retry loop
func InitRedisWindowsSimple() (err error) {
	// get redis password from environment variable
	passwd, err := public.DockerEnv("REDISPASS")

	if err != nil {
		g.Log().Warning(context.Background(), "Redis password not found, using empty password")
		passwd = ""
	}

	address := "127.0.0.1:6379" // Use standard Redis port instead of 26379

	// Initialize Redis configuration
	gredis.SetConfig(&gredis.Config{
		Address: address,
		Db:      1,
		Pass:    passwd,
	})

	// Test Redis connection once
	k := "bm_test_connection"
	if err := g.Redis().SetEX(context.Background(), k, k, 1); err != nil {
		g.Log().Warning(context.Background(), "Redis connection test failed: ", err, " - Redis functionality will be disabled")
		return nil // Don't fail the application, just log the warning
	}

	if _, err := g.Redis().Del(context.Background(), k); err != nil {
		g.Log().Warning(context.Background(), "Redis cleanup test failed: ", err, " - Redis functionality will be disabled")
		return nil // Don't fail the application, just log the warning
	}

	g.Log().Info(context.Background(), "Redis connection test successful")
	return nil
}