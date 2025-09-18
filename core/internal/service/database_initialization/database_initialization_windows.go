package database_initialization

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"os"
	"time"
)

// InitDatabaseWindows initializes the database configuration for Windows development
func InitDatabaseWindows() (err error) {
	// Try to get database password from environment
	dbPass, err := public.DockerEnv("DBPASS")
	
	// If no password is found, use a default one for development
	if err != nil || dbPass == "" {
		dbPass = "billionmail123"
		g.Log().Warning(context.Background(), "Using default database password for development")
	}

	// Check if we should use SQLite for development
	useSQLite := os.Getenv("USE_SQLITE") == "true"
	
	if useSQLite {
		// Configure SQLite for development
		err = gdb.SetConfig(gdb.Config{
			"default": gdb.ConfigGroup{
				gdb.ConfigNode{
					Link:             "sqlite::@file(./data/billionmail.db)", // File-based database
					Type:             "sqlite",
					Role:             "master",
					MaxOpenConnCount: 10,
				},
			},
		})

		if err != nil {
			return fmt.Errorf("Set SQLite configuration failed: %v", err)
		}

		g.Log().Info(context.Background(), "Using SQLite in-memory database for development")
		
		// Test connection
		_, err = g.DB().Exec(context.Background(), "SELECT 1")
		if err != nil {
			return fmt.Errorf("SQLite connection test failed: %v", err)
		}
		
	} else {
		// Try to use PostgreSQL with socket connection
		err = gdb.SetConfig(gdb.Config{
			"default": gdb.ConfigGroup{
				gdb.ConfigNode{
					Host:             public.AbsPath(consts.POSTGRESQL_SOCK),
					User:             "billionmail_user",
					Pass:             dbPass,
					Name:             "billionmail",
					Type:             "pgsql",
					Role:             "master",
					MaxOpenConnCount: 100,
				},
			},
		})

		if err != nil {
			return fmt.Errorf("Set database configuration failed: %v", err)
		}

		// Testing database connection with retries
		connectionOK := false
		for i := 0; i < 5; i++ {
			_, err = g.DB().Exec(context.Background(), "SELECT 1")

			if err != nil {
				g.Log().Debug(context.Background(), "Database connection failed, retrying in 3 seconds...")
				time.Sleep(time.Second * 3)
				continue
			}

			connectionOK = true
			g.Log().Debug(context.Background(), "Database connection successful")
			break
		}

		if !connectionOK {
			g.Log().Warning(context.Background(), "PostgreSQL connection failed, falling back to SQLite")
			// Set environment variable to use SQLite and retry
			os.Setenv("USE_SQLITE", "true")
			return InitDatabaseWindows() // Recursive call to try SQLite
		}
	}

	// Execute registered handlers
	for _, handler := range registeredHandlers {
		if handler != nil {
			handler()
		}
	}

	// Empty the registered handlers
	registeredHandlers = registeredHandlers[:0]

	g.Log().Info(context.Background(), "Database initialization completed successfully")
	return nil
}