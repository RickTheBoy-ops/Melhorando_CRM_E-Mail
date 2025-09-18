package database_initialization

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"os"
)

// InitDatabaseWindowsSimple initializes SQLite database for Windows development
func InitDatabaseWindowsSimple() error {
	// Create data directory if it doesn't exist
	dataDir := "./data"
	if !gfile.Exists(dataDir) {
		if err := gfile.Mkdir(dataDir); err != nil {
			return fmt.Errorf("failed to create data directory: %v", err)
		}
	}

	// Set SQLite configuration
	err := gdb.SetConfig(gdb.Config{
		"default": gdb.ConfigGroup{
			gdb.ConfigNode{
				Type:             "sqlite",
				Link:             "sqlite::@file(./data/billionmail.db)",
				Role:             "master",
				MaxOpenConnCount: 10,
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to set SQLite config: %v", err)
	}

	// Test connection
	_, err = g.DB().Exec(context.Background(), "SELECT 1")
	if err != nil {
		return fmt.Errorf("SQLite connection test failed: %v", err)
	}

	// Execute registered handlers
	for _, handler := range registeredHandlers {
		if handler != nil {
			handler()
		}
	}

	// Clear handlers
	registeredHandlers = registeredHandlers[:0]

	g.Log().Info(context.Background(), "SQLite database initialized successfully")
	return nil
}

// SetEnvironmentForSQLite configures environment to use SQLite
func SetEnvironmentForSQLite() {
	os.Setenv("USE_SQLITE", "true")
	g.Log().Info(context.Background(), "Environment configured for SQLite")
}