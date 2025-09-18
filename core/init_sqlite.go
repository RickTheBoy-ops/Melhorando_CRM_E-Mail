package main

import (
	"context"
	"fmt"
	"time"

	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"golang.org/x/crypto/bcrypt"
)

func initSQLite() {
	ctx := context.Background()

	// Configure SQLite
	dataDir := "./data"
	if !gfile.Exists(dataDir) {
		if err := gfile.Mkdir(dataDir); err != nil {
			fmt.Printf("Failed to create data directory: %v\n", err)
			return
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
		fmt.Printf("Failed to set SQLite config: %v\n", err)
		return
	}

	// Test connection
	_, err = g.DB().Exec(ctx, "SELECT 1")
	if err != nil {
		fmt.Printf("SQLite connection test failed: %v\n", err)
		return
	}

	fmt.Println("SQLite connection successful")

	// SQL statements for SQLite
	rbacSQLList := []string{
		// Account table - SQLite version
		`CREATE TABLE IF NOT EXISTS account (
			account_id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR(64) NOT NULL UNIQUE,
			password VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL,
			status INTEGER NOT NULL DEFAULT 1,
			language VARCHAR(50) NOT NULL DEFAULT 'pt',
			last_login_time INTEGER NOT NULL DEFAULT 0,
			create_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			update_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		// Role table - SQLite version
		`CREATE TABLE IF NOT EXISTS role (
			role_id INTEGER PRIMARY KEY AUTOINCREMENT,
			role_name VARCHAR(64) NOT NULL UNIQUE,
			description TEXT,
			status INTEGER NOT NULL DEFAULT 1,
			create_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			update_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		// Permission table - SQLite version
		`CREATE TABLE IF NOT EXISTS permission (
			permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
			permission_name VARCHAR(64) NOT NULL UNIQUE,
			description TEXT,
			module VARCHAR(64) NOT NULL,
			action VARCHAR(64) NOT NULL,
			resource VARCHAR(64) NOT NULL,
			status INTEGER NOT NULL DEFAULT 1,
			create_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			update_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			UNIQUE(module, action, resource)
		)`,

		// Account-Role mapping table - SQLite version
		`CREATE TABLE IF NOT EXISTS account_role (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			create_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			UNIQUE(account_id, role_id),
			FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE
		)`,

		// Role-Permission mapping table - SQLite version
		`CREATE TABLE IF NOT EXISTS role_permission (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role_id INTEGER NOT NULL,
			permission_id INTEGER NOT NULL,
			create_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			UNIQUE(role_id, permission_id),
			FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE,
			FOREIGN KEY (permission_id) REFERENCES permission(permission_id) ON DELETE CASCADE
		)`,
	}

	// Execute SQL statements
	for _, sql := range rbacSQLList {
		_, execErr := g.DB().Exec(ctx, sql)
		if execErr != nil {
			fmt.Printf("Failed to execute SQL: %v\nSQL: %s\n", execErr, sql)
			return
		}
	}

	fmt.Println("RBAC tables created successfully")

	// Create admin role
	var adminRoleId int64
	adminRoleIdVal, err := g.DB().Model("role").Where("role_name = ?", "admin").Value("role_id")
	if err != nil {
		fmt.Printf("Failed to check admin role: %v\n", err)
		return
	}

	if adminRoleIdVal == nil {
		result, insertErr := g.DB().Model("role").Data(g.Map{
			"role_name":   "admin",
			"description": "System administrator with full access",
			"status":      1,
			"create_time": time.Now().Unix(),
			"update_time": time.Now().Unix(),
		}).Insert()
		if insertErr != nil {
			fmt.Printf("Failed to create admin role: %v\n", insertErr)
			return
		}
		adminRoleId, _ = result.LastInsertId()
		fmt.Printf("Admin role created with ID: %d\n", adminRoleId)
	} else {
		adminRoleId = adminRoleIdVal.Int64()
		fmt.Printf("Admin role already exists with ID: %d\n", adminRoleId)
	}

	// Create admin account
	adminUsername := "admin"
	adminPassword := "admin123"

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Failed to hash password: %v\n", err)
		return
	}

	// Check if admin account exists
	var adminAccountId int64
	adminAccountIdVal, err := g.DB().Model("account").Where("username = ?", adminUsername).Value("account_id")
	if err != nil {
		fmt.Printf("Failed to check admin account: %v\n", err)
		return
	}

	if adminAccountIdVal == nil {
		result, insertErr := g.DB().Model("account").Data(g.Map{
			"username":    adminUsername,
			"password":    string(hashedPassword),
			"email":       "admin@billionmail.com",
			"status":      1,
			"language":    "pt",
			"create_time": time.Now().Unix(),
			"update_time": time.Now().Unix(),
		}).Insert()
		if insertErr != nil {
			fmt.Printf("Failed to create admin account: %v\n", insertErr)
			return
		}
		adminAccountId, _ = result.LastInsertId()
		fmt.Printf("Admin account created with ID: %d\n", adminAccountId)
	} else {
		adminAccountId = adminAccountIdVal.Int64()
		// Update password
		_, err = g.DB().Model("account").Data(g.Map{
			"password":    string(hashedPassword),
			"update_time": time.Now().Unix(),
		}).Where("account_id = ?", adminAccountId).Update()
		if err != nil {
			fmt.Printf("Failed to update admin password: %v\n", err)
			return
		}
		fmt.Printf("Admin account updated with ID: %d\n", adminAccountId)
	}

	// Assign admin role to admin account
	_, err = g.DB().Model("account_role").InsertIgnore(g.Map{
		"account_id":  adminAccountId,
		"role_id":     adminRoleId,
		"create_time": time.Now().Unix(),
	})
	if err != nil {
		fmt.Printf("Failed to assign admin role: %v\n", err)
		return
	}

	fmt.Printf("Admin role assigned to admin account successfully\n")
	fmt.Printf("\nLogin credentials:\n")
	fmt.Printf("Username: %s\n", adminUsername)
	fmt.Printf("Password: %s\n", adminPassword)
	fmt.Printf("\nDatabase initialization completed successfully!\n")
}

func initSQLiteMain() {
	initSQLite()
}