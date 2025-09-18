package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"golang.org/x/crypto/bcrypt"
)

func createAdmin() {
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

	// Create admin role if it doesn't exist
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
}

func createAdminMain() {
	createAdmin()
}