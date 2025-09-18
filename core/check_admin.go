package main

import (
	"context"
	"fmt"

	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
)

func checkAdmin() {
	ctx := context.Background()

	// Configure SQLite
	dataDir := "./data"
	if !gfile.Exists(dataDir) {
		fmt.Println("Data directory does not exist")
		return
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

	// Check if admin account exists
	var adminAccount struct {
		AccountId int64  `orm:"account_id"`
		Username  string `orm:"username"`
		Email     string `orm:"email"`
		Status    int    `orm:"status"`
		Password  string `orm:"password"`
	}

	err = g.DB().Model("account").Where("username = ?", "admin").Scan(&adminAccount)
	if err != nil {
		fmt.Printf("Admin account not found: %v\n", err)
		return
	}

	fmt.Printf("Admin account found:\n")
	fmt.Printf("  Account ID: %d\n", adminAccount.AccountId)
	fmt.Printf("  Username: %s\n", adminAccount.Username)
	fmt.Printf("  Email: %s\n", adminAccount.Email)
	fmt.Printf("  Status: %d\n", adminAccount.Status)
	fmt.Printf("  Password hash: %s\n", adminAccount.Password)

	// Check admin role
	var adminRole struct {
		RoleId      int64  `orm:"role_id"`
		RoleName    string `orm:"role_name"`
		Description string `orm:"description"`
	}

	err = g.DB().Model("role").Where("role_name = ?", "admin").Scan(&adminRole)
	if err != nil {
		fmt.Printf("Admin role not found: %v\n", err)
		return
	}

	fmt.Printf("\nAdmin role found:\n")
	fmt.Printf("  Role ID: %d\n", adminRole.RoleId)
	fmt.Printf("  Role Name: %s\n", adminRole.RoleName)
	fmt.Printf("  Description: %s\n", adminRole.Description)

	// Check if admin has admin role
	var accountRole struct {
		AccountId int64 `orm:"account_id"`
		RoleId    int64 `orm:"role_id"`
	}

	err = g.DB().Model("account_role").Where("account_id = ? AND role_id = ?", adminAccount.AccountId, adminRole.RoleId).Scan(&accountRole)
	if err != nil {
		fmt.Printf("Admin role not assigned to admin account: %v\n", err)
		return
	}

	fmt.Printf("\nAdmin role assigned to admin account successfully!\n")

	// List all accounts
	var accounts []struct {
		AccountId int64  `orm:"account_id"`
		Username  string `orm:"username"`
		Email     string `orm:"email"`
		Status    int    `orm:"status"`
	}

	err = g.DB().Model("account").Scan(&accounts)
	if err != nil {
		fmt.Printf("Failed to list accounts: %v\n", err)
		return
	}

	fmt.Printf("\nAll accounts in database:\n")
	for _, account := range accounts {
		fmt.Printf("  ID: %d, Username: %s, Email: %s, Status: %d\n", 
			account.AccountId, account.Username, account.Email, account.Status)
	}
}

func checkAdminMain() {
	checkAdmin()
}