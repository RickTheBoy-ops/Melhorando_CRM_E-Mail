package main

import (
	_ "billionmail-core/internal/packed"
	_ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2" // Add SQLite support
	_ "github.com/gogf/gf/contrib/nosql/redis/v2"
	"github.com/gogf/gf/v2/os/gctx"

	"billionmail-core/internal/cmd"
)

func mainApp() {
	cmd.Main.Run(gctx.GetInitCtx())
}