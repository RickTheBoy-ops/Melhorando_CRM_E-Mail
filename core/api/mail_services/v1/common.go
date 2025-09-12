package v1

import (
	"billionmail-core/internal/service/public"
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

type ServiceType string

var (
	BaseConfigDir       = public.AbsPath("../conf")
	ServiceType_Postfix = BaseConfigDir + "/postfix/main.cf"
	ServiceType_Dovecot = BaseConfigDir + "/dovecot/dovecot.conf"
	ServiceType_Rspamd  = BaseConfigDir + "/rspamd/rspamd.conf"
)

type GetConfigFileReq struct {
	g.Meta      `path:"/services/get_config" method:"post" summary:"get config file"`
	ServiceType string `json:"service_type" v:"required" desc:"service type"`
}

type GetConfigFileRes struct {
	api_v1.StandardRes
	Data struct {
		ConfigPath   string `json:"config_path"`   // config file path
		Content      string `json:"content"`       // file content
		Encoding     string `json:"encoding"`      // file encoding
		LastModified int64  `json:"last_modified"` // last modified time
		Size         int64  `json:"size"`          // file size
		OnlyRead     bool   `json:"only_read"`     // only read (file too large)
	} `json:"data"`
}

type SaveConfigFileReq struct {
	g.Meta      `path:"/services/save_config" method:"post" summary:"save config file"`
	ServiceType string `json:"service_type" v:"required" desc:"service type"`
	Content     string `json:"content" v:"required" desc:"file content"`
}

type SaveConfigFileRes struct {
	api_v1.StandardRes
}
