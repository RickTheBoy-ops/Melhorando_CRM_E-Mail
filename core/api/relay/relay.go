// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package relay

import (
	"context"

	"billionmail-core/api/relay/v1"
)

type IRelayV1 interface {
	CreateRelayConfig(ctx context.Context, req *v1.CreateRelayConfigReq) (res *v1.CreateRelayConfigRes, err error)
	ListRelayConfigs(ctx context.Context, req *v1.ListRelayConfigsReq) (res *v1.ListRelayConfigsRes, err error)
	UpdateRelayConfig(ctx context.Context, req *v1.UpdateRelayConfigReq) (res *v1.UpdateRelayConfigRes, err error)
	DeleteRelayConfig(ctx context.Context, req *v1.DeleteRelayConfigReq) (res *v1.DeleteRelayConfigRes, err error)
	GetUnboundDomains(ctx context.Context, req *v1.GetUnboundDomainsReq) (res *v1.GetUnboundDomainsRes, err error)
	TestSmtpConnection(ctx context.Context, req *v1.TestSmtpConnectionReq) (res *v1.TestSmtpConnectionRes, err error)
}
