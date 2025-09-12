package v1

import "github.com/gogf/gf/v2/frame/g"

type FormReq struct {
	g.Meta   `path:"/subscription/form" tags:"Campaign - Subscription" method:"get,post" summary:"Subscription Form"`
	Email    string `json:"email" v:"email#Lang{Email is required}|Lang{Invalid email format}"`
	Name     string `json:"name"`
	GroupIds []int  `json:"group_ids"`
	Token    string `json:"token"`
}

type FormRes struct {
	g.Meta `mime:"text/html"`
}
