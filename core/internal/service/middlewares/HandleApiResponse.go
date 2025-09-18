package middlewares

import (
	"billionmail-core/internal/service/public"
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/util/gvalid"
	"github.com/gogf/gf/v2/net/ghttp"
	"strings"
)

func HandleApiResponse(r *ghttp.Request) {
	r.Middleware.Next()

	g.Log().Info(r.Context(), "HandleApiResponse - BufferLength:", r.Response.BufferLength(), "Error:", r.GetError(), "HandlerResponse:", r.GetHandlerResponse())
	buffer := r.Response.Buffer()
	g.Log().Info(r.Context(), "HandleApiResponse - Buffer length:", len(buffer))
	if err := r.GetError(); err != nil {
		g.Log().Error(r.Context(), "HandleApiResponse - Error:", err)
	}
	responseContent := string(buffer)
	g.Log().Info(r.Context(), "HandleApiResponse - Handler response:", responseContent)
	g.Log().Info(r.Context(), "HandleApiResponse - Response length:", len(responseContent))

	// If the request has been exited, do nothing.
	if r.Response.BufferLength() > 0 {
		g.Log().Info(r.Context(), "HandleApiResponse - BufferLength > 0, returning")
		return
	}

	// Handle the error if it exists.
	if r.GetError() != nil {
		// Clear the response buffer.
		r.Response.ClearBuffer()

		// Catch validation errors and respond with 412.
		if v, ok := r.GetError().(gvalid.Error); ok {
			errorStr := v.Error()
			errorLen := len(errorStr)
			// If the error message is in the format Lang{xxx}, convert it to the corresponding language.
			if strings.Contains(errorStr, "Lang{") && errorStr[errorLen-1] == '}' {
				errorStr = errorStr[5 : errorLen-1]
				errorStr = public.LangCtx(r.Context(), errorStr)
			}

			r.Response.WriteJson(api_v1.StandardRes{
				Success: false,
				Code:    412,
				Msg:     errorStr,
			})

			return
		}

		// Respond with 500 error.
		r.Response.WriteJson(api_v1.StandardRes{
			Success: false,
			Code:    500,
			Msg:     r.GetError().Error(),
		})

		return
	}

	// Get the response data.
	resp := r.GetHandlerResponse()

	g.Log().Info(r.Context(), "HandleApiResponse - HandlerResponse:", resp)

	// Respond with the data if it exists.
	if resp != nil {
		g.Log().Info(r.Context(), "HandleApiResponse - Writing JSON response")
		r.Response.WriteJson(resp)
	} else {
		g.Log().Info(r.Context(), "HandleApiResponse - No response data, returning empty")
	}
}
