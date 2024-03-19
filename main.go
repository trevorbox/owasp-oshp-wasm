// Copyright 2020-2021 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

// Override types.DefaultVMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext

	// headerName and headerValue are the header to be added to response. They are configured via
	// plugin configuration during OnPluginStart.
	// headerName  string
	// headerValue string
}

// Override types.DefaultPluginContext.
func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpHeaders{
		contextID: contextID,
		// headerName:  p.headerName,
		// headerValue: p.headerValue,
	}
}

func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	proxywasm.LogDebug("loading plugin config")
	data, err := proxywasm.GetPluginConfiguration()
	if data == nil {
		return types.OnPluginStartStatusOK
	}

	if err != nil {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	// if !gjson.Valid(string(data)) {
	// 	proxywasm.LogCritical(`invalid configuration format; expected {"header": "<header name>", "value": "<header value>"}`)
	// 	return types.OnPluginStartStatusFailed
	// }

	// p.headerName = strings.TrimSpace(gjson.Get(string(data), "header").Str)
	// p.headerValue = strings.TrimSpace(gjson.Get(string(data), "value").Str)

	// if p.headerName == "" || p.headerValue == "" {
	// 	proxywasm.LogCritical(`invalid configuration format; expected {"header": "<header name>", "value": "<header value>"}`)
	// 	return types.OnPluginStartStatusFailed
	// }

	// proxywasm.LogInfof("header from config: %s = %s", p.headerName, p.headerValue)

	return types.OnPluginStartStatusOK
}

type httpHeaders struct {
	// Embed the default http context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultHttpContext
	contextID   uint32
	headerName  string
	headerValue string
}

// Override types.DefaultHttpContext.
func (ctx *httpHeaders) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// err := proxywasm.ReplaceHttpRequestHeader("test", "best")
	// if err != nil {
	// 	proxywasm.LogCritical("failed to set request header: test")
	// }

	// hs, err := proxywasm.GetHttpRequestHeaders()
	// if err != nil {
	// 	proxywasm.LogCriticalf("failed to get request headers: %v", err)
	// }

	// for _, h := range hs {
	// 	proxywasm.LogInfof("request header --> %s: %s", h[0], h[1])
	// }
	return types.ActionContinue
}

func addHeader(headerName string, headerValue string) {
	err := proxywasm.AddHttpResponseHeader(headerName, headerValue)
	if err != nil {
		proxywasm.LogCriticalf("failed to add header %s with value %s: %v", headerName, headerValue, err)
	} else {
		proxywasm.LogInfof("added header %s with value %s", headerName, headerValue)
	}
}

// Header always exists with the expected value
func setHeader(headerName string, expectedValue string) {
	currentValue, err := proxywasm.GetHttpResponseHeader(headerName)
	if err != nil {
		addHeader(headerName, expectedValue)
	} else if currentValue != expectedValue {
		err := proxywasm.ReplaceHttpResponseHeader(headerName, expectedValue)
		if err != nil {
			proxywasm.LogCriticalf("failed to replace header %s with value %s: %v", headerName, expectedValue, err)
		} else {
			proxywasm.LogInfof("replaced header %s with value %s", headerName, expectedValue)
		}
	}
}

// Default the header to a value if missing
func defaultHeader(headerName string, defaultValue string) {
	_, err := proxywasm.GetHttpResponseHeader(headerName)
	if err != nil {
		addHeader(headerName, defaultValue)
	}
}

// Remove the header if it exists
func removeHeader(headerName string) {
	_, err := proxywasm.GetHttpResponseHeader(headerName)
	if err == nil {
		err := proxywasm.RemoveHttpResponseHeader(headerName)
		if err != nil {
			proxywasm.LogCriticalf("failed to remove header %s : %v", headerName, err)
		} else {
			proxywasm.LogInfof("removed header %s", headerName)
		}
	} else {
		proxywasm.LogInfof("header %s not found", headerName)
	}
}

func printResponseHeaders() {
	// Get and log the headers
	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get response headers: %v", err)
	}
	for _, h := range hs {
		proxywasm.LogInfof("response header <-- %s: %s", h[0], h[1])
	}
}

const cookieSuffix = "; HTTPOnly; Secure;"

// Override types.DefaultHttpContext.
func (ctx *httpHeaders) OnHttpResponseHeaders(_ int, _ bool) types.Action {
	printResponseHeaders()
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options
	setHeader("X-Frame-Options", "DENY")
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-xss-protection
	setHeader("X-XSS-Protection", "1; mode=block")
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options
	setHeader("X-Content-Type-Options", "nosniff")
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy
	setHeader("Referrer-Policy", "strict-origin-when-cross-origin")
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type
	defaultHeader("Content-Type", "text/plain; charset=utf-8")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#set-cookie
	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get response headers: %v", err)
	}

	updatedSetCookieHeaders := make([][2]string, 0)

	for _, h := range hs {

		val := h[1]
		if !strings.HasSuffix(val, cookieSuffix) {
			if h[0] == "set-cookie" {
				var kv [2]string
				kv[0] = h[0]
				kv[1] = val + cookieSuffix
				kv[1] = val + cookieSuffix
				updatedSetCookieHeaders = append(updatedSetCookieHeaders, kv)
			} else {
				updatedSetCookieHeaders = append(updatedSetCookieHeaders, h)
			}
		}
	}

	if len(updatedSetCookieHeaders) > 0 {
		err := proxywasm.ReplaceHttpResponseHeaders(updatedSetCookieHeaders)
		if err != nil {
			proxywasm.LogCriticalf("failed to update set-cookie headers: %v", err)
		}
	} else {
		proxywasm.LogInfo("no updated set-cookie headers")
	}

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts
	setHeader("Strict-Transport-Security", "max-age=63072000;includeSubDomains;preload")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#expect-ct
	removeHeader("Expect-CT")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-security-policy-csp
	setHeader("Content-Security-Policy", "upgrade-insecure-requests; base-uri 'self'; frame-ancestors 'none'; script-src 'self'; form-action 'self'; frame-src 'none'; font-src 'none'; style-src 'self'; manifest-src 'none'; worker-src 'none'; media-src 'none'; object-src 'none';")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin
	accessControlAllowOrigin, err := proxywasm.GetHttpResponseHeader("Access-Control-Allow-Origin")
	if err != nil {
		proxywasm.LogCriticalf("failed to get response header: %s", "Access-Control-Allow-Origin")
	}
	if strings.Trim(accessControlAllowOrigin, " ") == "*" {
		removeHeader("Access-Control-Allow-Origin")
	}

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cross-origin-opener-policy-coop
	setHeader("Cross-Origin-Opener-Policy", "same-origin")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cross-origin-embedder-policy-coep
	setHeader("Cross-Origin-Embedder-Policy", "require-corp")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cross-origin-resource-policy-corp
	setHeader("Cross-Origin-Resource-Policy", "same-site")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#permissions-policy-formerly-feature-policy, https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#floc-federated-learning-of-cohorts
	setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server
	// Note this won't work with Istio <https://github.com/istio/istio/issues/13861>, you need an EnvoyFilter
	removeHeader("Server")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by
	removeHeader("X-Powered-By")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-aspnet-version
	removeHeader("X-AspNet-Version")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-aspnetmvc-version
	removeHeader("X-AspNetMvc-Version")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-dns-prefetch-control
	setHeader("X-DNS-Prefetch-Control", "off")

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#public-key-pins-hpkp
	removeHeader("Public-Key-Pins")

	// others
	// https://owasp.org/www-community/attacks/Cache_Poisoning
	removeHeader("ETag")

	// https://owasp.org/www-project-secure-headers/#cache-control
	contentType, err := proxywasm.GetHttpResponseHeader("Content-Type")
	if err != nil {
		proxywasm.LogCriticalf("failed to get response header: %s", "Content-Type")
	} else {
		contentType = strings.Trim(contentType, " ")

		if contentType == "application/ecmascript" || contentType == "application/javascript" || contentType == "text/css" || strings.HasPrefix(contentType, "font/") || strings.HasPrefix(contentType, "image/") {
			setHeader("Cache-Control", "no-cache=\"Set-Cookie,Authorization\"")
		} else {
			setHeader("Cache-Control", "no-store, no-cache")
		}

	}

	printResponseHeaders()
	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *httpHeaders) OnHttpStreamDone() {
	proxywasm.LogInfof("%d finished", ctx.contextID)
}
