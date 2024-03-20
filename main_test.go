// The framework emulates the expected behavior of Envoyproxy, and you can test your extensions without running Envoy and with
// the standard Go CLI. To run tests, simply run
// go test ./...

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// func TestHttpHeaders_OnHttpRequestHeaders(t *testing.T) {
// 	vmTest(t, func(t *testing.T, vm types.VMContext) {
// 		opt := proxytest.NewEmulatorOption().WithVMContext(vm)
// 		host, reset := proxytest.NewHostEmulator(opt)
// 		defer reset()

// 		// Initialize http context.
// 		id := host.InitializeHttpContext()

// 		// Call OnHttpResponseHeaders.
// 		hs := [][2]string{{"key1", "value1"}, {"key2", "value2"}}
// 		action := host.CallOnRequestHeaders(id,
// 			hs, false)
// 		require.Equal(t, types.ActionContinue, action)

// 		// Check headers.
// 		resultHeaders := host.GetCurrentRequestHeaders(id)
// 		var found bool
// 		for _, val := range resultHeaders {
// 			if val[0] == "test" {
// 				require.Equal(t, "best", val[1])
// 				found = true
// 			}
// 		}
// 		require.True(t, found)

// 		// Call OnHttpStreamDone.
// 		host.CompleteHttpContext(id)

// 		// Check Envoy logs.
// 		logs := host.GetInfoLogs()
// 		require.Contains(t, logs, fmt.Sprintf("%d finished", id))
// 		require.Contains(t, logs, "request header --> key2: value2")
// 		require.Contains(t, logs, "request header --> key1: value1")
// 	})
// }

func TestHttpHeaders_OnHttpResponseHeaders(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{{"key1", "value1"}, {"key2", "value2"}}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)
		require.Contains(t, resHeaders, [2]string{"key1", "value1"})
		require.Contains(t, resHeaders, [2]string{"key2", "value2"})
		require.Contains(t, resHeaders, [2]string{"x-frame-options", "DENY"})
		// require.Contains(t, resHeaders, [2]string{"x-proxy-wasm-go-sdk-example", "http_headers"})

		// Check Envoy logs.
		logs := host.GetInfoLogs()
		require.Contains(t, logs, fmt.Sprintf("%d finished", id))
		require.Contains(t, logs, "response header <-- key2: value2")
		require.Contains(t, logs, "response header <-- key1: value1")
		require.Contains(t, logs, "response header <-- x-frame-options: DENY")
		// require.Contains(t, logs, "response header <-- x-proxy-wasm-go-sdk-example: http_headers")
	})
}

func TestHttpHeaders_OnHttpResponseHeaders_empty(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.Contains(t, resHeaders, [2]string{strings.ToLower("X-Frame-Options"), "DENY"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("X-XSS-Protection"), "1; mode=block"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("X-Content-Type-Options"), "nosniff"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Referrer-Policy"), "strict-origin-when-cross-origin"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Content-Type"), "text/plain; charset=utf-8"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Strict-Transport-Security"), "max-age=63072000;includeSubDomains;preload"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Content-Security-Policy"), "upgrade-insecure-requests; base-uri 'self'; frame-ancestors 'none'; script-src 'self'; form-action 'self'; frame-src 'none'; font-src 'none'; style-src 'self'; manifest-src 'none'; worker-src 'none'; media-src 'none'; object-src 'none';"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Cross-Origin-Opener-Policy"), "same-origin"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Cross-Origin-Embedder-Policy"), "require-corp"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Cross-Origin-Resource-Policy"), "same-site"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Permissions-Policy"), "geolocation=(), camera=(), microphone=(), interest-cohort=()"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("X-DNS-Prefetch-Control"), "off"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Cache-Control"), "no-store, max-age=0"})
		// require.Contains(t, resHeaders, [2]string{"x-proxy-wasm-go-sdk-example", "http_headers"})

		// Check Envoy logs.
		logs := host.GetInfoLogs()
		require.Contains(t, logs, fmt.Sprintf("%d finished", id))

		require.Contains(t, logs, "response header <-- x-frame-options: DENY")
		// require.Contains(t, logs, "response header <-- x-proxy-wasm-go-sdk-example: http_headers")
	})
}

func TestHttpHeaders_OnHttpResponseHeaders_setCookie(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{
			{"set-cookie", "yummy_cookie=choco"},
			{"set-cookie", "id=a3fWa; Expires=Thu, 21 Oct 2021 07:28:00 GMT; Secure; HTTPOnly"},
			{"set-cookie", "tasty_cookie=strawberry"},
			{"set-cookie", "id=a3fWb; Secure; Expires=Thu, 21 Oct 2021 07:28:00 GMT                     ; HttpOnly"},
			{"set-cookie", "id=a3fWc; ;;;;Secure; ;"},
		}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.Contains(t, resHeaders, [2]string{strings.ToLower("Set-Cookie"), "yummy_cookie=choco; Secure; HttpOnly"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Set-Cookie"), "id=a3fWa; Expires=Thu, 21 Oct 2021 07:28:00 GMT; Secure; HTTPOnly"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Set-Cookie"), "tasty_cookie=strawberry; Secure; HttpOnly"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Set-Cookie"), "id=a3fWb; Secure; Expires=Thu, 21 Oct 2021 07:28:00 GMT; HttpOnly"})
		require.Contains(t, resHeaders, [2]string{strings.ToLower("Set-Cookie"), "id=a3fWc; Secure; HttpOnly"})

		// Check Envoy logs.
		logs := host.GetInfoLogs()
		require.Contains(t, logs, fmt.Sprintf("%d finished", id))

		require.Contains(t, logs, "response header <-- x-frame-options: DENY")
		require.Contains(t, logs, "response header <-- set-cookie: yummy_cookie=choco; Secure; HttpOnly")
		require.Contains(t, logs, "response header <-- set-cookie: id=a3fWa; Expires=Thu, 21 Oct 2021 07:28:00 GMT; Secure; HTTPOnly")
		require.Contains(t, logs, "response header <-- set-cookie: tasty_cookie=strawberry; Secure; HttpOnly")
		require.Contains(t, logs, "response header <-- set-cookie: id=a3fWb; Secure; Expires=Thu, 21 Oct 2021 07:28:00 GMT; HttpOnly")
		require.Contains(t, logs, "response header <-- set-cookie: id=a3fWc; Secure; HttpOnly")

	})
}

func TestHttpHeaders_OnHttpResponseHeaders_accessControlWildcard(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{
			{"Access-Control-Allow-Origin", "*"},
		}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.NotContains(t, resHeaders, [2]string{strings.ToLower("Access-Control-Allow-Origin"), "*"})

	})
}

func TestHttpHeaders_OnHttpResponseHeaders_accessControlOK(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{
			{"Access-Control-Allow-Origin", "https://developer.mozilla.org"},
		}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.Contains(t, resHeaders, [2]string{strings.ToLower("Access-Control-Allow-Origin"), "https://developer.mozilla.org"})
	})
}

func TestHttpHeaders_OnHttpResponseHeaders_accessControlNull(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{
			{"Access-Control-Allow-Origin", "null"},
		}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.NotContains(t, resHeaders, [2]string{strings.ToLower("Access-Control-Allow-Origin"), "null"})
	})
}

func TestHttpHeaders_OnHttpResponseHeaders_cacheControlContentType_text(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{
			{"content-Type", "text"},
		}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.Contains(t, resHeaders, [2]string{strings.ToLower("Cache-Control"), "no-store, max-age=0"})
	})
}

func TestHttpHeaders_OnHttpResponseHeaders_cacheControlContentType_text_css(t *testing.T) {
	vmTest(t, func(t *testing.T, vm types.VMContext) {
		opt := proxytest.NewEmulatorOption().
			// WithPluginConfiguration([]byte(fmt.Sprintf(`{"header": %q, "value": %q}`, "x-wasm-header", "x-value"))).
			WithVMContext(vm)
		host, reset := proxytest.NewHostEmulator(opt)
		defer reset()

		require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

		// Initialize http context.
		id := host.InitializeHttpContext()

		// Call OnHttpResponseHeaders.
		hs := [][2]string{
			{"content-Type", "text/css"},
		}
		action := host.CallOnResponseHeaders(id, hs, false)
		require.Equal(t, types.ActionContinue, action)

		// Call OnHttpStreamDone.
		host.CompleteHttpContext(id)

		resHeaders := host.GetCurrentResponseHeaders(id)

		require.Contains(t, resHeaders, [2]string{strings.ToLower("Cache-Control"), "no-cache=\"Set-Cookie\""})
	})
}

// vmTest executes f twice, once with a types.VMContext that executes plugin code directly
// in the host, and again by executing the plugin code within the compiled main.wasm binary.
// Execution with main.wasm will be skipped if the file cannot be found.
func vmTest(t *testing.T, f func(*testing.T, types.VMContext)) {
	t.Helper()

	t.Run("go", func(t *testing.T) {
		f(t, &vmContext{})
	})

	t.Run("wasm", func(t *testing.T) {
		wasm, err := os.ReadFile("main.wasm")
		if err != nil {
			t.Skip("wasm not found")
		}
		v, err := proxytest.NewWasmVMContext(wasm)
		require.NoError(t, err)
		defer v.Close()
		f(t, v)
	})
}
