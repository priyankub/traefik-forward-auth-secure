package tfa

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerLogoutRedirectVariations(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	cfg.CookieDomains = []CookieDomain{
		*NewCookieDomain("example.com"),
	}
	cfg.Secret = []byte("test-signing-secret-1234567890123")
	config = cfg

	// 1. Logout without LogoutRedirect returns 401 and clears cookies
	server := NewServer()
	req := httptest.NewRequest("GET", "https://app.example.com/_oauth/logout", nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	server.RootHandler(rec, req)

	assert.Equal(http.StatusUnauthorized, rec.Code)
	assert.Contains(rec.Body.String(), "You have been logged out")

	// Verify Set-Cookie headers clear cookie
	cookies := rec.Result().Cookies()
	assert.NotEmpty(cookies)
	for _, c := range cookies {
		assert.Equal(config.CookieName, c.Name)
		assert.Equal("", c.Value)
		assert.True(c.Expires.Before(time.Now()))
	}

	// 2. Logout with safe relative LogoutRedirect
	config.LogoutRedirect = "/login-again"
	rec2 := httptest.NewRecorder()
	server.RootHandler(rec2, req)
	assert.Equal(http.StatusTemporaryRedirect, rec2.Code)
	assert.Equal("/login-again", rec2.Header().Get("Location"))

	// 3. Logout with safe absolute LogoutRedirect on allowed domain
	config.LogoutRedirect = "https://app.example.com/goodbye"
	rec3 := httptest.NewRecorder()
	server.RootHandler(rec3, req)
	assert.Equal(http.StatusTemporaryRedirect, rec3.Code)
	assert.Equal("https://app.example.com/goodbye", rec3.Header().Get("Location"))

	// 4. Logout with unsafe LogoutRedirect (open redirect attempt) -> returns 400 Bad Request
	config.LogoutRedirect = "https://evil.com/phishing"
	rec4 := httptest.NewRecorder()
	server.RootHandler(rec4, req)
	assert.Equal(http.StatusBadRequest, rec4.Code)
	assert.Contains(rec4.Body.String(), "Invalid logout redirect")

	// 5. Logout with CRLF in LogoutRedirect -> 400
	config.LogoutRedirect = "/path\r\nInjected: true"
	rec5 := httptest.NewRecorder()
	server.RootHandler(rec5, req)
	assert.Equal(http.StatusBadRequest, rec5.Code)
}

func TestServerAuthCallbackErrors(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	cfg.Secret = []byte("test-signing-secret-1234567890123")
	config = cfg
	server := NewServer()

	// 1. Missing state parameter
	reqNoState := httptest.NewRequest("GET", "https://example.com/_oauth", nil)
	recNoState := httptest.NewRecorder()
	server.RootHandler(recNoState, reqNoState)
	assert.Equal(http.StatusUnauthorized, recNoState.Code)

	// 2. Short state parameter
	reqShortState := httptest.NewRequest("GET", "https://example.com/_oauth?state=short", nil)
	recShortState := httptest.NewRecorder()
	server.RootHandler(recShortState, reqShortState)
	assert.Equal(http.StatusUnauthorized, recShortState.Code)

	// 3. Valid length state, but missing CSRF cookie
	err, nonce := Nonce()
	require.NoError(t, err)
	state := fmt.Sprintf("%s:google:https://example.com/dashboard", nonce)
	reqNoCookie := httptest.NewRequest("GET", fmt.Sprintf("https://example.com/_oauth?state=%s", state), nil)
	recNoCookie := httptest.NewRecorder()
	server.RootHandler(recNoCookie, reqNoCookie)
	assert.Equal(http.StatusUnauthorized, recNoCookie.Code)

	// 4. CSRF cookie with wrong name or mismatched nonce
	reqMismatch := httptest.NewRequest("GET", fmt.Sprintf("https://example.com/_oauth?state=%s", state), nil)
	wrongCookie := &http.Cookie{
		Name:  buildCSRFCookieName(nonce),
		Value: "different-nonce-1234567890123456",
	}
	reqMismatch.AddCookie(wrongCookie)
	recMismatch := httptest.NewRecorder()
	server.RootHandler(recMismatch, reqMismatch)
	assert.Equal(http.StatusUnauthorized, recMismatch.Code)

	// 5. CSRF state with unconfigured provider
	stateUnknownProvider := fmt.Sprintf("%s:unknown-provider:https://example.com/dashboard", nonce)
	reqUnknownProv := httptest.NewRequest("GET", fmt.Sprintf("https://example.com/_oauth?state=%s", stateUnknownProvider), nil)
	cookieUnknownProv := &http.Cookie{
		Name:  buildCSRFCookieName(nonce),
		Value: nonce,
	}
	reqUnknownProv.AddCookie(cookieUnknownProv)
	recUnknownProv := httptest.NewRecorder()
	server.RootHandler(recUnknownProv, reqUnknownProv)
	assert.Equal(http.StatusUnauthorized, recUnknownProv.Code)

	// 6. CSRF state with open redirect URL
	stateEvilRedirect := fmt.Sprintf("%s:google:https://evil.com/leak", nonce)
	reqEvil := httptest.NewRequest("GET", fmt.Sprintf("https://example.com/_oauth?state=%s", stateEvilRedirect), nil)
	cookieEvil := &http.Cookie{
		Name:  buildCSRFCookieName(nonce),
		Value: nonce,
	}
	reqEvil.AddCookie(cookieEvil)
	recEvil := httptest.NewRecorder()
	server.RootHandler(recEvil, reqEvil)
	assert.Equal(http.StatusUnauthorized, recEvil.Code)
}

func TestServerRootHandlerHeaderCleaning(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	config = cfg
	server := NewServer()

	// Multi-proxy forwarded headers with leading/trailing spaces and multiple entries
	req := httptest.NewRequest("POST", "http://ignored.internal", nil)
	req.Header.Set("X-Forwarded-Method", "  GET  , POST, PUT")
	req.Header.Set("X-Forwarded-Proto", "  https  , http")
	req.Header.Set("X-Forwarded-Host", "  example.com  , proxy2.internal")
	req.Header.Set("X-Forwarded-Uri", "  /cleaned?param=1  , /raw")

	rec := httptest.NewRecorder()
	server.RootHandler(rec, req)

	assert.Equal("GET", req.Method)
	assert.Equal("https", req.Header.Get("X-Forwarded-Proto"))
	assert.Equal("example.com", req.Host)
	assert.Equal("/cleaned", req.URL.Path)
	assert.Equal("param=1", req.URL.RawQuery)
}

func TestServerAuthLifecycleEndToEnd(t *testing.T) {
	assert := assert.New(t)

	oauthServer, serverURL := NewOAuthServer(t)
	defer oauthServer.Close()

	cfg := newDefaultConfig()
	cfg.Secret = []byte("test-signing-secret-1234567890123")
	cfg.Providers.Google.TokenURL = serverURL.ResolveReference(&url.URL{Path: "/token"})
	cfg.Providers.Google.UserURL = serverURL.ResolveReference(&url.URL{Path: "/userinfo"})
	config = cfg
	server := NewServer()

	// Step 1: Initial unauthenticated request to protected endpoint
	req1 := httptest.NewRequest("GET", "http://example.com/protected", nil)
	req1.Header.Set("X-Forwarded-Method", "GET")
	req1.Header.Set("X-Forwarded-Proto", "https")
	req1.Header.Set("X-Forwarded-Host", "example.com")
	req1.Header.Set("X-Forwarded-Uri", "/protected")

	rec1 := httptest.NewRecorder()
	server.RootHandler(rec1, req1)
	assert.Equal(http.StatusTemporaryRedirect, rec1.Code)

	// Extract CSRF cookie and login redirect
	cookies := rec1.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, config.CSRFCookieName) {
			csrfCookie = c
			break
		}
	}
	require.NotNil(t, csrfCookie, "CSRF cookie should be returned")

	loginLoc, err := rec1.Result().Location()
	require.NoError(t, err)
	state := loginLoc.Query().Get("state")
	require.NotEmpty(t, state)

	// Step 2: Auth callback after OAuth provider approval
	callbackURL := fmt.Sprintf("https://example.com/_oauth?code=testcode123&state=%s", url.QueryEscape(state))
	req2 := httptest.NewRequest("GET", callbackURL, nil)
	req2.Header.Set("X-Forwarded-Method", "GET")
	req2.Header.Set("X-Forwarded-Proto", "https")
	req2.Header.Set("X-Forwarded-Host", "example.com")
	req2.Header.Set("X-Forwarded-Uri", fmt.Sprintf("/_oauth?code=testcode123&state=%s", url.QueryEscape(state)))
	req2.AddCookie(csrfCookie)

	rec2 := httptest.NewRecorder()
	server.RootHandler(rec2, req2)
	assert.Equal(http.StatusTemporaryRedirect, rec2.Code)

	// Check redirect target is the original target
	redirLoc, err := rec2.Result().Location()
	require.NoError(t, err)
	assert.Equal("/protected", redirLoc.Path)

	// Find the issued auth cookie
	var authCookie *http.Cookie
	for _, c := range rec2.Result().Cookies() {
		if c.Name == config.CookieName && c.Value != "" {
			authCookie = c
			break
		}
	}
	require.NotNil(t, authCookie, "Auth cookie should be issued")

	// Step 3: Access protected resource with issued auth cookie
	req3 := httptest.NewRequest("GET", "https://example.com/protected", nil)
	req3.Header.Set("X-Forwarded-Method", "GET")
	req3.Header.Set("X-Forwarded-Proto", "https")
	req3.Header.Set("X-Forwarded-Host", "example.com")
	req3.Header.Set("X-Forwarded-Uri", "/protected")
	req3.AddCookie(authCookie)

	rec3 := httptest.NewRecorder()
	server.RootHandler(rec3, req3)
	assert.Equal(http.StatusOK, rec3.Code)
	assert.Equal("example@example.com", rec3.Header().Get("X-Forwarded-User"))
}
