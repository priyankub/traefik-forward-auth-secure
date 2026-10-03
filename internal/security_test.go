package tfa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenRedirectAttacks tests exhaustive vectors for open redirect vulnerabilities.
func TestOpenRedirectAttacks(t *testing.T) {
	assert := assert.New(t)

	cfg, err := NewConfig([]string{
		"--cookie-domain=example.com",
		"--cookie-domain=sub.corp.net",
		"--auth-host=auth.example.com",
		"--secret=super-secret-key-12345",
	})
	require.NoError(t, err)
	config = cfg

	vectors := []struct {
		name        string
		url         string
		reqHost     string
		shouldError bool
	}{
		// Scheme-relative & slash bypasses
		{"protocol relative double slash", "//evil.com", "example.com", true},
		{"protocol relative triple slash", "///evil.com", "example.com", true},
		{"protocol relative quadruple slash", "////evil.com", "example.com", true},
		{"backslash prefix", "\\evil.com", "example.com", true},
		{"slash backslash", "/\\evil.com", "example.com", true},
		{"backslash slash", "\\/evil.com", "example.com", true},
		{"multiple backslashes", "\\\\\\evil.com", "example.com", true},

		// Dangerous schemes
		{"javascript scheme", "javascript:alert(1)", "example.com", true},
		{"javascript with uppercase", "JAVASCRIPT:alert(document.cookie)", "example.com", true},
		{"data scheme", "data:text/html,<script>alert(1)</script>", "example.com", true},
		{"vbscript scheme", "vbscript:msgbox(1)", "example.com", true},
		{"file scheme", "file:///etc/passwd", "example.com", true},
		{"ftp scheme", "ftp://evil.com/malware", "example.com", true},

		// Untrusted domains
		{"untrusted domain", "https://evil.com", "example.com", true},
		{"untrusted subdomain", "https://evil.example.com.attacker.com", "example.com", true},
		{"untrusted suffix", "https://example.com.evil.com", "example.com", true},
		{"untrusted prefix", "https://notexample.com", "example.com", true},
		{"userinfo trick", "https://example.com@evil.com", "example.com", true},
		{"userinfo trick 2", "https://user:pass@evil.com", "example.com", true},
		{"userinfo allowed host target evil", "https://evil.com#example.com", "example.com", true},
		{"userinfo allowed host query evil", "https://evil.com?target=example.com", "example.com", true},

		// CRLF injection vectors
		{"crlf in path", "https://example.com/\r\nSet-Cookie:malicious=1", "example.com", true},
		{"cr in path", "https://example.com/\rmalicious", "example.com", true},
		{"lf in path", "https://example.com/\nmalicious", "example.com", true},

		// Control chars
		{"null byte in url", "https://example.com/\x00evil", "example.com", true},

		// Valid trusted targets
		{"valid relative root", "/", "example.com", false},
		{"valid relative path", "/dashboard", "example.com", false},
		{"valid relative with query", "/app?user=1&ref=test", "example.com", false},
		{"valid relative with fragment", "/app#section2", "example.com", false},
		{"valid absolute allowed domain", "https://example.com/home", "example.com", false},
		{"valid absolute subdomain of allowed domain", "https://app.example.com/welcome", "example.com", false},
		{"valid absolute nested subdomain", "https://deep.sub.corp.net/admin", "example.com", false},
		{"valid auth host", "https://auth.example.com/oauth", "example.com", false},
		{"valid with port matching allowed domain", "https://example.com:8443/test", "example.com", false},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ValidateRedirect(tc.url, tc.reqHost)
			if tc.shouldError {
				assert.Error(err, "vector %s should have failed", tc.url)
			} else {
				assert.NoError(err, "vector %s should have passed", tc.url)
				assert.NotNil(u)
			}
		})
	}
}

// TestValidateRedirectNoConfigFallback tests redirect validation when config has no auth-host or cookie-domain.
func TestValidateRedirectNoConfigFallback(t *testing.T) {
	assert := assert.New(t)

	cfg, err := NewConfig([]string{
		"--secret=super-secret-key-12345",
	})
	require.NoError(t, err)
	config = cfg

	// When no domains or auth-host are configured, redirect must match request host
	_, err = ValidateRedirect("https://app.mycorp.com/path", "app.mycorp.com")
	assert.NoError(err, "should allow redirect matching request host")

	_, err = ValidateRedirect("https://app.mycorp.com/path", "app.mycorp.com:443")
	assert.NoError(err, "should allow redirect matching request host ignoring port")

	_, err = ValidateRedirect("https://attacker.com/path", "app.mycorp.com")
	assert.Error(err, "should reject redirect not matching request host")

	// Empty requestHosts fallback
	u, err := ValidateRedirect("https://anyhost.com/path")
	assert.NoError(err, "fallback with no requestHosts allows absolute URL")
	assert.Equal("anyhost.com", u.Host)
}

// TestCookieTamperingAndForgery tests that any tampering with auth cookies is caught.
func TestCookieTamperingAndForgery(t *testing.T) {
	assert := assert.New(t)

	cfg, err := NewConfig([]string{
		"--secret=secret-signing-key-12345",
		"--cookie-domain=example.com",
	})
	require.NoError(t, err)
	config = cfg

	r := httptest.NewRequest("GET", "https://app.example.com/dashboard", nil)
	validCookie := MakeCookie(r, "user@example.com")

	// 1. Verify valid cookie passes
	email, err := ValidateCookie(r, validCookie)
	assert.NoError(err)
	assert.Equal("user@example.com", email)

	// 2. Privilege escalation attempt: tamper email in cookie
	parts := strings.Split(validCookie.Value, "|")
	tamperedValue := fmt.Sprintf("%s|%s|admin@example.com", parts[0], parts[1])
	tamperedCookie := &http.Cookie{Name: config.CookieName, Value: tamperedValue}
	_, err = ValidateCookie(r, tamperedCookie)
	assert.Error(err)
	assert.Equal("Invalid cookie mac", err.Error())

	// 3. Expiration extension attempt: change expiration to year 2099
	tamperedValue = fmt.Sprintf("%s|4102444800|%s", parts[0], parts[2])
	tamperedCookie = &http.Cookie{Name: config.CookieName, Value: tamperedValue}
	_, err = ValidateCookie(r, tamperedCookie)
	assert.Error(err)
	assert.Equal("Invalid cookie mac", err.Error())

	// 4. Bit flipping the HMAC signature
	sigBytes, _ := base64.URLEncoding.DecodeString(parts[0])
	sigBytes[0] ^= 0xFF // flip bits
	tamperedSig := base64.URLEncoding.EncodeToString(sigBytes)
	tamperedValue = fmt.Sprintf("%s|%s|%s", tamperedSig, parts[1], parts[2])
	tamperedCookie = &http.Cookie{Name: config.CookieName, Value: tamperedValue}
	_, err = ValidateCookie(r, tamperedCookie)
	assert.Error(err)
	assert.Equal("Invalid cookie mac", err.Error())

	// 5. Cross-domain / Host spoofing attack:
	// Cookie generated for app.example.com presented to another.com
	otherReq := httptest.NewRequest("GET", "https://another.com/dashboard", nil)
	_, err = ValidateCookie(otherReq, validCookie)
	assert.Error(err)
	assert.Equal("Invalid cookie mac", err.Error())

	// 6. Delimiter injection / malformed structures
	malformedValues := []string{
		"",
		"|",
		"||",
		"|||",
		"||||",
		"MQ==|notanumber|user@example.com",
		"invalid-base64-mac!@#$%|1234567890|user@example.com",
		"MQ==|-999999999999999999999999999999999|user@example.com",
		parts[0] + "||user@example.com",
		parts[0] + "|" + parts[1],
		parts[0] + "|" + parts[1] + "|" + parts[2] + "|extra",
	}

	for _, val := range malformedValues {
		c := &http.Cookie{Name: config.CookieName, Value: val}
		_, err := ValidateCookie(r, c)
		assert.Error(err, "value %q should fail cookie validation", val)
	}
}

// TestCSRFStateAndCookieAttacks tests tampering with CSRF state and cookie.
func TestCSRFStateAndCookieAttacks(t *testing.T) {
	assert := assert.New(t)

	cfg, err := NewConfig([]string{
		"--secret=secret-signing-key-12345",
		"--cookie-domain=example.com",
	})
	require.NoError(t, err)
	config = cfg

	r := httptest.NewRequest("GET", "https://app.example.com/protected", nil)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")

	err, nonce := Nonce()
	require.NoError(t, err)
	require.Len(t, nonce, 32)

	csrfCookie := MakeCSRFCookie(r, nonce)

	// Valid state: nonce:provider:redirect
	validState := fmt.Sprintf("%s:google:https://app.example.com/protected", nonce)

	// 1. Valid CSRF validation passes
	valid, provider, redirect, err := ValidateCSRFCookie(csrfCookie, validState, "app.example.com")
	assert.True(valid)
	assert.NoError(err)
	assert.Equal("google", provider)
	assert.Equal("https://app.example.com/protected", redirect)

	// 2. Tampered nonce in state
	tamperedState := fmt.Sprintf("%s:google:https://app.example.com/protected", strings.Repeat("0", 32))
	valid, _, _, err = ValidateCSRFCookie(csrfCookie, tamperedState, "app.example.com")
	assert.False(valid)
	assert.Error(err)
	assert.Contains(err.Error(), "does not match state")

	// 3. Short / malformed cookie value
	shortCookie := &http.Cookie{Name: csrfCookie.Name, Value: "short"}
	valid, _, _, err = ValidateCSRFCookie(shortCookie, validState, "app.example.com")
	assert.False(valid)
	assert.Error(err)
	assert.Contains(err.Error(), "Invalid CSRF cookie value")

	// 4. Missing colon in state
	noColonState := fmt.Sprintf("%sgoogleappexamplecom", nonce)
	valid, _, _, err = ValidateCSRFCookie(csrfCookie, noColonState, "app.example.com")
	assert.False(valid)
	assert.Error(err)
	assert.Contains(err.Error(), "Invalid CSRF state format")

	// 5. Open redirect inside CSRF state
	evilRedirectState := fmt.Sprintf("%s:google:https://attacker.com/steal-token", nonce)
	valid, _, _, err = ValidateCSRFCookie(csrfCookie, evilRedirectState, "app.example.com")
	assert.False(valid)
	assert.Error(err)
	assert.Contains(err.Error(), "redirect host is not in allowed domains")

	// 6. ValidateState length check
	assert.Error(ValidateState(""))
	assert.Error(ValidateState("short"))
	assert.Error(ValidateState(strings.Repeat("a", 33)))
	assert.NoError(ValidateState(strings.Repeat("a", 34)))
}

// TestHealthcheckBypassPrevention verifies that forward auth requests cannot bypass authentication via /ping.
func TestHealthcheckBypassPrevention(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	cfg.Secret = []byte("test-secret-12345678901234567890")
	config = cfg

	server := NewServer()

	// 1. Direct healthcheck probe (NO X-Forwarded-Uri) -> should return 200 OK
	directReq := httptest.NewRequest("GET", "/ping", nil)
	rec := httptest.NewRecorder()
	server.RootHandler(rec, directReq)
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal("OK", rec.Body.String())

	// 2. Forwarded auth request to /ping (with X-Forwarded-Uri: /ping) -> MUST NOT bypass auth!
	fwdReq := httptest.NewRequest("GET", "http://auth.internal/", nil)
	fwdReq.Header.Set("X-Forwarded-Method", "GET")
	fwdReq.Header.Set("X-Forwarded-Proto", "https")
	fwdReq.Header.Set("X-Forwarded-Host", "secure-api.corp.com")
	fwdReq.Header.Set("X-Forwarded-Uri", "/ping")

	rec2 := httptest.NewRecorder()
	server.RootHandler(rec2, fwdReq)
	// Without cookie, this should redirect to OAuth provider (307), NOT 200 OK!
	assert.Equal(http.StatusTemporaryRedirect, rec2.Code, "forwarded request to /ping should redirect unauthenticated users")
	loc, err := rec2.Result().Location()
	assert.NoError(err)
	assert.Contains(loc.String(), "accounts.google.com")

	// 3. Forwarded auth request to /ping with valid auth cookie -> 200 OK with X-Forwarded-User
	validCookie := MakeCookie(fwdReq, "example@example.com")
	fwdReq.AddCookie(validCookie)
	rec3 := httptest.NewRecorder()
	server.RootHandler(rec3, fwdReq)
	assert.Equal(http.StatusOK, rec3.Code)
	assert.Equal("example@example.com", rec3.Header().Get("X-Forwarded-User"))
}

// TestClientForwardedHeaderRuleRejection tests rule validation blocking X-Forwarded-For and Forwarded in allow rules.
func TestClientForwardedHeaderRuleRejection(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()

	disallowedRules := []string{
		"Headers(`X-Forwarded-For`, `10.0.0.1`)",
		"Headers(`x-forwarded-for`, `10.0.0.1`)",
		"HeadersRegexp(`X-Forwarded-For`, `.*`)",
		"Headers(`Forwarded`, `for=10.0.0.1`)",
		"HeadersRegexp(`forwarded`, `.*`)",
		"Headers( `X-Forwarded-For` , `10.0.0.1` )",
		"PathPrefix(`/api`) && Headers(`X-Forwarded-For`, `1.2.3.4`)",
	}

	for _, rStr := range disallowedRules {
		r := &Rule{
			Action:   "allow",
			Rule:     rStr,
			Provider: "google",
		}
		err := r.Validate(cfg)
		assert.Error(err, "rule %q should be rejected for allow action", rStr)
		if err != nil {
			assert.Contains(err.Error(), "client-controlled header")
		}

		// Same rule with action "auth" is acceptable (since it still requires auth)
		rAuth := &Rule{
			Action:   "auth",
			Rule:     rStr,
			Provider: "google",
		}
		errAuth := rAuth.Validate(cfg)
		assert.NoError(errAuth, "rule %q should be accepted for auth action", rStr)
	}

	// Safe header: X-Real-Ip is allowed
	safeRule := &Rule{
		Action:   "allow",
		Rule:     "Headers(`X-Real-Ip`, `10.0.0.1`)",
		Provider: "google",
	}
	assert.NoError(safeRule.Validate(cfg))
}

// TestTimingAttackResistance verifies constant time comparisons are used.
func TestTimingAttackResistance(t *testing.T) {
	assert := assert.New(t)

	// ValidateCookie uses hmac.Equal
	key := []byte("secret-key")
	h1 := hmac.New(sha256.New, key)
	h1.Write([]byte("message"))
	mac1 := h1.Sum(nil)

	h2 := hmac.New(sha256.New, key)
	h2.Write([]byte("message"))
	mac2 := h2.Sum(nil)

	h3 := hmac.New(sha256.New, key)
	h3.Write([]byte("different"))
	mac3 := h3.Sum(nil)

	assert.True(hmac.Equal(mac1, mac2))
	assert.False(hmac.Equal(mac1, mac3))
}

// TestRootHandlerMalformedURINoPanic verifies that malformed URIs return 400 and do not cause nil pointer dereference panics.
func TestRootHandlerMalformedURINoPanic(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	config = cfg
	server := NewServer()

	malformedURIs := []string{
		"http://[::1:80",
		"://invalid-uri",
		"\x7f",
	}

	for _, badURI := range malformedURIs {
		req := httptest.NewRequest("GET", "http://auth.local/", nil)
		req.Header.Set("X-Forwarded-Uri", badURI)
		rec := httptest.NewRecorder()

		assert.NotPanics(func() {
			server.RootHandler(rec, req)
		}, "malformed URI %q should not panic", badURI)

		assert.Equal(http.StatusBadRequest, rec.Code, "malformed URI %q should return 400 Bad Request", badURI)
	}
}

// TestPathTraversalRuleBypassPrevention verifies that an attacker cannot bypass auth via dot segments like /public/../admin.
func TestPathTraversalRuleBypassPrevention(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	cfg.Rules = map[string]*Rule{
		"public": {
			Action: "allow",
			Rule:   "PathPrefix(`/public`)",
		},
	}
	config = cfg
	server := NewServer()

	traversalURIs := []string{
		"/public/../admin",
		"/public/sub/../../admin",
		"/public/..%2fadmin",
		"/public/%2e%2e/admin",
	}

	for _, uri := range traversalURIs {
		req := httptest.NewRequest("GET", "http://example.com"+uri, nil)
		req.Header.Set("X-Forwarded-Method", "GET")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "example.com")
		req.Header.Set("X-Forwarded-Uri", uri)

		rec := httptest.NewRecorder()
		server.RootHandler(rec, req)

		// Must NOT return 200 OK (allow). Since user is not authenticated, must return 307 redirect!
		assert.Equal(http.StatusTemporaryRedirect, rec.Code, "path traversal URI %q must require auth and redirect, not allow!", uri)
	}
}

// TestDoubleSlashEvasionPrevention verifies that paths starting with // are normalized and properly match auth rules.
func TestDoubleSlashEvasionPrevention(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	cfg.DefaultAction = "allow"
	cfg.Rules = map[string]*Rule{
		"admin": {
			Action:   "auth",
			Rule:     "PathPrefix(`/admin`)",
			Provider: "google",
		},
	}
	config = cfg
	server := NewServer()

	doubleSlashURIs := []string{
		"//admin",
		"//admin/settings",
		"///admin",
	}

	for _, uri := range doubleSlashURIs {
		req := httptest.NewRequest("GET", "http://example.com"+uri, nil)
		req.Header.Set("X-Forwarded-Method", "GET")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "example.com")
		req.Header.Set("X-Forwarded-Uri", uri)

		rec := httptest.NewRecorder()
		server.RootHandler(rec, req)

		// Under default-action=allow, /admin is protected by auth rule.
		// If //admin evaded rule matching, it would return 200 OK (bypass!).
		// With proper normalization, it matches PathPrefix(/admin) and redirects (307)!
		assert.Equal(http.StatusTemporaryRedirect, rec.Code, "URI %q must match auth rule and redirect, not allow!", uri)
	}
}

// TestClientForwardedHeaderRuleRejectionComprehensive verifies all syntax variants (single, double, backtick, Header, Headers).
func TestClientForwardedHeaderRuleRejectionComprehensive(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()

	disallowedRules := []string{
		`Headers("X-Forwarded-For", "1.2.3.4")`,
		`Header("X-Forwarded-For", "1.2.3.4")`,
		`Header('X-Forwarded-For', '1.2.3.4')`,
		`Header(` + "`X-Forwarded-For`, `1.2.3.4`" + `)`,
		`HeaderRegexp("X-Forwarded-For", ".*")`,
		`HeadersRegexp("X-Forwarded-For", ".*")`,
		`Headers("Forwarded", "for=1.2.3.4")`,
		`Header("Forwarded", "for=1.2.3.4")`,
		`Header(` + "`Forwarded`, `for=1.2.3.4`" + `)`,
		`HeaderRegexp("Forwarded", ".*")`,
	}

	for _, rStr := range disallowedRules {
		r := &Rule{
			Action:   "allow",
			Rule:     rStr,
			Provider: "google",
		}
		err := r.Validate(cfg)
		assert.Error(err, "rule %q must be rejected for allow action", rStr)
	}
}
