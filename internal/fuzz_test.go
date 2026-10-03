package tfa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzValidateCookie(f *testing.F) {
	// Seed corpus
	f.Add("")
	f.Add("a|b|c")
	f.Add("MQ==|1800000000|user@example.com")
	f.Add("invalidbase64|notint|bademail")
	f.Add("||")
	f.Add("|||")
	f.Add(strings.Repeat("A", 1000))

	cfg := newDefaultConfig()
	cfg.Secret = []byte("fuzz-secret-key-1234567890123456")
	config = cfg

	r := httptest.NewRequest("GET", "https://app.example.com", nil)

	f.Fuzz(func(t *testing.T, cookieVal string) {
		c := &http.Cookie{
			Name:  config.CookieName,
			Value: cookieVal,
		}
		// ValidateCookie must never panic, even on arbitrary garbage inputs
		_, _ = ValidateCookie(r, c)
	})
}

func FuzzValidateRedirect(f *testing.F) {
	f.Add("/", "example.com")
	f.Add("/path?q=1", "example.com")
	f.Add("//evil.com", "example.com")
	f.Add("/\\evil.com", "example.com")
	f.Add("\\evil.com", "example.com")
	f.Add("https://example.com/target", "example.com")
	f.Add("https://attacker.com/target", "example.com")
	f.Add("javascript:alert(1)", "example.com")
	f.Add("data:text/html,test", "example.com")
	f.Add("https://user:pass@example.com", "example.com")
	f.Add("https://example.com:8443/secure", "example.com")
	f.Add("\r\nLocation: evil.com", "example.com")

	cfg := newDefaultConfig()
	cfg.CookieDomains = []CookieDomain{
		*NewCookieDomain("example.com"),
	}
	config = cfg

	f.Fuzz(func(t *testing.T, redirectURL string, reqHost string) {
		u, err := ValidateRedirect(redirectURL, reqHost)
		if err == nil && u != nil {
			// Invariants for valid redirects:
			// 1. Must never contain CRLF
			if strings.ContainsAny(redirectURL, "\r\n") {
				t.Fatalf("ValidateRedirect allowed CRLF injection: %q", redirectURL)
			}
			// 2. If relative, must never start with // or /\ or \
			if u.Scheme == "" && u.Host == "" {
				if strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, "/\\") || strings.HasPrefix(redirectURL, "\\") {
					t.Fatalf("ValidateRedirect allowed scheme-relative or backslash bypass: %q", redirectURL)
				}
			}
			// 3. If absolute, scheme must be http or https
			if u.Scheme != "" && !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
				t.Fatalf("ValidateRedirect allowed non-http scheme: %q", redirectURL)
			}
		}
	})
}

func FuzzValidateEmail(f *testing.F) {
	f.Add("user@example.com")
	f.Add("admin@sub.corp.com")
	f.Add("no-at-sign")
	f.Add("@nodomain")
	f.Add("nouser@")
	f.Add("two@at@signs.com")
	f.Add("")
	f.Add("user+tag@domain.co.uk")

	config = &Config{
		Whitelist:              []string{"allowed@example.com"},
		Domains:                []string{"example.com", "corp.com"},
		MatchWhitelistOrDomain: true,
		Rules:                  map[string]*Rule{},
	}

	f.Fuzz(func(t *testing.T, email string) {
		// Must not panic on any email format
		_ = ValidateEmail(email, "default")
	})
}

func FuzzValidateCSRFCookie(f *testing.F) {
	f.Add(strings.Repeat("a", 32), strings.Repeat("a", 32)+":google:/path")
	f.Add("short", "short")
	f.Add("", "")
	f.Add(strings.Repeat("x", 32), strings.Repeat("x", 32)+":unknown-provider:http://bad")

	cfg := newDefaultConfig()
	cfg.CookieDomains = []CookieDomain{
		*NewCookieDomain("example.com"),
	}
	config = cfg

	f.Fuzz(func(t *testing.T, cookieVal, stateVal string) {
		c := &http.Cookie{
			Name:  "_forward_auth_csrf",
			Value: cookieVal,
		}
		// ValidateCSRFCookie must never panic
		_, _, _, _ = ValidateCSRFCookie(c, stateVal, "example.com")
	})
}

func FuzzCookieDomainMatch(f *testing.F) {
	f.Add("example.com", "example.com")
	f.Add("example.com", "app.example.com")
	f.Add("example.com", "notexample.com")
	f.Add("example.com", "evil.com")
	f.Add("sub.domain.org", "deep.sub.domain.org")

	f.Fuzz(func(t *testing.T, domainDef, testHost string) {
		if len(domainDef) == 0 {
			return
		}
		cd := NewCookieDomain(domainDef)
		// Must never panic
		matched := cd.Match(testHost)
		if matched {
			// Invariant: host must either equal domain or end with .domain
			if testHost != domainDef && !strings.HasSuffix(testHost, "."+domainDef) {
				t.Fatalf("CookieDomain match logic error: %q matched %q", domainDef, testHost)
			}
		}
	})
}

func FuzzServerRootHandler(f *testing.F) {
	f.Add("GET", "https", "example.com", "/protected")
	f.Add("POST", "http", "example.com:8080", "/ping")
	f.Add("DELETE", "ftp", "another.com", "foo")
	f.Add("CONNECT", "", "", "")
	f.Add("GET", "https", "example.com, proxy2", "/a, /b")

	cfg := newDefaultConfig()
	cfg.Secret = []byte("fuzzing-signing-secret-123456789")
	config = cfg
	server := NewServer()

	f.Fuzz(func(t *testing.T, method, proto, host, uri string) {
		req := httptest.NewRequest("GET", "http://auth.local/", nil)
		if method != "" {
			req.Header.Set("X-Forwarded-Method", method)
		}
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		if host != "" {
			req.Header.Set("X-Forwarded-Host", host)
		}
		if uri != "" {
			req.Header.Set("X-Forwarded-Uri", uri)
		}

		rec := httptest.NewRecorder()
		// Must never panic on any combination of forwarded headers
		server.RootHandler(rec, req)
	})
}
