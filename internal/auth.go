package tfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/priyankub/traefik-forward-auth-secure/internal/provider"
)

// Request Validation

// ValidateCookie verifies that a cookie matches the expected format of:
// Cookie = hash(secret, cookie domain, email, expires)|expires|email
func ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("Invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Unable to decode cookie mac")
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("Unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New("Invalid cookie mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("Unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("Cookie has expired")
	}

	// Looks valid
	return parts[2], nil
}

// ValidateEmail checks if the given email address matches either a whitelisted
// email address, as defined by the "whitelist" config parameter. Or is part of
// a permitted domain, as defined by the "domains" config parameter
func ValidateEmail(email, ruleName string) bool {
	// Use global config by default
	whitelist := config.Whitelist
	domains := config.Domains

	if rule, ok := config.Rules[ruleName]; ok {
		// Override with rule config if found
		if len(rule.Whitelist) > 0 || len(rule.Domains) > 0 {
			whitelist = rule.Whitelist
			domains = rule.Domains
		}
	}

	// Do we have any validation to perform?
	if len(whitelist) == 0 && len(domains) == 0 {
		return true
	}

	// Email whitelist validation
	if len(whitelist) > 0 {
		if ValidateWhitelist(email, whitelist) {
			return true
		}

		// If we're not matching *either*, stop here
		if !config.MatchWhitelistOrDomain {
			return false
		}
	}

	// Domain validation
	if len(domains) > 0 && ValidateDomains(email, domains) {
		return true
	}

	return false
}

// ValidateWhitelist checks if the email is in whitelist
func ValidateWhitelist(email string, whitelist CommaSeparatedList) bool {
	for _, whitelist := range whitelist {
		if strings.EqualFold(email, whitelist) {
			return true
		}
	}
	return false
}

// ValidateDomains checks if the email matches a whitelisted domain
func ValidateDomains(email string, domains CommaSeparatedList) bool {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return false
	}
	for _, domain := range domains {
		if strings.EqualFold(domain, parts[1]) {
			return true
		}
	}
	return false
}

// Utility methods

// Get the redirect base
func redirectBase(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.Header.Get("X-Forwarded-Proto"), r.Host)
}

// Return url
func returnUrl(r *http.Request) string {
	return fmt.Sprintf("%s%s", redirectBase(r), r.URL.Path)
}

// Get oauth redirect uri
func redirectUri(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		p := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", p, config.AuthHost, config.Path)
	}

	return fmt.Sprintf("%s%s", redirectBase(r), config.Path)
}

// Should we use auth host + what it is
func useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Host)

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeCookie creates an auth cookie
func MakeCookie(r *http.Request, email string) *http.Cookie {
	expires := cookieExpiry()
	mac := cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

// ClearCookies returns a slice of expired cookies covering all domain permutations (.domain, domain, host-only)
func ClearCookies(r *http.Request) []*http.Cookie {
	var cookies []*http.Cookie
	seen := make(map[string]bool)

	add := func(domain string) {
		if seen[domain] {
			return
		}
		seen[domain] = true
		cookies = append(cookies, &http.Cookie{
			Name:     config.CookieName,
			Value:    "",
			Path:     "/",
			Domain:   domain,
			HttpOnly: true,
			Secure:   !config.InsecureCookie,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Local().Add(time.Hour * -1),
		})
	}

	// Always clear host-only cookie (empty domain)
	add("")

	// Clear host without port
	hostParts := strings.Split(r.Host, ":")
	add(hostParts[0])

	// Clear configured domains and subdomains
	for _, d := range config.CookieDomains {
		add(d.Domain)
		add(d.SubDomain)
	}

	// Fallback to cookieDomain(r)
	add(cookieDomain(r))

	return cookies
}

func buildCSRFCookieName(nonce string) string {
	return config.CSRFCookieName + "_" + nonce[:6]
}

// MakeCSRFCookie makes a csrf cookie (used during login only)
//
// Note, CSRF cookies live shorter than auth cookies, a fixed 1h.
// That's because some CSRF cookies may belong to auth flows that don't complete
// and thus may not get cleared by ClearCookie.
func MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     buildCSRFCookieName(nonce),
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Local().Add(time.Hour * 1),
	}
}

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
func ClearCSRFCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// FindCSRFCookie extracts the CSRF cookie from the request based on state.
func FindCSRFCookie(r *http.Request, state string) (c *http.Cookie, err error) {
	// Check for CSRF cookie
	return r.Cookie(buildCSRFCookieName(state))
}

// ValidateCSRFCookie validates the csrf cookie against state
func ValidateCSRFCookie(c *http.Cookie, state string) (valid bool, provider string, redirect string, err error) {
	if len(c.Value) != 32 {
		return false, "", "", errors.New("Invalid CSRF cookie value")
	}

	// Check nonce match
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(state[:32])) != 1 {
		return false, "", "", errors.New("CSRF cookie does not match state")
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New("Invalid CSRF state format")
	}

	// Valid, return provider and redirect
	redirect = params[split+1:]
	if err := ValidateRedirect(redirect); err != nil {
		return false, "", "", err
	}

	return true, params[:split], redirect, nil
}

// ValidateRedirect verifies that the redirect URL is valid and targets a trusted domain or relative path.
func ValidateRedirect(redirect string) error {
	if strings.ContainsAny(redirect, "\r\n") {
		return errors.New("redirect URL contains invalid characters")
	}

	u, err := url.Parse(redirect)
	if err != nil {
		return errors.New("invalid redirect URL format")
	}

	// Relative path redirects on the same host are safe
	if u.Scheme == "" && u.Host == "" {
		if strings.HasPrefix(u.Path, "//") {
			return errors.New("relative redirect cannot start with //")
		}
		return nil
	}

	// For absolute URLs, enforce HTTP/HTTPS schemes only
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return errors.New("invalid redirect scheme")
	}

	host := strings.Split(u.Host, ":")[0]
	if config != nil && config.AuthHost == "" && len(config.CookieDomains) == 0 {
		return nil
	}

	if config != nil && config.AuthHost != "" && strings.EqualFold(host, config.AuthHost) {
		return nil
	}

	if config != nil {
		for _, d := range config.CookieDomains {
			if d.Match(host) {
				return nil
			}
		}
	}

	return errors.New("redirect host is not in allowed domains")
}

// MakeState generates a state value
func MakeState(r *http.Request, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl(r))
}

// ValidateState checks whether the state is of right length.
func ValidateState(state string) error {
	if len(state) < 34 {
		return errors.New("Invalid CSRF state value")
	}
	return nil
}

// Nonce generates a random nonce
func Nonce() (error, string) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return err, ""
	}

	return nil, fmt.Sprintf("%x", nonce)
}

// Cookie domain
func cookieDomain(r *http.Request) string {
	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(r.Host)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Host
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range config.CookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Create cookie hmac
func cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte("|"))
	hash.Write([]byte(email))
	hash.Write([]byte("|"))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expiry
func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.Lifetime)
}

// CookieDomain holds cookie domain info
type CookieDomain struct {
	Domain       string
	DomainLen    int
	SubDomain    string
	SubDomainLen int
}

// NewCookieDomain creates a new CookieDomain from the given domain string
func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match checks if the given host matches this CookieDomain
func (c *CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	if len(host) >= c.SubDomainLen && host[len(host)-c.SubDomainLen:] == c.SubDomain {
		return true
	}

	return false
}

// UnmarshalFlag converts a string to a CookieDomain
func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *NewCookieDomain(value)
	return nil
}

// MarshalFlag converts a CookieDomain to a string
func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// CookieDomains provides legacy sypport for comma separated list of cookie domains
type CookieDomains []CookieDomain

// UnmarshalFlag converts a comma separated list of cookie domains to an array
// of CookieDomains
func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

// MarshalFlag converts an array of CookieDomain to a comma seperated list
func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
