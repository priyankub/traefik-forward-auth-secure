package tfa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthEdgeValidateCookie(t *testing.T) {
	assert := assert.New(t)

	cfg, err := NewConfig([]string{
		"--secret=very-secret-key-12345678",
		"--cookie-domain=example.com",
	})
	require.NoError(t, err)
	config = cfg

	r := httptest.NewRequest("GET", "https://app.example.com", nil)

	// 1. Invalid base64 in signature
	c := &http.Cookie{
		Name:  config.CookieName,
		Value: "%%%invalid-base64%%%|1800000000|user@example.com",
	}
	_, err = ValidateCookie(r, c)
	assert.Error(err)
	assert.Equal("Unable to decode cookie mac", err.Error())

	// 2. Non-integer expiry
	// Compute valid signature for invalid expiry string
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte("|"))
	hash.Write([]byte("user@example.com"))
	hash.Write([]byte("|"))
	hash.Write([]byte("not-an-int"))
	validMac := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	c = &http.Cookie{
		Name:  config.CookieName,
		Value: fmt.Sprintf("%s|not-an-int|user@example.com", validMac),
	}
	_, err = ValidateCookie(r, c)
	assert.Error(err)
	assert.Equal("Unable to parse cookie expiry", err.Error())

	// 3. Expired cookie
	pastExpiry := fmt.Sprintf("%d", time.Now().Add(-1*time.Hour).Unix())
	hash = hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte("|"))
	hash.Write([]byte("user@example.com"))
	hash.Write([]byte("|"))
	hash.Write([]byte(pastExpiry))
	pastMac := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	c = &http.Cookie{
		Name:  config.CookieName,
		Value: fmt.Sprintf("%s|%s|user@example.com", pastMac, pastExpiry),
	}
	_, err = ValidateCookie(r, c)
	assert.Error(err)
	assert.Equal("Cookie has expired", err.Error())

	// 4. Valid future cookie
	futureExpiry := fmt.Sprintf("%d", time.Now().Add(24*time.Hour).Unix())
	hash = hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte("|"))
	hash.Write([]byte("user@example.com"))
	hash.Write([]byte("|"))
	hash.Write([]byte(futureExpiry))
	futureMac := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	c = &http.Cookie{
		Name:  config.CookieName,
		Value: fmt.Sprintf("%s|%s|user@example.com", futureMac, futureExpiry),
	}
	email, err := ValidateCookie(r, c)
	assert.NoError(err)
	assert.Equal("user@example.com", email)
}

func TestAuthEdgeValidateEmailMatrix(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name                   string
		whitelist              []string
		domains                []string
		matchWhitelistOrDomain bool
		email                  string
		expected               bool
	}{
		// No whitelist, no domain -> allow all
		{"no constraints allows any", nil, nil, false, "anyone@anywhere.com", true},

		// Whitelist only
		{"whitelist match exact", []string{"user@corp.com"}, nil, false, "user@corp.com", true},
		{"whitelist match case insensitive", []string{"User@Corp.com"}, nil, false, "user@corp.com", true},
		{"whitelist mismatch", []string{"user@corp.com"}, nil, false, "other@corp.com", false},

		// Domain only
		{"domain match exact", nil, []string{"corp.com"}, false, "user@corp.com", true},
		{"domain match case insensitive", nil, []string{"Corp.Com"}, false, "user@corp.com", true},
		{"domain mismatch", nil, []string{"corp.com"}, false, "user@evil.com", false},
		{"domain invalid email no at", nil, []string{"corp.com"}, false, "notanemail", false},
		{"domain invalid email empty", nil, []string{"corp.com"}, false, "", false},

		// Whitelist AND domain with MatchWhitelistOrDomain = false (must match whitelist, or fail if not in whitelist)
		{"both configured, in whitelist (match either = false)", []string{"user@corp.com"}, []string{"example.com"}, false, "user@corp.com", true},
		{"both configured, in domain not whitelist (match either = false)", []string{"user@corp.com"}, []string{"example.com"}, false, "user@example.com", false},

		// Whitelist AND domain with MatchWhitelistOrDomain = true (match either)
		{"both configured, in whitelist (match either = true)", []string{"special@partner.com"}, []string{"corp.com"}, true, "special@partner.com", true},
		{"both configured, in domain (match either = true)", []string{"special@partner.com"}, []string{"corp.com"}, true, "regular@corp.com", true},
		{"both configured, in neither (match either = true)", []string{"special@partner.com"}, []string{"corp.com"}, true, "intruder@evil.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config = &Config{
				Whitelist:              tc.whitelist,
				Domains:                tc.domains,
				MatchWhitelistOrDomain: tc.matchWhitelistOrDomain,
				Rules:                  map[string]*Rule{},
			}
			result := ValidateEmail(tc.email, "default")
			assert.Equal(tc.expected, result)
		})
	}
}

func TestAuthEdgeRuleEmailOverride(t *testing.T) {
	assert := assert.New(t)

	config = &Config{
		Whitelist:              []string{"global@corp.com"},
		Domains:                []string{"corp.com"},
		MatchWhitelistOrDomain: true,
		Rules: map[string]*Rule{
			"admin-rule": {
				Whitelist: []string{"admin@corp.com"},
			},
			"partner-rule": {
				Domains: []string{"partner.org"},
			},
		},
	}

	// Global allows global@corp.com
	assert.True(ValidateEmail("global@corp.com", "default"))
	assert.True(ValidateEmail("user@corp.com", "default"))

	// admin-rule overrides and only allows admin@corp.com
	assert.True(ValidateEmail("admin@corp.com", "admin-rule"))
	assert.False(ValidateEmail("global@corp.com", "admin-rule"))
	assert.False(ValidateEmail("user@corp.com", "admin-rule"))

	// partner-rule overrides and only allows @partner.org
	assert.True(ValidateEmail("person@partner.org", "partner-rule"))
	assert.False(ValidateEmail("user@corp.com", "partner-rule"))
}

func TestCookieDomainFlagMarshaling(t *testing.T) {
	assert := assert.New(t)

	cd := NewCookieDomain("sub.example.com")
	assert.Equal("sub.example.com", cd.Domain)
	assert.Equal(".sub.example.com", cd.SubDomain)

	marshaled, err := cd.MarshalFlag()
	assert.NoError(err)
	assert.Equal("sub.example.com", marshaled)

	var unmarshaled CookieDomain
	err = unmarshaled.UnmarshalFlag("newdomain.org")
	assert.NoError(err)
	assert.Equal("newdomain.org", unmarshaled.Domain)
	assert.Equal(".newdomain.org", unmarshaled.SubDomain)

	// CookieDomains legacy list marshaling
	cds := CookieDomains{
		*NewCookieDomain("one.com"),
		*NewCookieDomain("two.com"),
	}
	str, err := cds.MarshalFlag()
	assert.NoError(err)
	assert.Equal("one.com,two.com", str)

	var unmarshaledList CookieDomains
	err = unmarshaledList.UnmarshalFlag("alpha.io,beta.io")
	assert.NoError(err)
	assert.Len(unmarshaledList, 2)
	assert.Equal("alpha.io", unmarshaledList[0].Domain)
	assert.Equal("beta.io", unmarshaledList[1].Domain)

	// Empty string unmarshal
	var emptyList CookieDomains
	err = emptyList.UnmarshalFlag("")
	assert.NoError(err)
	assert.Len(emptyList, 0)
}

func TestUseAuthDomain(t *testing.T) {
	assert := assert.New(t)

	config = &Config{
		AuthHost: "auth.example.com",
		CookieDomains: []CookieDomain{
			*NewCookieDomain("example.com"),
		},
	}

	// Request matches same cookie domain as auth host
	r := httptest.NewRequest("GET", "https://app.example.com/protected", nil)
	use, domain := useAuthDomain(r)
	assert.True(use)
	assert.Equal("example.com", domain)

	// Request host is on different cookie domain
	r2 := httptest.NewRequest("GET", "https://other.net/protected", nil)
	use2, _ := useAuthDomain(r2)
	assert.False(use2)

	// When AuthHost is empty
	config.AuthHost = ""
	use3, _ := useAuthDomain(r)
	assert.False(use3)
}
