package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGenericOAuthTokenStyleAndErrors(t *testing.T) {
	assert := assert.New(t)

	// 1. Test token style "query"
	queryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("GET", r.Method)
		assert.Equal("token-12345", r.URL.Query().Get("access_token"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"email":"queryuser@example.com"}`)
	}))
	defer queryServer.Close()

	pQuery := &GenericOAuth{
		TokenStyle: "query",
		UserURL:    queryServer.URL,
	}
	user, err := pQuery.GetUser("token-12345")
	assert.NoError(err)
	assert.Equal("queryuser@example.com", user.Email)

	// 2. Test userinfo HTTP error 500
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal server error", 500)
	}))
	defer failingServer.Close()

	pFailing := &GenericOAuth{
		TokenStyle: "header",
		UserURL:    failingServer.URL,
	}
	_, err = pFailing.GetUser("token-123")
	assert.Error(err)

	// 3. Test userinfo malformed JSON
	badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{not valid json`)
	}))
	defer badJSONServer.Close()

	pBadJSON := &GenericOAuth{
		TokenStyle: "header",
		UserURL:    badJSONServer.URL,
	}
	_, err = pBadJSON.GetUser("token-123")
	assert.Error(err)

	// 4. Test invalid user URL
	pBadURL := &GenericOAuth{
		TokenStyle: "header",
		UserURL:    "://invalid-url",
	}
	_, err = pBadURL.GetUser("token-123")
	assert.Error(err)

	// 5. Test ExchangeCode error
	pExchange := &GenericOAuth{
		OAuthProvider: OAuthProvider{
			Config: &oauth2.Config{
				Endpoint: oauth2.Endpoint{
					TokenURL: failingServer.URL,
				},
			},
			ctx: context.Background(),
		},
	}
	_, err = pExchange.ExchangeCode("http://redirect", "bad-code")
	assert.Error(err)
}

func TestGoogleErrors(t *testing.T) {
	assert := assert.New(t)

	// Failing server
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal server error", 500)
	}))
	defer failingServer.Close()

	tokenURL, _ := url.Parse(failingServer.URL)
	userURL, _ := url.Parse(failingServer.URL)

	g := &Google{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     tokenURL,
		UserURL:      userURL,
	}

	// 1. ExchangeCode failure
	_, err := g.ExchangeCode("http://redirect", "code-123")
	assert.Error(err)

	// 2. GetUser failure
	_, err = g.GetUser("bad-token")
	assert.Error(err)

	// 3. Bad JSON response
	badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	}))
	defer badJSONServer.Close()
	badUserURL, _ := url.Parse(badJSONServer.URL)
	gBad := &Google{UserURL: badUserURL}
	_, err = gBad.GetUser("token")
	assert.Error(err)
}

func TestOIDCMissingIDToken(t *testing.T) {
	assert := assert.New(t)

	// Server returning access_token without id_token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"at-123"}`)
	}))
	defer server.Close()

	o := &OIDC{
		OAuthProvider: OAuthProvider{
			Config: &oauth2.Config{
				Endpoint: oauth2.Endpoint{
					TokenURL: server.URL,
				},
			},
			ctx: context.Background(),
		},
	}

	_, err := o.ExchangeCode("http://redirect", "code")
	assert.Error(err)
	assert.Contains(err.Error(), "Missing id_token")
}

func TestOAuthProviderResourceParameter(t *testing.T) {
	assert := assert.New(t)

	cfg := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.com/auth",
			TokenURL: "https://provider.com/token",
		},
	}

	p := &OAuthProvider{
		Resource: "https://api.myresource.org",
		Config:   cfg,
		ctx:      context.Background(),
	}

	loginURL := p.OAuthGetLoginURL("https://app.com/callback", "nonce123")
	u, err := url.Parse(loginURL)
	require.NoError(t, err)

	assert.Equal("https://api.myresource.org", u.Query().Get("resource"))
	assert.Equal("nonce123", u.Query().Get("state"))
	assert.Equal("https://app.com/callback", u.Query().Get("redirect_uri"))

	// Without Resource
	pNoResource := &OAuthProvider{
		Config: cfg,
		ctx:    context.Background(),
	}
	loginURLNoRes := pNoResource.OAuthGetLoginURL("https://app.com/callback", "nonce123")
	uNoRes, err := url.Parse(loginURLNoRes)
	require.NoError(t, err)
	assert.Empty(uNoRes.Query().Get("resource"))
}
