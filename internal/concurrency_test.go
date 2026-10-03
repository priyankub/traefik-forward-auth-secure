package tfa

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerHighConcurrencyAndRaceStress hammers the server with concurrent requests of diverse types.
func TestServerHighConcurrencyAndRaceStress(t *testing.T) {
	cfg := newDefaultConfig()
	cfg.Secret = []byte("super-secret-key-for-stress-testing-123456789")
	cfg.CookieDomains = []CookieDomain{
		*NewCookieDomain("example.com"),
		*NewCookieDomain("corp.net"),
	}
	config = cfg

	server := NewServer()

	// Pre-create some cookies for known users
	rExample := httptest.NewRequest("GET", "https://app.example.com", nil)
	validCookie := MakeCookie(rExample, "example@example.com")

	const (
		concurrency       = 50
		requestsPerWorker = 200
	)

	var wg sync.WaitGroup
	wg.Add(concurrency)

	errChan := make(chan error, concurrency*requestsPerWorker)

	for worker := 0; worker < concurrency; worker++ {
		go func(workerID int) {
			defer wg.Done()

			r := rand.New(rand.NewSource(int64(workerID * 1000)))

			for reqNum := 0; reqNum < requestsPerWorker; reqNum++ {
				op := r.Intn(6)
				rec := httptest.NewRecorder()

				switch op {
				case 0:
					// Direct healthcheck probe
					req := httptest.NewRequest("GET", "/ping", nil)
					server.RootHandler(rec, req)
					if rec.Code != http.StatusOK {
						errChan <- fmt.Errorf("direct healthcheck returned %d", rec.Code)
					}

				case 1:
					// Forwarded healthcheck request (must not bypass auth, redirects unauth)
					req := httptest.NewRequest("GET", "http://auth.internal/", nil)
					req.Header.Set("X-Forwarded-Method", "GET")
					req.Header.Set("X-Forwarded-Proto", "https")
					req.Header.Set("X-Forwarded-Host", "secure.example.com")
					req.Header.Set("X-Forwarded-Uri", "/ping")
					server.RootHandler(rec, req)
					if rec.Code != http.StatusTemporaryRedirect {
						errChan <- fmt.Errorf("forwarded /ping returned %d, expected 307", rec.Code)
					}

				case 2:
					// Authenticated request with valid cookie
					req := httptest.NewRequest("GET", "https://app.example.com/api/data", nil)
					req.Header.Set("X-Forwarded-Method", "GET")
					req.Header.Set("X-Forwarded-Proto", "https")
					req.Header.Set("X-Forwarded-Host", "app.example.com")
					req.Header.Set("X-Forwarded-Uri", fmt.Sprintf("/api/data?item=%d", reqNum))
					req.AddCookie(validCookie)
					server.RootHandler(rec, req)
					if rec.Code != http.StatusOK {
						errChan <- fmt.Errorf("authenticated request returned %d", rec.Code)
					}

				case 3:
					// Unauthenticated request -> should redirect to login
					req := httptest.NewRequest("GET", "https://app.example.com/unauth", nil)
					req.Header.Set("X-Forwarded-Method", "GET")
					req.Header.Set("X-Forwarded-Proto", "https")
					req.Header.Set("X-Forwarded-Host", "app.example.com")
					req.Header.Set("X-Forwarded-Uri", "/unauth")
					server.RootHandler(rec, req)
					if rec.Code != http.StatusTemporaryRedirect {
						errChan <- fmt.Errorf("unauth request returned %d, expected 307", rec.Code)
					}

				case 4:
					// Malformed cookie -> clears cookie and redirects
					req := httptest.NewRequest("GET", "https://app.example.com/bad", nil)
					req.Header.Set("X-Forwarded-Method", "GET")
					req.Header.Set("X-Forwarded-Proto", "https")
					req.Header.Set("X-Forwarded-Host", "app.example.com")
					req.Header.Set("X-Forwarded-Uri", "/bad")
					req.AddCookie(&http.Cookie{
						Name:  config.CookieName,
						Value: fmt.Sprintf("garbage-%d|notint|foo@bar.com", reqNum),
					})
					server.RootHandler(rec, req)
					if rec.Code != http.StatusTemporaryRedirect {
						errChan <- fmt.Errorf("bad cookie returned %d, expected 307", rec.Code)
					}

				case 5:
					// Logout request
					req := httptest.NewRequest("GET", "https://app.example.com/_oauth/logout", nil)
					req.Header.Set("X-Forwarded-Method", "GET")
					req.Header.Set("X-Forwarded-Proto", "https")
					req.Header.Set("X-Forwarded-Host", "app.example.com")
					req.Header.Set("X-Forwarded-Uri", "/_oauth/logout")
					server.RootHandler(rec, req)
					if rec.Code != http.StatusUnauthorized {
						errChan <- fmt.Errorf("logout returned %d, expected 401", rec.Code)
					}
				}
			}
		}(worker)
	}

	wg.Wait()
	close(errChan)

	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	require.Empty(t, errors, "concurrency test had failures: %v", errors)
}

func TestConcurrentCookieValidation(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()
	cfg.Secret = []byte("super-secret-key-for-stress-testing-123456789")
	cfg.CookieDomains = []CookieDomain{
		*NewCookieDomain("example.com"),
	}
	config = cfg

	r := httptest.NewRequest("GET", "https://app.example.com", nil)
	cookie := MakeCookie(r, "testuser@example.com")

	const iterations = 5000
	var wg sync.WaitGroup
	wg.Add(20)

	for i := 0; i < 20; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations/20; j++ {
				email, err := ValidateCookie(r, cookie)
				if err != nil || email != "testuser@example.com" {
					t.Errorf("ValidateCookie failed: %v", err)
				}
			}
		}()
	}

	wg.Wait()
	assert.True(true)
}
