package tfa

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/priyankub/traefik-forward-auth-secure/internal/provider"
	"github.com/sirupsen/logrus"
	muxhttp "github.com/traefik/traefik/v3/pkg/muxer/http"
)

// Server contains muxer and handler methods
type Server struct {
	muxer *muxhttp.Muxer
}

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	parser, err := muxhttp.NewSyntaxParser()
	if err != nil {
		log.Fatal(err)
	}
	s.muxer = muxhttp.NewMuxer(parser, nil)

	// Let's build a muxer
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		priority := muxhttp.GetRulePriority(matchRule)
		if rule.Action == "allow" {
			_ = s.muxer.AddRoute(matchRule, "v2", priority, "", s.AllowHandler(name))
		} else {
			_ = s.muxer.AddRoute(matchRule, "v2", priority, "", s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	cbRule := fmt.Sprintf("Path(`%s`)", config.Path)
	_ = s.muxer.AddRoute(cbRule, "v2", muxhttp.GetRulePriority(cbRule), "", s.AuthCallbackHandler())

	// Add logout handler
	logoutRule := fmt.Sprintf("Path(`%s/logout`)", config.Path)
	_ = s.muxer.AddRoute(logoutRule, "v2", muxhttp.GetRulePriority(logoutRule), "", s.LogoutHandler())

	// Add healthcheck handler
	pingRule := "Path(`/ping`)"
	_ = s.muxer.AddRoute(pingRule, "v2", muxhttp.GetRulePriority(pingRule), "", s.HealthcheckHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.muxer.SetDefaultHandler(s.AllowHandler("default"))
	} else {
		s.muxer.SetDefaultHandler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Enforce leading slash to prevent route/rule bypasses (Issue #424)
	if r.URL != nil && r.URL.Path != "" && !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.WithField("error", err).Warn("Invalid cookie")
				for _, c := range ClearCookies(r) {
					http.SetCookie(w, c)
				}
				s.authRedirect(logger, w, r, p)
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email, rule)
		if !valid {
			logger.WithField("email", email).Warn("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Valid request
		logger.Debug("Allowing valid request")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := r.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := p.GetUser(token)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user.Email))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     user.Email,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		if err := ValidateRedirect(redirect); err != nil {
			logger.WithField("error", err).Warn("Invalid redirect URL")
			http.Error(w, "Not authorized", 401)
			return
		}
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		for _, c := range ClearCookies(r) {
			http.SetCookie(w, c)
		}

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

// HealthcheckHandler handles healthcheck requests
func (s *Server) HealthcheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	var cookieNames []string
	for _, c := range r.Cookies() {
		cookieNames = append(cookieNames, c.Name)
	}
	logger.WithFields(logrus.Fields{
		"cookies": cookieNames,
	}).Debug(msg)

	return logger
}
