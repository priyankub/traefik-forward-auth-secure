package tfa

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestConfigStringRepresentation(t *testing.T) {
	assert := assert.New(t)

	cfg, err := NewConfig([]string{
		"--cookie-domain=example.com",
		"--cookie-name=custom_cookie",
		"--secret=signing-secret-12345",
	})
	require.NoError(t, err)

	str := cfg.String()
	assert.Contains(str, `"CookieName":"custom_cookie"`)
	assert.NotContains(str, "signing-secret-12345", "secret must not be serialized in json representation")
}

func TestConfigLogFormatsAndLevels(t *testing.T) {
	assert := assert.New(t)

	levels := []string{"trace", "debug", "info", "warn", "error", "fatal", "panic", "invalid-default"}
	formats := []string{"pretty", "json", "text", "invalid-default"}

	for _, fmt := range formats {
		for _, lvl := range levels {
			cfg := &Config{
				LogFormat: fmt,
				LogLevel:  lvl,
			}
			config = cfg
			l := NewDefaultLogger()
			assert.NotNil(l)
		}
	}
}

func TestConfigLegacyFlagsAndDeprecations(t *testing.T) {
	assert := assert.New(t)

	// Test legacy flag mappings
	args := []string{
		"--cookie-secret=legacy-secret",
		"--cookie-secure=true",
		"--client-id=legacy-client-id",
		"--client-secret=legacy-client-secret",
		"--prompt=consent",
		"--cookie-domains=one.com,two.com",
	}

	// Capture stdout to verify deprecation messages
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cfg, err := NewConfig(args)
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	require.NoError(t, err)
	assert.Contains(output, "cookie-secret config option is deprecated")
	assert.Contains(output, "cookie-secure config option is deprecated")
	assert.Contains(output, "prompt config option is deprecated")
	assert.Contains(output, "cookie-domains config option is deprecated")

	// Verify legacy options were transformed correctly
	assert.Equal("legacy-secret", cfg.SecretString)
	assert.False(cfg.InsecureCookie)
	assert.Equal("legacy-client-id", cfg.Providers.Google.ClientID)
	assert.Equal("legacy-client-secret", cfg.Providers.Google.ClientSecret)
	assert.Equal("consent", cfg.Providers.Google.Prompt)
	assert.Len(cfg.CookieDomains, 2)
}

func TestConfigProviderResolution(t *testing.T) {
	assert := assert.New(t)

	cfg := &Config{
		DefaultProvider: "google",
		Rules: map[string]*Rule{
			"oidc-rule": {
				Provider: "oidc",
			},
		},
	}

	// Known configured providers
	pGoogle, err := cfg.GetConfiguredProvider("google")
	assert.NoError(err)
	assert.Equal("google", pGoogle.Name())

	pOIDC, err := cfg.GetConfiguredProvider("oidc")
	assert.NoError(err)
	assert.Equal("oidc", pOIDC.Name())

	// Unconfigured provider (generic-oauth is valid type but not in rules or default)
	_, err = cfg.GetConfiguredProvider("generic-oauth")
	assert.Error(err)
	assert.Contains(err.Error(), "Unconfigured provider")

	// Completely unknown provider
	_, err = cfg.GetConfiguredProvider("saml2")
	assert.Error(err)
	assert.Contains(err.Error(), "Unconfigured provider")

	_, err = cfg.GetProvider("non-existent")
	assert.Error(err)
	assert.Contains(err.Error(), "Unknown provider")
}

func TestConfigRuleValidation(t *testing.T) {
	assert := assert.New(t)

	cfg := newDefaultConfig()

	// Invalid action
	rInvalidAction := &Rule{
		Action:   "bypass",
		Rule:     "Path(`/`)",
		Provider: "google",
	}
	err := rInvalidAction.Validate(cfg)
	assert.Error(err)
	assert.Contains(err.Error(), "invalid rule action")

	// Host formattedRule replaces Host( with HostRegexp(
	rHost := &Rule{
		Action:   "auth",
		Rule:     "Host(`example.com`)",
		Provider: "google",
	}
	assert.Equal("HostRegexp(`example.com`)", rHost.formattedRule())
}

func TestConfigParseFlagsErrors(t *testing.T) {
	assert := assert.New(t)

	// Missing route name
	_, err := NewConfig([]string{"--rule..action=allow"})
	assert.Error(err)
	assert.Contains(err.Error(), "route name is required")

	// Missing route param value
	_, err = NewConfig([]string{"--rule.test.action="})
	assert.Error(err)
	assert.Contains(err.Error(), "route param value is required")

	// Invalid unquote syntax
	_, err = NewConfig([]string{"--rule.test.rule=\"unclosed quote"})
	assert.Error(err)

	// Unknown flag
	_, err = NewConfig([]string{"--some-completely-unknown-flag=value"})
	assert.Error(err)
	assert.Contains(err.Error(), "unknown flag")

	// Invalid port
	_, err = NewConfig([]string{"--port=not-a-port"})
	assert.Error(err)

	// Invalid rule param
	_, err = NewConfig([]string{"--rule.test.badparam=value"})
	assert.Error(err)
	assert.Contains(err.Error(), "invalid route param")

	// Invalid legacy cookie-secure boolean
	_, err = NewConfig([]string{"--cookie-secure=not-a-bool"})
	assert.Error(err)
}

func TestConfigConvertLegacyToIni(t *testing.T) {
	assert := assert.New(t)

	tmpFile, err := ioutil.TempFile("", "tfa-legacy-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("secret mysecret\ncookie-domain test.com\n")
	require.NoError(t, err)
	tmpFile.Close()

	reader, err := convertLegacyToIni(tmpFile.Name())
	assert.NoError(err)

	content, err := ioutil.ReadAll(reader)
	assert.NoError(err)
	assert.Contains(string(content), "secret=mysecret")
	assert.Contains(string(content), "cookie-domain=test.com")
}
