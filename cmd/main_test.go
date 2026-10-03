package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCmdBuildAndHelp(t *testing.T) {
	assert := assert.New(t)

	// Build the binary into a temporary location
	cmd := exec.Command("go", "run", "main.go", "--help")
	out, err := cmd.CombinedOutput()
	// --help causes go-flags to exit 0
	require.NoError(t, err, "running --help should exit cleanly: %s", string(out))

	output := string(out)
	assert.Contains(output, "Usage:")
	assert.Contains(output, "--secret")
	assert.Contains(output, "--cookie-domain")
	assert.Contains(output, "--url-path")
	assert.Contains(output, "--default-provider")
}

func TestCmdMissingSecretExitsNonZero(t *testing.T) {
	assert := assert.New(t)

	// Running without required flags should fail
	cmd := exec.Command("go", "run", "main.go")
	out, err := cmd.CombinedOutput()
	assert.Error(err, "running without secret should exit non-zero")
	output := string(out)
	assert.True(strings.Contains(output, "secret") || strings.Contains(output, "exit status"))
}
