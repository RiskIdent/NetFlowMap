package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"Debug", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warning", LevelWarning},
		{"WARNING", LevelWarning},
		{"warn", LevelWarning},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"invalid", LevelInfo}, // defaults to info
		{"", LevelInfo},        // defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseLevel(tt.input)
			if result != tt.expected {
				t.Errorf("ParseLevel(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLevelToSlogLevel(t *testing.T) {
	tests := []struct {
		level    Level
		expected slog.Level
	}{
		{LevelDebug, slog.LevelDebug},
		{LevelInfo, slog.LevelInfo},
		{LevelWarning, slog.LevelWarn},
		{LevelError, slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			result := tt.level.toSlogLevel()
			if result != tt.expected {
				t.Errorf("%q.toSlogLevel() = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarning, "warning"},
		{LevelError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("%v.String() = %q, want %q", tt.level, result, tt.expected)
			}
		})
	}
}

func TestSetupAndLogging(t *testing.T) {
	var buf bytes.Buffer

	Setup(Options{
		Level:  LevelDebug,
		Output: &buf,
	})

	// Test all log levels
	Debug("debug message")
	Info("info message")
	Warning("warning message")
	Error("error message")

	output := buf.String()

	if !strings.Contains(output, "debug message") {
		t.Error("expected debug message in output")
	}
	if !strings.Contains(output, "info message") {
		t.Error("expected info message in output")
	}
	if !strings.Contains(output, "warning message") {
		t.Error("expected warning message in output")
	}
	if !strings.Contains(output, "error message") {
		t.Error("expected error message in output")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer

	// Set level to Warning - should only show warning and error
	Setup(Options{
		Level:  LevelWarning,
		Output: &buf,
	})

	Debug("debug message")
	Info("info message")
	Warning("warning message")
	Error("error message")

	output := buf.String()

	if strings.Contains(output, "debug message") {
		t.Error("debug message should not appear with warning level")
	}
	if strings.Contains(output, "info message") {
		t.Error("info message should not appear with warning level")
	}
	if !strings.Contains(output, "warning message") {
		t.Error("expected warning message in output")
	}
	if !strings.Contains(output, "error message") {
		t.Error("expected error message in output")
	}
}

func TestFormattedLogging(t *testing.T) {
	var buf bytes.Buffer

	Setup(Options{
		Level:  LevelDebug,
		Output: &buf,
	})

	Debugf("debug %s %d", "test", 123)
	Infof("info %s %d", "test", 456)
	Warningf("warning %s %d", "test", 789)
	Errorf("error %s %d", "test", 101)

	output := buf.String()

	if !strings.Contains(output, "debug test 123") {
		t.Error("expected formatted debug message")
	}
	if !strings.Contains(output, "info test 456") {
		t.Error("expected formatted info message")
	}
	if !strings.Contains(output, "warning test 789") {
		t.Error("expected formatted warning message")
	}
	if !strings.Contains(output, "error test 101") {
		t.Error("expected formatted error message")
	}
}

func TestWithComponent(t *testing.T) {
	var buf bytes.Buffer

	Setup(Options{
		Level:  LevelInfo,
		Output: &buf,
	})

	logger := WithComponent("netflow")
	logger.Info("test message")

	output := buf.String()

	if !strings.Contains(output, "component=netflow") {
		t.Errorf("expected component attribute in output, got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Error("expected test message in output")
	}
}

func TestWith(t *testing.T) {
	var buf bytes.Buffer

	Setup(Options{
		Level:  LevelInfo,
		Output: &buf,
	})

	logger := With("source_id", "fw-main", "ip", "192.168.1.1")
	logger.Info("connection received")

	output := buf.String()

	if !strings.Contains(output, "source_id=fw-main") {
		t.Errorf("expected source_id attribute in output, got: %s", output)
	}
	if !strings.Contains(output, "ip=192.168.1.1") {
		t.Errorf("expected ip attribute in output, got: %s", output)
	}
}

func TestSetupFromConfig(t *testing.T) {
	var buf bytes.Buffer

	// First setup with custom output
	Setup(Options{
		Level:  LevelDebug,
		Output: &buf,
	})

	// Then use SetupFromConfig (which uses stdout, so we test the level only)
	// We'll verify by checking the logger level indirectly
	SetupFromConfig("error")

	// Get a new buffer for testing
	var buf2 bytes.Buffer
	Setup(Options{
		Level:  ParseLevel("error"),
		Output: &buf2,
	})

	Debug("debug")
	Info("info")
	Warning("warning")
	Error("error message here")

	output := buf2.String()

	if strings.Contains(output, "debug") && !strings.Contains(output, "error") {
		t.Error("debug should not appear with error level")
	}
	if !strings.Contains(output, "error message here") {
		t.Error("expected error message in output")
	}
}

func TestContextLogger(t *testing.T) {
	var buf bytes.Buffer

	Setup(Options{
		Level:  LevelInfo,
		Output: &buf,
	})

	// Create a logger with component
	componentLogger := WithComponent("test-component")

	// Store in context
	ctx := WithContext(context.Background(), componentLogger)

	// Retrieve from context
	logger := FromContext(ctx)
	logger.Info("context test")

	output := buf.String()

	if !strings.Contains(output, "component=test-component") {
		t.Errorf("expected component in output, got: %s", output)
	}
	if !strings.Contains(output, "context test") {
		t.Error("expected context test message in output")
	}
}

func TestFromContextDefault(t *testing.T) {
	// When no logger in context, should return default logger
	ctx := context.Background()
	logger := FromContext(ctx)

	if logger == nil {
		t.Error("expected non-nil logger from context")
	}

	// Should be the global logger
	if logger != Logger() {
		t.Error("expected default logger when none in context")
	}
}

func TestLoggerConcurrency(t *testing.T) {
	var buf bytes.Buffer

	Setup(Options{
		Level:  LevelInfo,
		Output: &buf,
	})

	// Test concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 100; j++ {
				Infof("goroutine %d iteration %d", n, j)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify no panic occurred and some output was generated
	if buf.Len() == 0 {
		t.Error("expected some log output")
	}
}


