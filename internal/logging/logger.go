// Package logging provides a structured logging system for NetFlowMap.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	// defaultLogger is the global logger instance
	defaultLogger *slog.Logger
	loggerMu      sync.RWMutex
)

func init() {
	// Initialize with default info level logger
	defaultLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Level represents a logging level.
type Level string

const (
	LevelTrace   Level = "trace"   // Very verbose logging
	LevelDebug   Level = "debug"
	LevelInfo    Level = "info"
	LevelWarning Level = "warning"
	LevelError   Level = "error"
)

// slog doesn't have a native trace level, so we define one below debug
const slogLevelTrace = slog.LevelDebug - 4

// ParseLevel converts a string to a Level.
// Returns LevelInfo if the string is not recognized.
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warning", "warn":
		return LevelWarning
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// toSlogLevel converts a Level to slog.Level.
func (l Level) toSlogLevel() slog.Level {
	switch l {
	case LevelTrace:
		return slogLevelTrace
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarning:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// String returns the string representation of the level.
func (l Level) String() string {
	return string(l)
}

// Options configures the logger.
type Options struct {
	// Level is the minimum log level to output
	Level Level
	// Output is where logs are written (default: os.Stdout)
	Output io.Writer
	// AddSource adds source file information to log entries
	AddSource bool
}

// Setup initializes the global logger with the given options.
func Setup(opts Options) {
	loggerMu.Lock()
	defer loggerMu.Unlock()

	output := opts.Output
	if output == nil {
		output = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     opts.Level.toSlogLevel(),
		AddSource: opts.AddSource,
	}

	defaultLogger = slog.New(slog.NewTextHandler(output, handlerOpts))
}

// SetupFromConfig initializes the logger from a log level string.
// This is a convenience function for use with the config package.
func SetupFromConfig(level string) {
	Setup(Options{
		Level:  ParseLevel(level),
		Output: os.Stdout,
	})
}

// Logger returns the global logger instance.
func Logger() *slog.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return defaultLogger
}

// Trace logs a trace message (very verbose).
func Trace(msg string, args ...any) {
	Logger().Log(context.Background(), slogLevelTrace, msg, args...)
}

// Debug logs a debug message.
func Debug(msg string, args ...any) {
	Logger().Debug(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...any) {
	Logger().Info(msg, args...)
}

// Warning logs a warning message.
func Warning(msg string, args ...any) {
	Logger().Warn(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...any) {
	Logger().Error(msg, args...)
}

// Tracef logs a formatted trace message (very verbose).
func Tracef(format string, args ...any) {
	Logger().Log(context.Background(), slogLevelTrace, fmt.Sprintf(format, args...))
}

// Debugf logs a formatted debug message.
func Debugf(format string, args ...any) {
	Logger().Debug(fmt.Sprintf(format, args...))
}

// Infof logs a formatted info message.
func Infof(format string, args ...any) {
	Logger().Info(fmt.Sprintf(format, args...))
}

// Warningf logs a formatted warning message.
func Warningf(format string, args ...any) {
	Logger().Warn(fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message.
func Errorf(format string, args ...any) {
	Logger().Error(fmt.Sprintf(format, args...))
}

// With returns a logger with the given attributes.
func With(args ...any) *slog.Logger {
	return Logger().With(args...)
}

// WithComponent returns a logger with a component attribute.
// This is useful for identifying which part of the application generated the log.
func WithComponent(component string) *slog.Logger {
	return Logger().With("component", component)
}

// ContextLogger stores a logger in a context.
type contextKey struct{}

// WithContext returns a new context with the given logger.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// FromContext retrieves the logger from the context.
// Returns the default logger if none is found in the context.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(contextKey{}).(*slog.Logger); ok {
		return logger
	}
	return Logger()
}


