package logger

import (
	"fmt"
	"os"
)

const (
	colorReset   = "\033[0m"
	colorBlue    = "\033[94m"
	colorGreen   = "\033[92m"
	colorYellow  = "\033[93m"
	colorRed     = "\033[91m"
	colorCyan    = "\033[96m"
	colorMagenta = "\033[95m"
)

var (
	Silent    bool
	NoColor   bool
	DebugMode bool
)

func color(c, s string) string {
	if NoColor {
		return s
	}
	return c + s + colorReset
}

func Info(msg string) {
	if Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", color(colorBlue, "[INF]"), msg)
}

func Success(msg string) {
	if Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", color(colorGreen, "[SUC]"), msg)
}

func Warning(msg string) {
	if Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", color(colorYellow, "[WRN]"), msg)
}

func Error(msg string) {
	if Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", color(colorRed, "[ERR]"), msg)
}

func Fatal(msg string) {
	fmt.Fprintf(os.Stderr, "%s %s\n", color(colorRed, "[FTL]"), msg)
	os.Exit(1)
}

func Infof(format string, args ...any) {
	Info(fmt.Sprintf(format, args...))
}

func Successf(format string, args ...any) {
	Success(fmt.Sprintf(format, args...))
}

func Warningf(format string, args ...any) {
	Warning(fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
	Error(fmt.Sprintf(format, args...))
}

func Fatalf(format string, args ...any) {
	Fatal(fmt.Sprintf(format, args...))
}

// Debug prints a [DBG] line to stderr.
// It is NOT suppressed by Silent — debug takes precedence over silent for visibility.
func Debug(msg string) {
	if !DebugMode {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", color(colorMagenta, "[DBG]"), msg)
}

func Debugf(format string, args ...any) {
	Debug(fmt.Sprintf(format, args...))
}
