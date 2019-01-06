package log

import (
	l "log"
	"os"
)

// TODO replace this package

// Debugf logs if env DEBUG exist
func Debugf(format string, args ...interface{}) {
	if _, exist := os.LookupEnv("DEBUG"); exist {
		l.Printf(format+"\n", args...)
	}
}

func InfofN(format string, args ...interface{}) {
	l.Printf(format, args...)
}

func Infof(format string, args ...interface{}) {
	l.Printf(format+"\n", args...)
}

func Printf(format string, args ...interface{}) {
	l.Printf(format+"\n", args...)
}

func Fatalf(format string, args ...interface{}) {
	l.Fatalf(format, args...)
}
