package log

import (
	l "log"
)

func Debugf(format string, args ...interface{}) {
	l.Printf(format+"\n", args...)
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
