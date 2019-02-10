package log

import (
	l "log"
	"os"
)

type LOG interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

type Log struct{}

// Debugf logs if env DEBUG exist
func (*Log) Debugf(format string, args ...interface{}) {
	if _, exist := os.LookupEnv("DEBUG"); exist {
		l.Printf(format+"\n", args...)
	}
}

func (*Log) Infof(format string, args ...interface{}) {
	l.Printf(format+"\n", args...)
}

func (*Log) Fatalf(format string, args ...interface{}) {
	l.Fatalf(format, args...)
}
