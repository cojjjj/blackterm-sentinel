package config

import (
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Workers int
	Timeout time.Duration
	Rate    int
	Ports   []uint16
	DBPath  string
}

func DefaultDBPath() string {
	if custom := os.Getenv("SENTINEL_DB"); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "sentinel.db"
	}
	return filepath.Join(home, ".sentinel", "sentinel.db")
}

func DefaultPorts() []uint16 {
	return []uint16{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443,
		445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375,
		3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
		8888, 9200, 27017,
	}
}

func Default() Config {
	return Config{
		Workers: 128,
		Timeout: 650 * time.Millisecond,
		Rate:    400,
		Ports:   DefaultPorts(),
		DBPath:  DefaultDBPath(),
	}
}
