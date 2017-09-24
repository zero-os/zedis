package main

import (
	"flag"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/zero-os/zedis/config"
	"github.com/zero-os/zedis/server"
)

var (
	verbose *bool
	cfgFile *string
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetOutput(os.Stdout)

	parseFlags()

	if *verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Zedis is set to verbose")
	}

	cfg, err := config.NewZedisConfigFromFile(*cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	err = server.ListenAndServeRedis(cfg)
	if err != nil {
		log.Fatal(err)
	}
}

func parseFlags() {
	verbose = flag.Bool("v", false, "Set verbose output")
	cfgFile = flag.String("cfg", "./config.yaml", "Path of config file")
	flag.Parse()
}
