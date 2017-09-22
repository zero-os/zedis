package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/zero-os/zedis/cmd"
	"github.com/zero-os/zedis/config"
	"github.com/zero-os/zedis/server"
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetOutput(os.Stdout)

	if err := cmd.RootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	if cmd.Verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Zedis is set to verbose")
	}

	cfg, err := config.NewZedisConfigFromFile(cmd.CfgFile)
	if err != nil {
		log.Fatal(err)
	}

	err = server.ListenAndServeRedis(cfg)
	if err != nil {
		log.Fatal(err)
	}
}
