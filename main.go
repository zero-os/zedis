package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/zero-os/zedis/config"
	"github.com/zero-os/zedis/server"
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetOutput(os.Stdout)

	cfg, err := config.NewZedisConfigFromFile("config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = server.ListenAndServeRedis(cfg)
	if err != nil {
		log.Fatal(err)
	}
}
