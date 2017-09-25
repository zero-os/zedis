package server

import (
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/chrisvdg/redcon"
	"github.com/zero-os/zedis/config"
	"github.com/zero-os/zedis/stor"
)

var (
	zConfig    *config.Zedis
	storClient stor.Client

	// saves the jwt for a connection
	connsJWT     map[redcon.Conn]string
	connsJWTLock *sync.Mutex
)

// ListenAndServeRedis runs the redis server
func ListenAndServeRedis(cfg *config.Zedis) error {
	zConfig = cfg
	var err error
	storClient, err = stor.NewStor(zConfig.StorPolicy())
	if err != nil {
		return err
	}

	connsJWT = make(map[redcon.Conn]string)
	connsJWTLock = &sync.Mutex{}

	var errChannel chan error

	// serve Redis over plain TCP
	if zConfig.Port != "" {
		go func() {
			log.Infof("Redis plain TCP interface listening at localhost%s", zConfig.Port)
			defer log.Info("Redis plain TCP interface closed")

			errChannel <- redcon.ListenAndServe(zConfig.Port, handler, accept, closed)
		}()
	}

	go func() {
		// serve Redis over TCP with TLS
		tlsCfg, err := tlsConfig(zConfig)
		if err != nil {
			errChannel <- err
			return
		}

		log.Infof("Redis TLS interface listening at localhost%s", zConfig.TLSPort)
		defer log.Info("Redis TLS interface closed")

		errChannel <- redcon.ListenAndServeTLS(zConfig.TLSPort, handler, accept, closed, tlsCfg)
	}()

	// return if context is done or error
	// TODO: (gracefully) close still running servers (https://github.com/zero-os/zedis/issues/1)
	select {
	case err = <-errChannel:
		return err
	}
}

// redcon plain tcp handler func
func handler(conn redcon.Conn, cmd redcon.Command) {
	switch strings.ToLower(string(cmd.Args[0])) {
	case "ping":
		ping(conn)
	case "quit":
		quit(conn)
	case "auth":
		auth(conn, cmd)
	case "set":
		set(conn, cmd)
	case "get":
		get(conn, cmd)
	case "exists":
		exists(conn, cmd)
	default:
		unknown(conn, cmd)
	}
}

// redcon accept func
func accept(conn redcon.Conn) bool {
	log.Debugf("Received connection from %s", conn.RemoteAddr())
	return true
}

// redcon closed func
func closed(conn redcon.Conn, err error) {
	connsJWTLock.Lock()
	defer connsJWTLock.Unlock()
	delete(connsJWT, conn)
}
