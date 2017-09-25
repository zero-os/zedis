package server

import (
	log "github.com/Sirupsen/logrus"
	"github.com/chrisvdg/redcon"
	"github.com/zero-os/zedis/server/jwt"
)

var (
	permissionValidator  = jwt.ValidatePermission
	stillValidWithScopes = jwt.StillValidWithScopes
)

func ping(conn redcon.Conn) {
	log.Debugf("received PING request from %s", conn.RemoteAddr())
	conn.WriteString("PONG")
}

func quit(conn redcon.Conn) {
	log.Debugf("received QUIT request from %s", conn.RemoteAddr())
	conn.WriteString("OK")
	conn.Close()
}

func auth(conn redcon.Conn, cmd redcon.Command) {
	log.Debugf("received AUTH request from %s", conn.RemoteAddr())
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	jwtStr := string(cmd.Args[1])

	err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace)
	if err != nil {
		conn.WriteError("ERR invalid JWT: " + err.Error())
		return
	}

	connsJWTLock.Lock()
	connsJWT[conn] = jwtStr
	connsJWTLock.Unlock()

	conn.WriteString("OK")
}

func set(conn redcon.Conn, cmd redcon.Command) {
	log.Debugf("received SET request from %s", conn.RemoteAddr())
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	// check authentication
	_, authorize := zConfig.AuthCommands[string(cmd.Args[0])]
	if authorize {
		connsJWTLock.Lock()
		jwtStr, ok := connsJWT[conn]
		connsJWTLock.Unlock()
		if !ok {
			conn.WriteError("ERR no authentication token found for this connection")
			return
		}
		err := stillValidWithScopes(jwtStr, jwt.WriteScopes(zConfig.JWTOrganization, zConfig.JWTNamespace))
		if err != nil {
			conn.WriteError("ERR JWT invalid: " + err.Error())
			return
		}
	}
	storClient.Write(cmd.Args[1], cmd.Args[2])

	conn.WriteString("OK")
}

func get(conn redcon.Conn, cmd redcon.Command) {
	log.Debugf("received GET request from %s", conn.RemoteAddr())
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	// check authentication
	_, authorize := zConfig.AuthCommands[string(cmd.Args[0])]
	if authorize {
		connsJWTLock.Lock()
		jwtStr, ok := connsJWT[conn]
		connsJWTLock.Unlock()
		if !ok {
			conn.WriteError("ERR no authentication token found for this connection")
			return
		}
		err := stillValidWithScopes(jwtStr, jwt.ReadScopes(zConfig.JWTOrganization, zConfig.JWTNamespace))
		if err != nil {
			conn.WriteError("ERR JWT invalid: " + err.Error())
			return
		}
	}

	val, err := storClient.Read(cmd.Args[1])

	if err != nil {
		conn.WriteError("ERR reading from the stor: " + err.Error())
		return
	}

	conn.WriteBulk(val)
}

func unknown(conn redcon.Conn, cmd redcon.Command) {
	log.Debugf("received unknown command %s from %s", string(cmd.Args[0]), conn.RemoteAddr())
	conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
}
