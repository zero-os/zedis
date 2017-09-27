package server

import (
	log "github.com/Sirupsen/logrus"
	"github.com/tidwall/redcon"
	"github.com/zero-os/zedis/server/jwt"
)

var (
	permissionValidator = jwt.ValidatePermission
	unAuthMsg           = "ERR no authentication token found for this connection"
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

	err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace, nil)
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
			conn.WriteError(unAuthMsg)
			return
		}
		err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace, jwt.WriteScopes)
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
			conn.WriteError(unAuthMsg)
			return
		}
		err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace, jwt.ReadScopes)
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

func exists(conn redcon.Conn, cmd redcon.Command) {
	log.Debugf("received EXISTS request from %s", conn.RemoteAddr())
	if len(cmd.Args) < 2 {
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
			conn.WriteError(unAuthMsg)
			return
		}
		err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace, jwt.ReadScopes)
		if err != nil {
			conn.WriteError("ERR JWT invalid: " + err.Error())
			return
		}
	}

	keysFound := 0
	for _, key := range cmd.Args[1:] {
		found, err := storClient.KeyExists(key)
		if err != nil {
			log.Errorf("checking if data exists in the store went wrong: %s", err)
		}
		if found {
			keysFound++
		}
	}

	conn.WriteInt(keysFound)
}

func unknown(conn redcon.Conn, cmd redcon.Command) {
	log.Debugf("received unknown command %s from %s", string(cmd.Args[0]), conn.RemoteAddr())
	conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
}
