package server

import (
	"github.com/chrisvdg/redcon"
	"github.com/zero-os/zedis/server/jwt"
)

var (
	permissionValidator = jwt.ValidatePermission
)

func ping(conn redcon.Conn) {
	conn.WriteString("PONG")
}

func quit(conn redcon.Conn) {
	conn.WriteString("OK")
	conn.Close()
}

func auth(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	jwtStr := string(cmd.Args[1])

	err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace)
	if err != nil {
		conn.WriteString("ERR invalid JWT: " + err.Error())
		return
	}

	connsJWTLock.Lock()
	connsJWT[conn] = jwtStr
	connsJWTLock.Unlock()

	conn.WriteString("OK")
}

func set(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 3 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	// check authentication
	connsJWTLock.Lock()
	jwtStr, ok := connsJWT[conn]
	connsJWTLock.Unlock()
	if !ok {
		conn.WriteString("ERR no JWT found for this connection")
		return
	}
	err := permissionValidator(jwtStr, zConfig.JWTOrganization, zConfig.JWTNamespace)
	if err != nil {
		conn.WriteString("ERR JWT invalid: " + err.Error())
		return
	}

	storClient.Write(cmd.Args[1], cmd.Args[2])

	conn.WriteString("OK")
}

func get(conn redcon.Conn, cmd redcon.Command) {
	if len(cmd.Args) != 2 {
		conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
		return
	}

	val, err := storClient.Read(cmd.Args[1])

	if err != nil {
		conn.WriteNull()
		return
	}

	conn.WriteBulk(val)
}

func unknown(conn redcon.Conn, cmd redcon.Command) {
	conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
}
