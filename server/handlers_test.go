package server

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/chrisvdg/redcon"
	"github.com/stretchr/testify/assert"
	"github.com/zero-os/zedis/config"
)

func init() {
	connsJWT = make(map[redcon.Conn]string)
	connsJWTLock = &sync.Mutex{}
	zConfig = new(config.Zedis)
	zConfig.AuthCommands = make(map[string]struct{})
	zConfig.AuthCommands["SET"] = struct{}{}

}

func TestPing(t *testing.T) {
	conn := new(stubConn)
	ping(conn)
	assert.Equal(t, "PONG", conn.s)

}

func TestQuit(t *testing.T) {
	conn := new(stubConn)
	quit(conn)
	assert.Equal(t, "OK", conn.s)
	assert.True(t, conn.closed)
}

func TestAuth(t *testing.T) {
	permissionValidator = stubAuthValidator

	conn := new(stubConn)
	var cmd redcon.Command

	// valid args
	cmd.Args = [][]byte{
		[]byte("AUTH"),
		[]byte("jwtString"),
	}

	auth(conn, cmd)
	assert.Equal(t, "OK", conn.s)

	// in case permission would fail
	permissionValidator = stubAuthValidatorErr
	cmd.Args = [][]byte{
		[]byte("AUTH"),
		[]byte("jwtString"),
	}

	auth(conn, cmd)
	assert.Equal(t, "ERR invalid JWT: a stub error", conn.s)

	// invalid command length
	cmd.Args = [][]byte{
		[]byte("AUTH"),
		[]byte("hello"),
		[]byte("world"),
	}

	auth(conn, cmd)
	assert.Equal(t, "ERR wrong number of arguments for 'AUTH' command", conn.s)

}

func TestSet(t *testing.T) {
	stillValidWithScopes = stubStillValidWithScopes
	stubStorClient := newStubStorClient()
	storClient = stubStorClient
	conn := new(stubConn)
	var cmd redcon.Command

	// missing jwt
	cmd.Args = [][]byte{
		[]byte("SET"),
		[]byte("key"),
		[]byte("value"),
	}

	set(conn, cmd)
	assert.Equal(t, "ERR no authentication token found for this connection", conn.s)

	// valid args and jwt present
	connsJWT[conn] = "aJWT"
	cmd.Args = [][]byte{
		[]byte("SET"),
		[]byte("key"),
		[]byte("value"),
	}

	set(conn, cmd)
	assert.Equal(t, "OK", conn.s)
	assert.Equal(t, []byte("value"), stubStorClient.stor["key"])

	// invalid jwt
	stillValidWithScopes = stubStillValidWithScopesErr
	cmd.Args = [][]byte{
		[]byte("SET"),
		[]byte("key"),
		[]byte("value"),
	}

	set(conn, cmd)
	assert.Equal(t, "ERR JWT invalid: a stub error", conn.s)

	// invalid command length
	permissionValidator = stubAuthValidatorErr
	cmd.Args = [][]byte{
		[]byte("SET"),
		[]byte("key"),
	}

	set(conn, cmd)
	assert.Equal(t, "ERR wrong number of arguments for 'SET' command", conn.s)
}

func TestGet(t *testing.T) {
	storClient = newStubStorClient()
	storClient.Write([]byte("hello"), []byte("world"))
	conn := new(stubConn)
	var cmd redcon.Command

	// valid command args
	cmd.Args = [][]byte{
		[]byte("GET"),
		[]byte("hello"),
	}

	get(conn, cmd)
	assert.Equal(t, "world", conn.s)

	// invalid command length
	cmd.Args = [][]byte{
		[]byte("GET"),
		[]byte("hello"),
		[]byte("world"),
	}

	get(conn, cmd)
	assert.Equal(t, "ERR wrong number of arguments for 'GET' command", conn.s)
}

func TestUnknown(t *testing.T) {
	var cmd redcon.Command
	cmd.Args = [][]byte{
		[]byte("hello world"),
	}
	conn := new(stubConn)
	unknown(conn, cmd)
	assert.Equal(t, "ERR unknown command 'hello world'", conn.s)
}

// stubs redcon.Conn
type stubConn struct {
	s      string
	ctx    context.Context
	cmds   []redcon.Command
	conn   net.Conn
	closed bool
}

func (c *stubConn) Close() error {
	c.closed = true
	return nil
}
func (c *stubConn) Context() interface{}        { return c.ctx }
func (c *stubConn) SetContext(v interface{})    { c.ctx = v.(context.Context) }
func (c *stubConn) SetReadBuffer(n int)         {}
func (c *stubConn) WriteString(str string)      { c.s = str }
func (c *stubConn) WriteBulk(bulk []byte)       { c.s = string(bulk) }
func (c *stubConn) WriteBulkString(bulk string) { c.s = bulk }
func (c *stubConn) WriteInt(num int)            { c.s = strconv.Itoa(num) }
func (c *stubConn) WriteInt64(num int64)        { c.s = strconv.FormatInt(num, 10) }
func (c *stubConn) WriteError(msg string)       { c.s = msg }
func (c *stubConn) WriteArray(count int)        { c.s = strconv.Itoa(count) }
func (c *stubConn) WriteNull()                  { c.s = "" }
func (c *stubConn) WriteRaw(data []byte)        { c.s = string(data) }
func (c *stubConn) RemoteAddr() string          { return "127.0.0.1" }
func (c *stubConn) ReadPipeline() []redcon.Command {
	cmds := c.cmds
	c.cmds = nil
	return cmds
}
func (c *stubConn) PeekPipeline() []redcon.Command { return c.cmds }
func (c *stubConn) NetConn() net.Conn              { return c.conn }
func (c *stubConn) Detach() redcon.DetachedConn    { return nil }

// stub source client
func newStubStorClient() *stubStorClient {
	c := new(stubStorClient)
	c.stor = make(map[string][]byte)
	return c
}

type stubStorClient struct {
	stor   map[string][]byte
	closed bool
}

func (c *stubStorClient) Close() { c.closed = true }
func (c *stubStorClient) Read(key []byte) ([]byte, error) {
	val, ok := c.stor[string(key)]
	if !ok {
		return nil, errors.New("key was not found")
	}
	return val, nil
}
func (c *stubStorClient) Write(key []byte, value []byte) error {
	c.stor[string(key)] = value
	return nil
}

// stub validator that returns nil (success)
func stubAuthValidator(jwtStr, organization, namespace string) error {
	return nil
}

// stub validator that returns "a stub error" error
func stubAuthValidatorErr(jwtStr, organization, namespace string) error {
	return errors.New("a stub error")
}

// stub still valid validator that returns nil
func stubStillValidWithScopes(jwtStr string, scopes []string) error {
	return nil
}

// stub still valid validator that returns an error
func stubStillValidWithScopesErr(jwtStr string, scopes []string) error {
	return errors.New("a stub error")
}
