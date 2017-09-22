package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthParse(t *testing.T) {
	// setup
	assert := assert.New(t)
	zc := Zedis{
		AuthCommandsInput: "set,get, select",
	}

	parseAuthCommands(&zc)

	_, ok := zc.AuthCommands["SET"]
	assert.True(ok, "SET should be present in the list")
	_, ok = zc.AuthCommands["GET"]
	assert.True(ok, "GET should be present in the list")
	_, ok = zc.AuthCommands["SELECT"]
	assert.True(ok, "SELECT should be present in the list")
}
