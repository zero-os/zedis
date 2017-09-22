package jwt

import (
	"crypto"
	"io/ioutil"
	"os"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/zero-os/0-stor/client/itsyouonline"
)

const (
	org       = "zedisorg"
	namespace = "zedisnamespace"
)

var (
	token string
)

func init() {
	b, err := ioutil.ReadFile("./devcert/jwt_pub.pem")
	if err != nil {
		os.Exit(2)
	}
	SetJWTPublicKey(string(b))
}

func TestJWT(t *testing.T) {
	// init data
	assert := assert.New(t)

	writeToken := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	adminToken := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)
	readToken := getToken(t, 24, itsyouonline.Permission{Read: true}, org, namespace)
	expiredToken := getToken(t, -24, itsyouonline.Permission{Write: true}, org, namespace)

	// test valid permission
	err := ValidatePermission(writeToken, org, namespace)
	assert.NoError(err)
	// test again to test cached restult
	err = ValidatePermission(writeToken, org, namespace)
	assert.NoError(err)
	err = ValidatePermission(adminToken, org, namespace)
	assert.NoError(err)

	// test invalid permission
	err = ValidatePermission(readToken, org, namespace)
	assert.Error(err)
	log.Error(err)
	// test invalid token in cache
	err = ValidatePermission(readToken, org, namespace)
	assert.Error(err)

	// test expired token
	err = ValidatePermission(expiredToken, org, namespace)
	assert.Error(err)
	log.Error(err)
	// test expired token in cache
	err = ValidatePermission(expiredToken, org, namespace)
	assert.Error(err)
}

func TestStillValid(t *testing.T) {
	assert := assert.New(t)
	validToken1 := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	validToken2 := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)
	expiredToken := getToken(t, -24, itsyouonline.Permission{Write: true}, org, namespace)

	//cache token1
	err := ValidatePermission(validToken1, org, namespace)
	assert.NoError(err)

	// check if cached token is still valid
	err = StillValid(validToken1)
	assert.NoError(err)

	// test valid non cached token
	err = StillValid(validToken2)
	assert.NoError(err)

	// test non cached expired token
	err = StillValid(expiredToken)
	assert.Error(err)
	log.Error(err)
}

func getToken(t *testing.T, hoursValid time.Duration, perm itsyouonline.Permission, org, namespace string) string {
	b, err := ioutil.ReadFile("./devcert/jwt_key.pem")
	assert.NoError(t, err)

	key, err := jwtgo.ParseECPrivateKeyFromPEM(b)
	assert.NoError(t, err)

	token, err = createJWT(hoursValid, org, namespace, perm, key)
	if err != nil {
		t.Fatal("failed to create iyo token:" + err.Error())
	}

	return token
}

// CreateJWT generate a JWT that can be used for testing
func createJWT(hoursValid time.Duration, organization, namespace string, perm itsyouonline.Permission, jwtSingingKey crypto.PrivateKey) (string, error) {
	claims := jwtgo.MapClaims{
		"exp":   time.Now().Add(time.Hour * hoursValid).Unix(),
		"scope": perm.Scopes(organization, namespace),
	}

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodES384, claims)
	return token.SignedString(jwtSingingKey)
}
