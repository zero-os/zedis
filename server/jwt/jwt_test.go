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
	log.SetLevel(log.DebugLevel)
	b, err := ioutil.ReadFile("./devcert/jwt_pub.pem")
	if err != nil {
		log.Error(err)
		os.Exit(2)
	}
	SetJWTPublicKey(string(b))
}

func TestJWT(t *testing.T) {
	// init data
	assert := assert.New(t)

	writeToken := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	adminToken := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)
	expiredToken := getToken(t, -24, itsyouonline.Permission{Write: true}, org, namespace)
	invalidOrgtoken := getToken(t, 24, itsyouonline.Permission{Write: true}, "not"+org, namespace)

	// test valid permission
	err := ValidatePermission(writeToken, org, namespace)
	assert.NoError(err)
	// test again to test cached restult
	err = ValidatePermission(writeToken, org, namespace)
	assert.NoError(err)
	err = ValidatePermission(adminToken, org, namespace)
	assert.NoError(err)

	// test expired token
	err = ValidatePermission(expiredToken, org, namespace)
	assert.Error(err)
	log.Error(err)
	// test expired token in cache
	err = ValidatePermission(expiredToken, org, namespace)
	assert.Error(err)

	// test token without zedis scopes
	err = ValidatePermission(invalidOrgtoken, org, namespace)
	assert.Error(err)
	log.Error(err)
}

func TestStillValidWithScopes(t *testing.T) {
	assert := assert.New(t)
	writeToken := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	readToken := getToken(t, 24, itsyouonline.Permission{Read: true}, org, namespace)
	adminToken := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)

	// test if write token is valid
	err := StillValidWithScopes(writeToken, WriteScopes(org, namespace))
	assert.NoError(err)

	// test if read token is valid
	err = StillValidWithScopes(readToken, ReadScopes(org, namespace))
	assert.NoError(err)

	// test if write token with read scopes
	err = StillValidWithScopes(writeToken, ReadScopes(org, namespace))
	//assert.Error(err)
	log.Error(err)

	// check if admin token has read and write rights
	err = StillValidWithScopes(adminToken, ReadScopes(org, namespace))
	assert.NoError(err, "admin should have read access")
	err = StillValidWithScopes(adminToken, WriteScopes(org, namespace))
	assert.NoError(err, "admin should have write access")

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
