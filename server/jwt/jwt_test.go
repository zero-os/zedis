package jwt

import (
	"crypto"
	"io/ioutil"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/zero-os/0-stor/client/itsyouonline"
)

var (
	token string
)

func TestJWT(t *testing.T) {
	// init data
	assert := assert.New(t)
	b, err := ioutil.ReadFile("./devcert/jwt_pub.pem")
	if !assert.NoError(err) {
		return
	}
	org := "zedisorg"
	namespace := "zedisnamespace"
	SetJWTPublicKey(string(b))
	writeToken := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	adminToken := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)
	readToken := getToken(t, 24, itsyouonline.Permission{Read: true}, org, namespace)
	expiredToken := getToken(t, -24, itsyouonline.Permission{Write: true}, org, namespace)

	// test valid permission
	err = ValidatePermission(writeToken, org, namespace)
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
