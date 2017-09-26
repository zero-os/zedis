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

func TestValidatePermission(t *testing.T) {
	// init data
	assert := assert.New(t)

	writeToken := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	adminToken := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)
	expiredToken := getToken(t, -24, itsyouonline.Permission{Write: true}, org, namespace)
	invalidOrgtoken := getToken(t, 24, itsyouonline.Permission{Write: true}, "not"+org, namespace)

	// test valid permission
	err := ValidatePermission(writeToken, org, namespace, nil)
	assert.NoError(err)
	// test again to test cached restult
	err = ValidatePermission(writeToken, org, namespace, nil)
	assert.NoError(err)
	err = ValidatePermission(adminToken, org, namespace, nil)
	assert.NoError(err)

	// test expired token
	err = ValidatePermission(expiredToken, org, namespace, nil)
	assert.Error(err)
	log.Errorf("expected error: %v", err)
	// test expired token in cache
	err = ValidatePermission(expiredToken, org, namespace, nil)
	assert.Error(err)

	// test token without zedis scopes
	err = ValidatePermission(invalidOrgtoken, org, namespace, nil)
	assert.Error(err)
	log.Errorf("expected error: %v", err)
}

func TestValidatePermissionWithScopes(t *testing.T) {
	assert := assert.New(t)
	writeToken := getToken(t, 24, itsyouonline.Permission{Write: true}, org, namespace)
	readToken := getToken(t, 24, itsyouonline.Permission{Read: true}, org, namespace)
	adminToken := getToken(t, 24, itsyouonline.Permission{Admin: true}, org, namespace)

	// test if write token is valid
	err := ValidatePermission(writeToken, org, namespace, WriteScopes)
	assert.NoError(err)

	// test if read token is valid
	err = ValidatePermission(readToken, org, namespace, ReadScopes)
	assert.NoError(err)

	// test write token with read scopes
	err = ValidatePermission(writeToken, org, namespace, ReadScopes)
	assert.Error(err)
	log.Errorf("expected error: %v", err)

	// check if admin token has read and write rights
	err = ValidatePermission(adminToken, org, namespace, ReadScopes)
	assert.NoError(err, "admin should have read access")
	err = ValidatePermission(adminToken, org, namespace, WriteScopes)
	assert.NoError(err, "admin should have write access")
}

func TestRemoveScopePrefix(t *testing.T) {
	assert := assert.New(t)

	scope := org + "." + namespace
	withPrefix := "user:memberof:" + scope

	resScope := removeScopePrefix(scope)
	assert.Equal(scope, resScope)

	resScopePrefix := removeScopePrefix(withPrefix)
	assert.Equal(scope, resScopePrefix)
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
