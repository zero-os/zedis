//Package jwt provides JWT helper functions for authenticating a connection
package jwt

import (
	"bytes"
	"crypto"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/karlseguin/ccache"
)

const (
	iyoPublicKeyStr = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAES5X8XrfKdx9gYayFITc89wad4usrk0n2
7MjiGYvqalizeSWTHEpnd7oea9IQ8T5oJjMVH5cc0H5tFSKilFFeh//wngxIyny6
6+Vq5t5B0V0Ehy01+2ceEon2Y0XDkIKv
-----END PUBLIC KEY-----
`

	// number of entries we want to keep in the LRU cache
	// rough estimation size of jwtCacheVal is 150 bytes
	// if our jwtCacheSize = 1024, it takes : 150 * 1024 bytes = 153 kilobytes
	jwtCacheSize = 2 << 11 // 4096
)

var (
	jwtCache     *ccache.Cache
	iyoPublicKey crypto.PublicKey
)

type jwtCacheVal struct {
	err    error
	scopes []string
}

func init() {
	var err error
	iyoPublicKey, err = jwtgo.ParseECPublicKeyFromPEM([]byte(iyoPublicKeyStr))
	if err != nil {
		log.Errorf("failed to parse pub key:%v", err)
		os.Exit(1)
	}

	conf := ccache.Configure()
	conf.MaxSize(jwtCacheSize)
	jwtCache = ccache.New(conf)
}

// SetJWTPublicKey configure the public key used to verify JWT token
func SetJWTPublicKey(key string) error {
	var err error
	iyoPublicKey, err = jwtgo.ParseECPublicKeyFromPEM([]byte(key))
	if err != nil {
		return err
	}
	return nil
}

// ValidatePermission checks if the token has set permission
// getExpectedScopes is optional, if nil it will check if the JWT has a scope within zedis namespace
// if not nil it will check if JWT has a scope returned from getExpectedScopes
func ValidatePermission(jwtStr, organization, namespace string, getExpectedScopes GetScopes) error {
	var scopes []string
	var inCache bool
	var exp int64
	var err error
	var hasValidScope bool

	scopes, inCache, err = getScopesFromCache(jwtStr)
	if err != nil {
		// invalid cached token
		return err
	}

	if !inCache {
		scopes, err = getScopes(jwtStr)
		if err != nil {
			cacheVal := jwtCacheVal{
				err: err,
			}
			jwtCache.Set(jwtStr, cacheVal, 24*time.Hour)
			return err
		}
	}

	if getExpectedScopes == nil {
		hasValidScope = checkInNamespace(organization, namespace, scopes)
	} else {
		hasValidScope = checkPermissions(getExpectedScopes(organization, namespace), scopes)
	}

	if !hasValidScope {
		err = fmt.Errorf("JWT does not contain a scope Zedis requires")
		cacheVal := jwtCacheVal{
			err: err,
		}
		jwtCache.Set(jwtStr, cacheVal, 24*time.Hour)
		return err
	}

	if !inCache {
		exp, err = checkJWTExpiration(jwtStr)
		if err != nil {
			cacheVal := jwtCacheVal{
				err: err,
			}
			jwtCache.Set(jwtStr, cacheVal, 24*time.Hour)
			return err
		}

		cacheVal := jwtCacheVal{
			scopes: scopes,
		}
		jwtCache.Set(jwtStr, cacheVal, time.Until(time.Unix(exp, 0)))
	}

	return nil
}

// GetScopes defines a function that fetches scopes
type GetScopes func(string, string) []string

// ReadScopes returns the required reading scopes to read from Zedis
func ReadScopes(organization, namespace string) []string {
	return []string{
		organization + "." + namespace,
		organization + "." + namespace + ".read",
	}
}

// WriteScopes returns the required writing scopes to write to Zedis
func WriteScopes(organization, namespace string) []string {
	return []string{
		organization + "." + namespace,
		organization + "." + namespace + ".write",
	}
}

// AdminScopes returns the required admin scopes for Zedis
func AdminScopes(organization, namespace string) []string {
	return []string{
		organization + "." + namespace,
	}
}

// get scopes from the cache
func getScopesFromCache(jwtStr string) ([]string, bool, error) {
	exists := false
	item := jwtCache.Get(jwtStr)
	if item == nil {
		return nil, exists, nil
	}
	exists = true

	// check validity
	cacheVal := item.Value().(jwtCacheVal)
	if cacheVal.err != nil {
		return nil, exists, cacheVal.err
	}

	// check cache expiration
	if item.Expired() {
		// check JWT expired
		exp, err := checkJWTExpiration(jwtStr)
		if err != nil {
			return nil, exists, err
		}
		// falsely expired in cache, set back into cache
		jwtCache.Set(jwtStr, cacheVal, time.Until(time.Unix(exp, 0)))
	}

	return cacheVal.scopes, exists, nil
}

func checkJWTExpiration(jwtStr string) (int64, error) {
	token, err := jwtgo.Parse(jwtStr, func(token *jwtgo.Token) (interface{}, error) {
		if token.Method != jwtgo.SigningMethodES384 {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return iyoPublicKey, nil
	})

	if err != nil {
		return 0, err
	}

	claims, ok := token.Claims.(jwtgo.MapClaims)
	if !(ok && token.Valid) {
		return 0, fmt.Errorf("invalid JWT token")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return 0, fmt.Errorf("invalid expiration claims in token")
	}
	exp := int64(expFloat)
	if time.Until(time.Unix(exp, 0)).Seconds() <= 0 {
		return 0, fmt.Errorf("expired JWT token")
	}

	return exp, nil
}

func getScopes(jwtStr string) ([]string, error) {
	token, err := jwtgo.Parse(jwtStr, func(token *jwtgo.Token) (interface{}, error) {
		if token.Method != jwtgo.SigningMethodES384 {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return iyoPublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwtgo.MapClaims)
	if !(ok && token.Valid) {
		return nil, fmt.Errorf("invalid JWT token")
	}

	var scopes []string
	for _, v := range claims["scope"].([]interface{}) {
		scopes = append(scopes, v.(string))
	}

	return scopes, nil
}

// CheckPermissions checks whether user has needed scopes
func checkPermissions(expectedScopes, userScopes []string) bool {
	for _, scope := range userScopes {
		scope = removeScopePrefix(scope)
		for _, expected := range expectedScopes {
			if scope == expected {
				return true
			}
		}
	}
	return false
}

// checkInNamespace checks if one of the scopes is in the right org
func checkInNamespace(organization, namespace string, scopes []string) bool {
	for _, scope := range scopes {
		scope = removeScopePrefix(scope)
		if strings.HasPrefix(scope, organization+"."+namespace) {
			return true
		}
	}
	return false
}

// removes the `user:memberof:` scope tag
func removeScopePrefix(scope string) string {
	prefix := []byte("user:memberof:")
	bScope := []byte(scope)
	if !bytes.HasPrefix(bScope, prefix) {
		return scope
	}

	return string(bScope[len(prefix):])
}
