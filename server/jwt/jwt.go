package jwt

import (
	"crypto"
	"fmt"
	"log"
	"strings"
	"time"

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
	valid  bool
	scopes []string
}

func init() {
	var err error
	iyoPublicKey, err = jwtgo.ParseECPublicKeyFromPEM([]byte(iyoPublicKeyStr))
	if err != nil {
		log.Fatalf("failed to parse pub key:%v", err)
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
func ValidatePermission(jwtStr, organization, namespace string) error {
	var scopes []string
	var inCache bool
	var exp int64
	var err error

	scopes, inCache, err = getScopesFromCache(jwtStr)
	if err != nil {
		// invalid in token
		return err
	}

	if !inCache {
		scopes, exp, err = checkJWTGetScopes(jwtStr)
		if err != nil || time.Until(time.Unix(exp, 0)).Seconds() < 0 {
			// Insert invalid or expired token to cache
			// so we don't need to validate it again
			jwtCache.Set(jwtStr, jwtCacheVal{
				valid: false,
			}, time.Hour*24)

			if err != nil {
				return err
			}
			return fmt.Errorf("expired token")
		}
	}

	expectedScopes := []string{
		organization + "." + namespace,
		organization + "." + namespace + ".write",
	}

	canSet := checkPermissions(expectedScopes, scopes)
	if !canSet {
		cacheVal := jwtCacheVal{
			valid:  false,
			scopes: scopes,
		}
		jwtCache.Set(jwtStr, cacheVal, time.Until(time.Unix(exp, 0)))

		return fmt.Errorf("user does not not have the right scope")
	}

	cacheVal := jwtCacheVal{
		valid:  true,
		scopes: scopes,
	}
	jwtCache.Set(jwtStr, cacheVal, time.Until(time.Unix(exp, 0)))

	return nil
}

// get scopes from the cache
func getScopesFromCache(token string) (scopes []string, exists bool, err error) {
	item := jwtCache.Get(token)
	if item == nil {
		return
	}
	exists = true

	// check validity
	cacheVal := item.Value().(jwtCacheVal)
	if !cacheVal.valid {
		err = fmt.Errorf("invalid token")
		return
	}

	// check cache expiration
	if item.Expired() {
		jwtCache.Delete(token)
		err = fmt.Errorf("expired token")
		return
	}

	scopes = cacheVal.scopes
	return
}

// checkJWTGetScopes checks JWT token and get it's scopes
func checkJWTGetScopes(jwtStr string) ([]string, int64, error) {
	token, err := jwtgo.Parse(jwtStr, func(token *jwtgo.Token) (interface{}, error) {
		if token.Method != jwtgo.SigningMethodES384 {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return iyoPublicKey, nil
	})
	if err != nil {
		return nil, 0, err
	}

	claims, ok := token.Claims.(jwtgo.MapClaims)
	if !(ok && token.Valid) {
		return nil, 0, fmt.Errorf("invalid token")
	}

	var scopes []string
	for _, v := range claims["scope"].([]interface{}) {
		scopes = append(scopes, v.(string))
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, 0, fmt.Errorf("invalid expiration claims in token")
	}
	return scopes, int64(exp), nil
}

// CheckPermissions checks whether user has needed scopes
func checkPermissions(expectedScopes, userScopes []string) bool {
	for _, scope := range userScopes {
		scope = strings.Replace(scope, "user:memberof:", "", 1)
		for _, expected := range expectedScopes {
			if scope == expected {
				return true
			}
		}
	}
	return false
}
