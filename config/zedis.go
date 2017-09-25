//Package config provides types and functions to manage the config for Zedis
package config

import (
	"io/ioutil"
	"strings"

	valid "github.com/asaskevich/govalidator"
	"github.com/zero-os/0-stor/client"
	"gopkg.in/yaml.v2"
)

// list of all commands that could need authentication
var allAUTHCommands = []string{
	"GET",
	"SET",
}

// NewZedisConfigFromFile returns a full zedis config from a given YAML file
func NewZedisConfigFromFile(filePath string) (*Zedis, error) {
	zc := new(Zedis)

	bs, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(bs, zc)
	if err != nil {
		return nil, err
	}
	_, err = valid.ValidateStruct(zc)
	if err != nil {
		return nil, err
	}

	// parse authenticated commands
	parseAuthCommands(zc)

	return zc, nil
}

// Zedis represents a full zedis config
type Zedis struct {
	// Port of the Redis interface
	Port string `yaml:"port"`
	//TLS protected port of the Redis interface
	TLSPort string `yaml:"tls_port" valid:"required"`

	// Defines the commands that require authentication
	AuthCommandsInput string `yaml:"auth_commands"`
	// Parsed AuthCommandsInput into a map of commands that require authentication
	AuthCommands map[string]struct{} `yaml:"-"`

	// JWT authentication
	JWTOrganization string `yaml:"jwt_organization" valid:"required"`
	JWTNamespace    string `yaml:"jwt_namespace" valid:"required"`

	// ACME (let's encrypt) TLS proxy
	// defines if caddy should be used
	ACME bool `yaml:"acme"`
	// path of caddy config file
	ACMEWhitelist []string `yaml:"acme_whitelist"`

	// 0-stor specific

	// ItsYouOnline organization of the namespace used
	Organization string `yaml:"organization" valid:"required"`
	// Namespace label
	Namespace string `yaml:"namespace" valid:"required"`

	// ItsYouOnline oauth2 application ID
	IYOAppID string `yaml:"iyo_app_id" valid:"required"`
	// ItsYouOnline oauth2 application secret
	IYOSecret string `yaml:"iyo_app_secret" valid:"required"`

	// Addresses to the 0-stor used to store date
	DataShards []string `yaml:"data_shards" valid:"required"`
	// Addresses of the etcd cluster
	MetaShards []string `yaml:"meta_shards" valid:"required"`

	// If the data written to the store is bigger then BlockSize, the data is splitted into
	// blocks of size BlockSize
	// set to 0 to never split data
	BlockSize int `yaml:"block_size"`

	// Number of replication to create when writting
	ReplicationNr int `yaml:"replication_nr"`
	// if data size is smaller than ReplicationMaxSize then data
	// will be replicated ReplicationNr time
	// if data is bigger, distribution will be used if configured
	ReplicationMaxSize int `yaml:"replication_max_size"`

	// Number of data block to create during distribution
	DistributionNr int `yaml:"distribution_data"`
	// Number of parity block to create during distribution
	DistributionRedundancy int `yaml:"distribution_parity"`

	// Enable compression
	Compress bool `yaml:"compress"`
	// Enable ecryption, if true EncryptKey need to be set
	Encrypt bool `yaml:"encrypt"`
	// Key used during encryption
	EncryptKey string `yaml:"encrypt_key"`
}

// StorPolicy returns 0-Stor policy from Zedis config
func (zc *Zedis) StorPolicy() client.Policy {
	policy := client.Policy{
		Organization:           zc.Organization,
		Namespace:              zc.Namespace,
		IYOAppID:               zc.IYOAppID,
		IYOSecret:              zc.IYOSecret,
		DataShards:             zc.DataShards,
		MetaShards:             zc.MetaShards,
		BlockSize:              zc.BlockSize,
		ReplicationNr:          zc.ReplicationNr,
		ReplicationMaxSize:     zc.ReplicationMaxSize,
		DistributionNr:         zc.DistributionNr,
		DistributionRedundancy: zc.DistributionRedundancy,
		Compress:               zc.Compress,
		Encrypt:                zc.Encrypt,
		EncryptKey:             zc.EncryptKey,
	}

	return policy
}

func parseAuthCommands(zc *Zedis) {
	zc.AuthCommands = make(map[string]struct{})
	// default
	if zc.AuthCommandsInput == "" {
		zc.AuthCommands["SET"] = struct{}{}
		return
	}

	authList := strings.Split(zc.AuthCommandsInput, ",")

	// if no authentication required
	if strings.ToLower(authList[0]) == "none" {
		return
	}

	// if all supported commands need authentication
	if strings.ToLower(authList[0]) == "all" {
		for _, a := range allAUTHCommands {
			zc.AuthCommands[a] = struct{}{}
		}
		return
	}

	for _, a := range authList {
		a = strings.TrimSpace(a)
		a = strings.ToUpper(a)
		zc.AuthCommands[a] = struct{}{}
	}
}
