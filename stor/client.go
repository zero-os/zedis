package stor

import (
	"errors"

	log "github.com/Sirupsen/logrus"
	"github.com/zero-os/0-stor/client"
)

// package Errors
var (
	ErrNilStorClient = errors.New("Stor client was nil")
)

// Client defines the 0-stor client
type Client interface {
	Close()
	Read(key []byte) ([]byte, error)
	Write(key []byte, value []byte) error
}

// StorClient implementation
type storClient struct {
	policy client.Policy
	client *client.Client
}

// NewStor creates a new store connection
func NewStor(policy client.Policy) (Client, error) {
	sc := new(storClient)
	sc.policy = policy

	cl, err := client.New(policy)
	if err != nil {
		return nil, err
	}
	sc.client = cl
	return sc, nil
}

// Close closes the stor
func (sc *storClient) Close() {
	if sc != nil {
		sc.client.Close()
	}
}

// Read reads from the stor
func (sc *storClient) Read(key []byte) ([]byte, error) {
	log.Debug("Reading from 0-stor...")
	defer log.Debug("Done reading from the 0-stor")
	val, _, err := sc.client.Read(key)
	return val, err
}

// Write writes to the stor
func (sc *storClient) Write(key []byte, value []byte) error {
	log.Debug("Writing to 0-stor...")
	defer log.Debug("Done writing to the 0-stor")
	_, err := sc.client.Write(key, value, nil)
	return err
}
