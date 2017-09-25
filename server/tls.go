package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/zero-os/zedis/config"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// how long self signed certificates are valid
	certLifespan = 3650 * (24 * time.Hour)
	// renewInterval is how often to check the self signed certificates for renewal
	renewInterval = 24 * time.Hour
	// renewDurationBefore is how long before expiration to renew certificates.
	renewDurationBefore = 30 * (24 * time.Hour)
	// selfsigned certificate cache
	certCache *tls.Certificate
	// selfsigned certificate lock
	certCacheLock *sync.Mutex
)

// tlsConfig returns a TLS config from provided Zedis config
func tlsConfig(zc *config.Zedis) (*tls.Config, error) {
	// When ACME (let's encrypt is requested by config)
	if zc.ACME {
		log.Debug("Using ACME (let's encrypt) TLS certificates")
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
		}
		if len(zc.ACMEWhitelist) > 0 {
			m.HostPolicy = autocert.HostWhitelist(zc.ACMEWhitelist...)
		}
		return &tls.Config{
			MinVersion:     tls.VersionTLS11,
			GetCertificate: m.GetCertificate,
		}, nil
	}

	// In memory self signed certificates
	log.Debug("Using self generated TLS certificates")

	cert, err := genCertPair()
	if err != nil {
		return nil, err
	}
	certCacheLock = new(sync.Mutex)
	certCache = cert

	config := &tls.Config{
		MinVersion:     tls.VersionTLS11,
		GetCertificate: getCert,
	}

	go certUpgrader()

	return config, nil
}

func certUpgrader() {
	renewalTicker := time.NewTicker(renewInterval)

	for {
		<-renewalTicker.C
		// if in renew buffer, generate a new one
		certCacheLock.Lock()
		timeLeft := certCache.Leaf.NotAfter.Sub(time.Now())
		if timeLeft < renewDurationBefore {
			cert, err := genCertPair()
			if err != nil {
				log.Errorf("something went wrong generating new self signed certificates: %v", err)
			} else {
				certCache = cert
			}
		}
		certCacheLock.Unlock()
	}
}

func getCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certCacheLock.Lock()
	defer certCacheLock.Unlock()
	return certCache, nil
}

// GenCertPair generates an in memory certificate pair
func genCertPair() (*tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			Organization: []string{"zedis self-signed"},
		},
		NotBefore:             now.Add(-24 * time.Hour), // 1 day ago, in case of clock drift.
		NotAfter:              now.Add(certLifespan),
		SubjectKeyId:          []byte("zedis"),
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return &outCert, nil
}
