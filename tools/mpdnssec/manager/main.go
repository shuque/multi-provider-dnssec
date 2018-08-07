package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/miekg/dns"
)

type Key struct {
	Flags     int    `json:"flags"`
	Algorithm int    `json:"algorithm"`
	Protocol  int    `json:"protocol"`
	PublicKey string `json:"public_key"`
}

type Config struct {
	Zone string `json:"zone"`
	Keys []Key  `json:"keys"`
}

type Provider struct {
	URL string
}

func (p *Provider) GetKeys() ([]Key, error) {
	resp, err := http.Get(fmt.Sprintf("%s/keys", p.URL))
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	config := Config{}
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}

	return config.Keys, nil
}

func (p *Provider) PushKeys(dnskey []dns.RR, rrsig dns.RRSIG) error {
	buf := bytes.Buffer{}
	for _, key := range dnskey {
		fmt.Fprintf(&buf, "%s\n", key.String())
	}
	fmt.Fprintf(&buf, "%s\n", rrsig.String())

	body := bytes.NewReader(buf.Bytes())
	_, err := http.Post(fmt.Sprintf("%s/dnskey", p.URL), "text/plain", body)
	return err
}

func main() {
	var (
		log kitlog.Logger = kitlog.NewLogfmtLogger(os.Stdout)
	)

	ksk := dns.DNSKEY{}
	ksk.Hdr.Name = "example.test."
	ksk.Hdr.Class = dns.ClassINET
	ksk.Hdr.Rrtype = dns.TypeDNSKEY
	ksk.Hdr.Ttl = 1200
	ksk.Algorithm = 13
	ksk.Flags = 257
	ksk.Protocol = 3
	_privateKey, err := ksk.Generate(256)
	if err != nil {
		panic(err)
	}

	privateKey := _privateKey.(*ecdsa.PrivateKey)

	providers := []Provider{}
	for _, url := range os.Args[1:] {
		providers = append(providers, Provider{url})
	}

	keyset := map[string][]Key{}

	for _ = range time.Tick(10 * time.Second) {
		log.Log("msg", "fetching keys from providers")
		for _, provider := range providers {
			keys, err := provider.GetKeys()
			if err != nil {
				log.Log("msg", "failed to fetch key", "provider", provider, "err", err)
				continue
			}

			keyset[provider.URL] = keys
		}

		dnskeys := []dns.RR{}
		dnskeys = append(dnskeys, &ksk)

		for _, keys := range keyset {
			for _, key := range keys {
				dnskey := dns.DNSKEY{}
				dnskey.Hdr.Name = "example.test."
				dnskey.Hdr.Class = dns.ClassINET
				dnskey.Hdr.Rrtype = dns.TypeDNSKEY
				dnskey.Hdr.Ttl = 1200

				dnskey.Algorithm = uint8(key.Algorithm)
				dnskey.Flags = uint16(key.Flags)
				dnskey.Protocol = uint8(key.Protocol)
				dnskey.PublicKey = key.PublicKey

				dnskeys = append(dnskeys, &dnskey)
			}

		}

		now := time.Now().Unix()

		rrsig := dns.RRSIG{}
		rrsig.Hdr.Name = "example.test."
		rrsig.Hdr.Class = dns.ClassINET
		rrsig.Hdr.Rrtype = dns.TypeRRSIG
		rrsig.Hdr.Ttl = 1200
		rrsig.Inception = uint32(now - 60)
		rrsig.Expiration = uint32(now + 3600)
		rrsig.KeyTag = ksk.KeyTag()
		rrsig.SignerName = ksk.Hdr.Name
		rrsig.Algorithm = ksk.Algorithm

		err := rrsig.Sign(privateKey, dnskeys)
		if err != nil {
			log.Log("msg", "failed to sign DNSKEY", "err", err)
			continue
		}

		log.Log("msg", "updating DNSKEYs and signatures")
		for _, provider := range providers {
			err := provider.PushKeys(dnskeys, rrsig)
			if err != nil {
				log.Log("msg", "failed to push updated keys", "err", err)
			}
		}
	}
}
