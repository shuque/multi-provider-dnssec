package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"

	kitlog "github.com/go-kit/kit/log"
	"github.com/miekg/dns"
)

const (
	zoneName = "example.test."
)

type Key struct {
	Flags     uint16 `json:"flags"`
	Algorithm uint8  `json:"algorithm"`
	Protocol  uint8  `json:"protocol"`
	PublicKey string `json:"public_key"`
}

type Config struct {
	Zone string `json:"zone"`
	Keys []Key  `json:"keys"`
}

func main() {
	var (
		log     kitlog.Logger = kitlog.NewLogfmtLogger(os.Stdout)
		listen  string
		keyfile string
		dnskeys string
		updater string
	)

	flag.StringVar(&listen, "listen", ":8080", "HTTP interface")
	flag.StringVar(&keyfile, "zsks", "zsk.key", "Public keys used by the service")
	flag.StringVar(&dnskeys, "dnskeys", "dnskeys.db", "DNSKEY key file")
	flag.StringVar(&updater, "update_script", "./update.sh", "Script to run on key update")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, req *http.Request) {
		log.Log("msg", "request", "uri", req.RequestURI, "method", req.Method)

		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		file, err := os.Open(keyfile)
		if err != nil {
			http.Error(w, "failed to load keys", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		config := Config{
			Zone: zoneName,
			Keys: nil,
		}

		for tok := range dns.ParseZone(file, zoneName, "") {
			if tok.Error != nil {
				http.Error(w, "failed to parse keys", http.StatusInternalServerError)
				return
			}

			key, err := keyConfig(tok.RR)
			if err != nil {
				http.Error(w, "failed to parse keys", http.StatusInternalServerError)
				return
			}

			config.Keys = append(config.Keys, *key)
		}

		body, err := json.MarshalIndent(&config, "", "  ")
		if err != nil {
			http.Error(w, "failed to serialize response", http.StatusInternalServerError)
			return
		}

		w.Write(body)
	})

	mux.HandleFunc("/dnskey", func(w http.ResponseWriter, req *http.Request) {
		log.Log("msg", "request", "uri", req.RequestURI, "method", req.Method)

		//		if req.Method == http.MethodGet {
		//			fmt.Fprintf(w, `{}`)
		//			return
		//		}

		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		raw, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "failed to read request", http.StatusInternalServerError)
			return
		}

		if err := ioutil.WriteFile(dnskeys, raw, 0660); err != nil {
			http.Error(w, "failed to write new keys", http.StatusInternalServerError)
			return
		}

		cmd := exec.Command(updater)
		if err := cmd.Run(); err != nil {
			http.Error(w, "failed to update zone", http.StatusInternalServerError)
			return
		}
	})

	log.Log("msg", "starting")
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Log("msg", "failed to listen", "err", err)
		os.Exit(1)
	}
}

func keyConfig(rr dns.RR) (*Key, error) {
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("invalid record type")
	}

	return &Key{
		Flags:     dnskey.Flags,
		Algorithm: dnskey.Algorithm,
		Protocol:  dnskey.Protocol,
		PublicKey: dnskey.PublicKey,
	}, nil
}
