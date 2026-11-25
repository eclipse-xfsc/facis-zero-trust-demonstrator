package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorgateway"
)

func main() {
	path := flag.String("config", "/etc/gateway/gateway.json", "gateway configuration")
	flag.Parse()
	f, err := os.Open(*path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg connectorgateway.Config
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	err = dec.Decode(&cfg)
	_ = f.Close()
	if err != nil {
		log.Fatal(err)
	}
	att, err := cfg.Attestation()
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	enc := json.NewEncoder(os.Stdout)
	var mu sync.Mutex
	g, err := connectorgateway.Start(ctx, cfg, att, func(e connectorgateway.Event) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(e); err != nil {
			log.Print("cannot record channel decision")
			stop()
		}
	})
	if err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
	_ = g.Close()
}
