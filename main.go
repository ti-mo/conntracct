package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"gitlab.com/0ptr/conntracct/pkg/bpf"
)

func main() {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	mod, aec, ael, err := bpf.Init()
	if err != nil {
		log.Fatalln("Error initializing bpf infrastructure:", err)
	}

	go func() {
		for {
			ae, ok := <-aec
			if !ok {
				log.Println("AcctEvent channel closed, exiting read loop")
				break
			}

			fmt.Println(ae)
		}
	}()

	go func() {
		for {
			ae, ok := <-ael
			if !ok {
				log.Println("BPF lost channel closed, exiting read loop")
				break
			}

			fmt.Println("lost", ae)
		}
	}()

	defer func() {
		if err := mod.Close(); err != nil {
			log.Fatalf("Failed to close program: %v", err)
		}
	}()

	<-sig
}
