package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"gitlab.com/0ptr/conntracct/internal/apiserver"
	"gitlab.com/0ptr/conntracct/internal/config"
	"gitlab.com/0ptr/conntracct/internal/pipeline"
	"gitlab.com/0ptr/conntracct/internal/pprof"
	"gitlab.com/0ptr/conntracct/internal/sinks"
	"gitlab.com/0ptr/conntracct/internal/sinks/influxdb"
)

func main() {

	// Listen on localhost:6060 for pprof sessions.
	pprof.ListenAndServe()

	pipe := pipeline.New()

	// Attach InfluxDB sink.
	idb := influxdb.New()
	if err := idb.Init(sinks.AcctSinkConfig{Addr: "localhost:8089", Name: "ct_influx"}); err != nil {
		log.Fatalln("Error initializing InfluxDB sink:", err)
	}
	if err := pipe.RegisterAcctSink(&idb); err != nil {
		log.Fatalln("Error registering sink:", err)
	}

	// Initialize and start accounting pipeline.
	if err := pipe.Init(); err != nil {
		log.Fatalln("Error initializing pipeline:", err)
	}
	if err := pipe.Start(); err != nil {
		log.Fatalln("Error starting pipeline:", err)
	}

	// Initialize and run the API server.
	apiserver.Init(pipe)
	apiserver.Run(":8000")

	defer func() {
		if err := pipe.Cleanup(); err != nil {
			log.Fatalf("Failure during cleanup: %v", err)
		}
	}()

	if err := config.Init(); err != nil {
		log.Fatalf("Error applying system configuration: %v", err)
	}

	// Wait for program to be interrupted.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	log.Println("Exiting with signal", <-sig)
}
