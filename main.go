package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"gitlab.com/0ptr/conntracct/internal/apiserver"
	"gitlab.com/0ptr/conntracct/internal/pipeline"
	"gitlab.com/0ptr/conntracct/internal/pprof"
	"gitlab.com/0ptr/conntracct/internal/sinks"
	"gitlab.com/0ptr/conntracct/internal/sinks/influxdb"
)

func main() {

	// Listen on localhost:6060 for pprof sessions
	pprof.ListenAndServe()

	// Create pipeline
	pipe := pipeline.New()

	// Attach InfluxDB sink
	idb := influxdb.New()
	if err := idb.Init(sinks.AcctSinkConfig{Addr: "localhost:8089", Name: "le_influx"}); err != nil {
		log.Fatalln("Error initializing InfluxDB sink:", err)
	}

	if err := pipe.RegisterAcctSink(&idb); err != nil {
		log.Fatalln("Error registering sink:", err)
	}

	if err := pipe.RunAcct(); err != nil {
		log.Fatalln("Error initializing pipeline:", err)
	}

	// Initialize and run the API server
	apiserver.Init(pipe)
	apiserver.Run(":8000")

	defer func() {
		if err := pipe.Cleanup(); err != nil {
			log.Fatalf("Failure during cleanup: %v", err)
		}
	}()

	// Wait for program to be interrupted
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	log.Println("Exiting with signal", <-sig)
}
