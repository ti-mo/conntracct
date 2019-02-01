package apiserver

import (
	"fmt"
	"io"
	"log"
)

// write wraps fmt.Fprintf and calls log.Fatal() on error.
func write(w io.Writer, format string, a ...interface{}) {
	if _, err := fmt.Fprintf(w, format, a...); err != nil {
		log.Fatalf("error writing to http stream: %s", err)
	}
}
