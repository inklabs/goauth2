package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/inklabs/goauth2/web"
)

func main() {
	fmt.Println("OAuth2 Server")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	port := flag.Int("port", 8080, "port")

	app := web.New()

	fmt.Printf("Listening: http://0.0.0.0:%d/\n", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), app))
}
