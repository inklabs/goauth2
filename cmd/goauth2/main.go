package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/inklabs/rangedb/pkg/rangedbapi"
	"github.com/inklabs/rangedb/pkg/rangedbui"
	"github.com/inklabs/rangedb/pkg/rangedbui/pkg/templatemanager/provider/memorytemplate"
	"github.com/inklabs/rangedb/provider/inmemorystore"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/web"
)

func main() {
	fmt.Println("OAuth2 Server")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	port := flag.Int("port", 8080, "port")

	store := inmemorystore.New()
	webApp := web.New(
		web.WithGoauth2App(goauth2.New(goauth2.WithStore(store))),
	)

	go func() {
		rangedbPort := 8081
		baseUri := fmt.Sprintf("http://0.0.0.0:%d/api", rangedbPort)
		templateManager, _ := memorytemplate.New(rangedbui.GetTemplates())
		api := rangedbapi.New(rangedbapi.WithStore(store), rangedbapi.WithBaseUri(baseUri))
		ui := rangedbui.New(templateManager, api.AggregateTypeStatsProjection(), store)

		server := http.NewServeMux()
		server.Handle("/", ui)
		server.Handle("/api/", http.StripPrefix("/api", api))

		fmt.Printf("RangeDB UI: http://0.0.0.0:%d/\n", rangedbPort)
		log.Fatal(http.ListenAndServe(":8081", server))
	}()

	fmt.Printf("Go OAuth2 Server: http://0.0.0.0:%d/\n", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), webApp))
}
