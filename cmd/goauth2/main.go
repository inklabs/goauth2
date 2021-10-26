package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/inklabs/rangedb"
	"github.com/inklabs/rangedb/pkg/rangedbapi"
	"github.com/inklabs/rangedb/pkg/rangedbui"
	"github.com/inklabs/rangedb/provider/inmemorystore"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/web"
)

func main() {
	fmt.Println("OAuth2 Server")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	port := flag.Int("port", 8080, "port")

	store := inmemorystore.New(
		inmemorystore.WithLogger(log.New(os.Stderr, "", 0)),
	)
	goauth2App, err := goauth2.New(goauth2.WithStore(store))
	if err != nil {
		log.Fatal(err)
	}

	webApp, err := web.New(
		web.WithGoauth2App(goauth2App),
	)
	if err != nil {
		log.Fatal(err)
	}

	err = initDB(goauth2App, store)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		rangeDBPort := 8081
		baseUri := fmt.Sprintf("http://0.0.0.0:%d/api", rangeDBPort)
		api, err := rangedbapi.New(rangedbapi.WithStore(store), rangedbapi.WithBaseUri(baseUri))
		if err != nil {
			log.Fatal(err)
		}

		ui := rangedbui.New(api.AggregateTypeStatsProjection(), store)

		server := http.NewServeMux()
		server.Handle("/", ui)
		server.Handle("/api/", http.StripPrefix("/api", api))

		fmt.Printf("RangeDB UI: http://0.0.0.0:%d/\n", rangeDBPort)
		log.Fatal(http.ListenAndServe(":8081", server))
	}()

	fmt.Printf("Go OAuth2 Server: http://0.0.0.0:%d/\n", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), webApp))
}

func initDB(goauth2App *goauth2.App, store rangedb.Store) error {
	const (
		userID   = "445a57a41b7b43e285b51e99bba10a79"
		email    = "john@example.com"
		password = "Pass123"
	)

	goauth2App.Dispatch(goauth2.OnBoardUser{
		UserID:   userID,
		Username: email,
		Password: password,
	})

	ctx := context.Background()
	_, err := store.Save(ctx, &rangedb.EventRecord{
		Event: goauth2.UserWasGrantedAdministratorRole{
			UserID:         userID,
			GrantingUserID: userID,
		},
		Metadata: map[string]string{
			"message": "epoch event",
		},
	})
	if err != nil {
		return err
	}

	goauth2App.Dispatch(goauth2.AuthorizeUserToOnBoardClientApplications{
		UserID:            userID,
		AuthorizingUserID: userID,
	})

	goauth2App.Dispatch(goauth2.OnBoardClientApplication{
		ClientID:     "8895e1e5f06644ebb41c26ea5740b246",
		ClientSecret: "c1e847aef925467290b4302e64f3de4e",
		RedirectURI:  "https://example.com/oauth2/callback",
		UserID:       userID,
	})

	fmt.Println("Example commands to test grant flows:")
	fmt.Println("# Client Credentials")
	fmt.Println(`curl localhost:8080/token \
        -u 8895e1e5f06644ebb41c26ea5740b246:c1e847aef925467290b4302e64f3de4e \
        -d "grant_type=client_credentials" \
        -d "scope=read_write" -s | jq`)

	fmt.Println("# Resource Owner Password Credentials")
	fmt.Println(`curl localhost:8080/token \
        -u 8895e1e5f06644ebb41c26ea5740b246:c1e847aef925467290b4302e64f3de4e \
        -d "grant_type=password" \
        -d "username=john@example.com" \
        -d "password=Pass123" \
        -d "scope=read_write" -s | jq`)

	fmt.Println("# Refresh Token")
	fmt.Println(`curl localhost:8080/token \
        -u 8895e1e5f06644ebb41c26ea5740b246:c1e847aef925467290b4302e64f3de4e \
        -d "grant_type=refresh_token" \
        -d "refresh_token=3cc6fa5b470642b081e3ebd29aa9b43c" -s | jq`)

	fmt.Println("# Refresh Token x2")
	fmt.Println(`curl localhost:8080/token \
        -u 8895e1e5f06644ebb41c26ea5740b246:c1e847aef925467290b4302e64f3de4e \
        -d "grant_type=refresh_token" \
        -d "refresh_token=93b5e8869a954faaa6c6ba73dfea1a09" -s | jq`)

	fmt.Println("# Authorization Code")
	fmt.Println(`http://0.0.0.0:8080/login?client_id=8895e1e5f06644ebb41c26ea5740b246&redirect_uri=https://example.com/oauth2/callback&response_type=code&state=somestate&scope=read_write`)
	fmt.Println("user: john@example.com")
	fmt.Println("pass: Pass123")

	fmt.Println("# Authorization Code Token")
	fmt.Println(`curl localhost:8080/token \
        -u 8895e1e5f06644ebb41c26ea5740b246:c1e847aef925467290b4302e64f3de4e \
        -d "grant_type=authorization_code" \
        -d "code=3cc6fa5b470642b081e3ebd29aa9b43c" \
        -d "redirect_uri=https://example.com/oauth2/callback" -s | jq`)

	fmt.Println("\n# Implicit")
	fmt.Println(`http://0.0.0.0:8080/login?client_id=8895e1e5f06644ebb41c26ea5740b246&redirect_uri=https://example.com/oauth2/callback&response_type=token&state=somestate&scope=read_write`)
	fmt.Println("user: john@example.com")
	fmt.Println("pass: Pass123")

	return nil
}
