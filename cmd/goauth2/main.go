package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"text/template"

	"github.com/gorilla/securecookie"
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

	requestedOauth2Port := flag.Uint("port", 0, "port")
	templatesPath := flag.String("templates", "", "optional templates path")
	csrfAuthKey := flag.String("csrfAuthKey", string(securecookie.GenerateRandomKey(32)), "csrf authentication key")
	sessionAuthKey := flag.String("sessionAuthKey", string(securecookie.GenerateRandomKey(64)), "cookie session auth key (64 bytes)")
	sessionEncryptionKey := flag.String("sessionEncryptionKey", string(securecookie.GenerateRandomKey(32)), "cookie session encryption key (32 bytes)")
	flag.Parse()

	oAuth2Listener, err := getListener(*requestedOauth2Port)
	if err != nil {
		log.Fatal(err)
	}

	store := inmemorystore.New(
		inmemorystore.WithLogger(log.New(os.Stderr, "", 0)),
	)
	goAuth2App, err := goauth2.New(goauth2.WithStore(store))
	if err != nil {
		log.Fatal(err)
	}

	goAuth2WebAppOptions := []web.Option{
		web.WithGoAuth2App(goAuth2App),
		web.WithHost(oAuth2Listener.Addr().String()),
		web.WithCSRFAuthKey([]byte(*csrfAuthKey)),
		web.WithSessionKey([]byte(*sessionAuthKey), []byte(*sessionEncryptionKey)),
	}

	if *templatesPath != "" {
		if _, err := os.Stat(*templatesPath); os.IsNotExist(err) {
			log.Fatalf("templates path does not exist: %v", err)
		}

		templatesFS := os.DirFS(*templatesPath + "/..")

		goAuth2WebAppOptions = append(goAuth2WebAppOptions, web.WithTemplateFS(templatesFS))
	}

	goAuth2webApp, err := web.New(goAuth2WebAppOptions...)
	if err != nil {
		log.Fatal(err)
	}

	err = initDB(goAuth2App, store, oAuth2Listener.Addr().String())
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		rangeDBListener, err := getListener(0)
		rangeDBPort := rangeDBListener.Addr().(*net.TCPAddr).Port

		rangeDBAPIUri := url.URL{
			Scheme: "http",
			Host:   rangeDBListener.Addr().String(),
			Path:   "/api",
		}

		api, err := rangedbapi.New(rangedbapi.WithStore(store), rangedbapi.WithBaseUri(rangeDBAPIUri.String()))
		if err != nil {
			log.Fatal(err)
		}

		ui := rangedbui.New(
			api.AggregateTypeStatsProjection(),
			store,
			rangedbui.WithHost(rangeDBListener.Addr().String()))

		server := http.NewServeMux()
		server.Handle("/", ui)
		server.Handle("/api/", http.StripPrefix("/api", api))

		fmt.Printf("RangeDB UI: http://0.0.0.0:%d/\n", rangeDBPort)
		log.Fatal(http.Serve(rangeDBListener, server))
	}()

	goAuth2Port := oAuth2Listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Go OAuth2 Server:\n")
	fmt.Printf("   http://0.0.0.0:%d/login\n", goAuth2Port)
	fmt.Printf("   http://0.0.0.0:%d/list-client-applications\n", goAuth2Port)
	fmt.Printf("   http://0.0.0.0:%d/list-users\n", goAuth2Port)
	log.Fatal(http.Serve(oAuth2Listener, goAuth2webApp))
}

func getListener(port uint) (net.Listener, error) {
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	return listener, nil
}

func initDB(goauth2App *goauth2.App, store rangedb.Store, goAuth2Host string) error {
	const (
		email        = "john@example.com"
		password     = "Pass123"
		userID2      = "03e16d6469bc4d07b4d0c832380e20ce"
		email2       = "jane@example.com"
		password2    = "Pass123"
		clientID     = "8895e1e5f06644ebb41c26ea5740b246"
		clientSecret = "c1e847aef925467290b4302e64f3de4e"
	)

	userID := web.AdminUserIDTODO

	ctx := context.Background()
	_, err := store.Save(ctx,
		&rangedb.EventRecord{
			Event: goauth2.UserWasOnBoarded{
				UserID:         userID,
				Username:       email,
				PasswordHash:   goauth2.GeneratePasswordHash(password),
				GrantingUserID: userID,
			},
			Metadata: map[string]string{
				"message": "epoch event",
			},
		},
		&rangedb.EventRecord{
			Event: goauth2.UserWasGrantedAdministratorRole{
				UserID:         userID,
				GrantingUserID: userID,
			},
			Metadata: map[string]string{
				"message": "epoch event",
			},
		},
	)
	if err != nil {
		return err
	}

	goauth2App.Dispatch(goauth2.OnBoardUser{
		UserID:         userID2,
		Username:       email2,
		Password:       password2,
		GrantingUserID: userID,
	})

	goauth2App.Dispatch(goauth2.AuthorizeUserToOnBoardClientApplications{
		UserID:            userID,
		AuthorizingUserID: userID,
	})

	goauth2App.Dispatch(goauth2.OnBoardClientApplication{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  "https://example.com/oauth2/callback",
		UserID:       userID,
	})

	tmpl, err := template.New("docTemplate").Parse(`
Example commands to test grant flows:

# Client Credentials
curl {{.Host}}/token \
  -u {{.ClientID}}:{{.ClientSecret}} \
  -d "grant_type=client_credentials" \
  -d "scope=read_write" -s | jq

# Resource Owner Password Credentials
curl {{.Host}}/token \
  -u {{.ClientID}}:{{.ClientSecret}} \
  -d "grant_type=password" \
  -d "username=john@example.com" \
  -d "password=Pass123" \
  -d "scope=read_write" -s | jq

# Refresh Token
curl {{.Host}}/token \
  -u {{.ClientID}}:{{.ClientSecret}} \
  -d "grant_type=refresh_token" \
  -d "refresh_token=3cc6fa5b470642b081e3ebd29aa9b43c" \
  -d "scope=read_write" -s | jq

# Refresh Token x2
curl {{.Host}}/token \
  -u {{.ClientID}}:{{.ClientSecret}} \
  -d "grant_type=refresh_token" \
  -d "refresh_token=93b5e8869a954faaa6c6ba73dfea1a09" \
  -d "scope=read_write" -s | jq

# Authorization Code
http://{{.Host}}/login?client_id=8895e1e5f06644ebb41c26ea5740b246&redirect_uri=https://example.com/oauth2/callback&response_type=code&state=somestate&scope=read_write
  user: john@example.com
  pass: Pass123

# Authorization Code Token
curl {{.Host}}/token \
  -u {{.ClientID}}:{{.ClientSecret}} \
  -d "grant_type=authorization_code" \
  -d "code=3cc6fa5b470642b081e3ebd29aa9b43c" \
  -d "redirect_uri=https://example.com/oauth2/callback" -s | jq

# Implicit
http://{{.Host}}/login?client_id=8895e1e5f06644ebb41c26ea5740b246&redirect_uri=https://example.com/oauth2/callback&response_type=token&state=somestate&scope=read_write
  user: john@example.com
  pass: Pass123

`)
	if err != nil {
		return err
	}

	return tmpl.Execute(os.Stdout, struct {
		Host         string
		ClientSecret string
		ClientID     string
	}{
		Host:         goAuth2Host,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
}
