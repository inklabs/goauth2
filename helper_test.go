package goauth2_test

import (
	"log"
	"time"

	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/rangedbtest/bdd"

	"github.com/inklabs/goauth2"
)

func goauth2TestCase(options ...goauth2.Option) *bdd.TestCase {
	store := inmemorystore.New()
	goauth2.BindEvents(store)
	options = append([]goauth2.Option{goauth2.WithStore(store)}, options...)

	return bdd.New(store, func(command bdd.Command) {
		app, err := goauth2.New(options...)
		if err != nil {
			log.Fatal(err)
		}

		app.Dispatch(command)
		waitForProjections()
	})
}

func waitForProjections() {
	time.Sleep(10 * time.Millisecond)
}
