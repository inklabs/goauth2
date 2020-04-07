package goauth2_test

import (
	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/provider/jsonrecordserializer"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/pkg/bdd"
)

func goauth2TestCase() *bdd.TestCase {
	serializer := jsonrecordserializer.New()
	goauth2.BindEvents(serializer)
	eventStore := inmemorystore.New(inmemorystore.WithSerializer(serializer))
	app := goauth2.New(goauth2.WithStore(eventStore))
	return bdd.New(eventStore, func(command bdd.Command) {
		app.Dispatch(command)
	})
}
