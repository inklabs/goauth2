package goauth2_test

import (
	"github.com/inklabs/rangedb/provider/inmemorystore"
	"github.com/inklabs/rangedb/provider/jsonrecordserializer"

	"github.com/inklabs/goauth2"
	"github.com/inklabs/goauth2/pkg/bdd"
)

func goauth2TestCase(options ...goauth2.Option) *bdd.TestCase {
	serializer := jsonrecordserializer.New()
	goauth2.BindEvents(serializer)
	eventStore := inmemorystore.New(inmemorystore.WithSerializer(serializer))

	return bdd.New(eventStore, func(command bdd.Command) {
		options = append([]goauth2.Option{goauth2.WithStore(eventStore)}, options...)
		app := goauth2.New(options...)
		app.Dispatch(command)
	})
}
