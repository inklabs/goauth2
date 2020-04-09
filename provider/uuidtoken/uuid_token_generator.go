package uuidtoken

import (
	"github.com/inklabs/rangedb/pkg/shortuuid"
)

type generator struct{}

func NewGenerator() *generator {
	return &generator{}
}

func (u *generator) New() (string, error) {
	return shortuuid.New().String(), nil
}
