package uuidtoken

import (
	"github.com/inklabs/rangedb/pkg/shortuuid"
)

type uuidTokenGenerator struct{}

// NewGenerator constructs a new uuidTokenGenerator.
func NewGenerator() *uuidTokenGenerator {
	return &uuidTokenGenerator{}
}

func (u *uuidTokenGenerator) New() string {
	return shortuuid.New().String()
}
