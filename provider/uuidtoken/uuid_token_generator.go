package uuidtoken

import (
	"github.com/inklabs/rangedb/pkg/shortuuid"
)

type uuidTokenGenerator struct{}

func NewGenerator() *uuidTokenGenerator {
	return &uuidTokenGenerator{}
}

func (u *uuidTokenGenerator) New() string {
	return shortuuid.New().String()
}
