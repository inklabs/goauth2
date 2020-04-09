package goauth2test

import (
	"fmt"
)

type seededTokenGenerator struct {
	codes []string
	index int
}

func NewSeededTokenGenerator(codes ...string) *seededTokenGenerator {
	return &seededTokenGenerator{codes: codes}
}

func (s *seededTokenGenerator) New() (string, error) {
	if len(s.codes) == 0 || len(s.codes) <= s.index {
		return "", fmt.Errorf("token not found")
	}

	index := s.index
	s.index++
	return s.codes[index], nil
}
