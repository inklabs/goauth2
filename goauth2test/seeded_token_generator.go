package goauth2test

type seededTokenGenerator struct {
	codes []string
	index int
}

func NewSeededTokenGenerator(codes ...string) *seededTokenGenerator {
	return &seededTokenGenerator{codes: codes}
}

func (s *seededTokenGenerator) New() string {
	index := s.index
	s.index++
	return s.codes[index]
}
