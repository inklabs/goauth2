package goauth2

type TokenGenerator interface {
	New() (string, error)
}
