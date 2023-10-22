package keysstorage

import "errors"

var ErrOutOfBound = errors.New("requested key slice is out of the key's bounds")

type Closable interface {
	Close()
}
