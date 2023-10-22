package utils

type ErrFn func() error

func UntilFirstError(fns ...ErrFn) error {
	for _, fn := range fns {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

func UntilErrorPointer(err *error, fns ...func()) error {
	for i := range fns {
		fns[i]()
		if *err != nil {
			return *err
		}
	}
	return nil
}
