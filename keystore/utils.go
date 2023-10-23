package keystore

const DefaultPermMode = 0o700

func SafeClose(obj Closable) {
	if obj != nil {
		obj.Close()
	}
}
