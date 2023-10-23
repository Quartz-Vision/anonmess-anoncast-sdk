package keystore

const DefaultPermMode = 0o600

func SafeClose(obj Closable) {
	if obj != nil {
		obj.Close()
	}
}
