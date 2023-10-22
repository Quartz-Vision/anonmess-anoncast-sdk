package keysstorage

import (
	"Quartz-Vision/anonmess-client-sdk/utils"
	"path"
	"path/filepath"

	"github.com/Quartz-Vision/gocrypt/random"
	"github.com/Quartz-Vision/gofile"

	"github.com/google/uuid"
)

type KeyType int

const (
	KeyPayload KeyType = iota
	KeyId
)

func (k KeyType) String() string {
	switch k {
	case KeyPayload:
		return "payload"
	case KeyId:
		return "id"
	default:
		return "unknown"
	}
}

type KeyDirection int

const (
	KeyIn KeyDirection = iota
	KeyOut
)

func (k KeyDirection) String() string {
	switch k {
	case KeyIn:
		return "in"
	case KeyOut:
		return "out"
	default:
		return "unknown"
	}
}

const keyPosPrefix = "pos"

type Key struct {
	*gofile.BufferedFile
	KeyType      KeyType
	KeyDirection KeyDirection
	Pos          *KeyPosition
	pack         *KeyPack
}

func MakeKeyName(keyType KeyType, keyDirection KeyDirection) string {
	return keyType.String() + "-" + keyDirection.String()
}

func NewKey(pack *KeyPack, packId uuid.UUID, keyType KeyType, keyDirection KeyDirection) (key *Key, err error) {
	var keyPosition *KeyPosition
	path := path.Join(pack.packPath, MakeKeyName(keyType, keyDirection))

	file, err := gofile.NewFile(path, DefaultPermMode)
	if err != nil {
		return nil, err
	}

	bf, err := gofile.NewBufferedFile(file, pack.manager.bufferSize)
	if err != nil {
		return nil, err
	}

	if keyDirection == KeyOut {
		keyPosition, err = NewKeyPosition(path+keyPosPrefix, DefaultPermMode)
		if err != nil {
			file.Close()
			return nil, err
		}
	}

	return &Key{
		pack:         pack,
		BufferedFile: bf,
		KeyType:      keyType,
		KeyDirection: keyDirection,
		Pos:          keyPosition,
	}, nil
}

func (k *Key) ExportShared(dest string) (err error) {
	var file gofile.File
	var direction KeyDirection

	if k.KeyDirection == KeyOut {
		direction = KeyIn
	} else {
		direction = KeyOut
	}

	return utils.UntilErrorPointer(
		&err,
		func() {
			file, err = gofile.NewFile(filepath.Join(dest, MakeKeyName(k.KeyType, direction)), DefaultPermMode)
		},
		func() { err = file.Trunc() },
		func() { err = k.PipeTo(file, k.BufferSize) },
		func() { file.Close() },
	)
}

func (k *Key) ImportShared(src string) (err error) {
	var file gofile.File

	return utils.UntilErrorPointer(
		&err,
		func() {
			file, err = gofile.NewFile(filepath.Join(src, MakeKeyName(k.KeyType, k.KeyDirection)), DefaultPermMode)
		},
		func() { err = file.PipeTo(k, k.BufferSize) },
		func() { file.Close() },
	)
}

func (k *Key) Length() (length int64, err error) {
	return k.BufferedFile.Size()
}

// Generates new key parts
func (k *Key) GenerateKey(length int64) (err error) {
	if rest := length % k.BufferSize; rest != 0 {
		if key, err := random.GenerateRandomBytes(rest); err != nil {
			return err
		} else if _, err := k.Append(key); err != nil {
			return err
		}
	}

	length = length / k.BufferSize

	for i := int64(0); i < length; i++ {
		if key, err := random.GenerateRandomBytes(k.BufferSize); err != nil {
			return err
		} else if _, err := k.Append(key); err != nil {
			return err
		}
	}

	return nil
}
