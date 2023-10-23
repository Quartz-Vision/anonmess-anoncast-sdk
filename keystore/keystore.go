package keystore

import (
	"errors"
	"os"

	"github.com/Quartz-Vision/anonmess-anoncast-sdk/utils"
	"github.com/Quartz-Vision/gocrypt/symmetric"
	"github.com/Quartz-Vision/golog"
	"github.com/Quartz-Vision/goslice"

	"github.com/google/uuid"
)

var ErrPackageExists = errors.New("this package already exists")

type KeyStore struct {
	Packs        map[uuid.UUID]*KeyPack
	keystorePath string
	bufferSize   int64
}

func NewKeyStore(keystoreDirPath string, bufferSize int64) (store *KeyStore, err error) {
	store = &KeyStore{
		Packs:        make(map[uuid.UUID]*KeyPack),
		keystorePath: keystoreDirPath,
		bufferSize:   bufferSize,
	}

	if _, err = os.Stat(keystoreDirPath); os.IsNotExist(err) {
		if err = os.MkdirAll(keystoreDirPath, DefaultPermMode); err != nil {
			return nil, err
		}
		// no need to read the dir, it's definitely empty
		return store, nil
	} else if err != nil {
		return nil, err
	}

	dir, err := os.Open(keystoreDirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	if list, err := dir.Readdirnames(0); err != nil {
		return nil, err
	} else {
		for _, name := range list {
			if packId, err := uuid.Parse(name); err == nil {
				if pack, err := store.AddKeyPack(packId); err == nil {
					store.Packs[packId] = pack
				} else if err != ErrPackageExists {
					golog.Warning.Printf("Failed to load key pack %s: %s\n", name, err.Error())
				}
			}
		}
	}

	return store, nil
}

// Creates a new key pack and stores it, so that can be easily accessed later
func (k *KeyStore) AddKeyPack(packId uuid.UUID) (pack *KeyPack, err error) {
	pack, ok := k.Packs[packId]
	if !ok {
		pack, err = newKeyPack(k, packId)
		if err == nil {
			k.Packs[packId] = pack
		}
	} else {
		err = ErrPackageExists
	}

	return pack, err
}

func (k *KeyStore) RemoveKeyPack(packId uuid.UUID) {
	if pack, ok := k.Packs[packId]; ok {
		SafeClose(pack)
		delete(k.Packs, packId)
	}
}

func (k *KeyStore) ImportKeyPack(src string) (pack *KeyPack, err error) {
	var packId = uuid.UUID{}
	var ok bool

	utils.UntilErrorPointer(
		&err,
		func() { packId, err = getSharedPackId(src) },
		func() {
			if pack, ok = k.Packs[packId]; ok {
				err = ErrPackageExists
			}
		},
		func() { pack, err = importSharedKeyPack(k, packId, src) },
		func() { k.Packs[packId] = pack },
	)

	return pack, err
}

func (k *KeyStore) GetKeyPack(packId uuid.UUID) (pack *KeyPack, ok bool) {
	pack, ok = k.Packs[packId]
	return pack, ok
}

// Returns right pack id, using its encoded variant
func (k *KeyStore) TryDecodePackId(idKeyPos int64, encId []byte) (id uuid.UUID, ok bool) {
	idLen := int64(len(encId))
	tmpEncId := make([]byte, idLen)
	key := make([]byte, idLen)

	for id := range k.Packs {
		copy(tmpEncId, encId)

		_, err := k.Packs[id].IdIn.ReadAt(key, idKeyPos)

		if err == nil && symmetric.Decode(tmpEncId, key) == nil && goslice.Equal(tmpEncId, id[:]) {
			return id, true
		}
	}

	return id, false
}

func (k *KeyStore) Close() {
	for _, pack := range k.Packs {
		SafeClose(pack)
	}
}
