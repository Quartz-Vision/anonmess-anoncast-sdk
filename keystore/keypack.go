package keystore

import (
	"os"
	"path/filepath"

	"github.com/Quartz-Vision/anonmess-anoncast-sdk/utils"
	"github.com/Quartz-Vision/gofile"

	"github.com/google/uuid"
)

// KeyPack contains all the keys needed for a chat - id key, payload key etc
type KeyPack struct {
	manager    *KeyStore
	PackId     uuid.UUID
	IdIn       *Key
	IdOut      *Key
	PayloadIn  *Key
	PayloadOut *Key
	keys       [4]*Key
	packPath   string
}

func newKeyPack(manager *KeyStore, packId uuid.UUID) (keyPack *KeyPack, err error) {
	keyPack = &KeyPack{
		PackId:   packId,
		manager:  manager,
		packPath: filepath.Join(manager.keystorePath, packId.String()),
	}

	if utils.UntilErrorPointer(
		&err,
		func() {
			if _, err = os.Stat(keyPack.packPath); os.IsNotExist(err) {
				err = os.MkdirAll(keyPack.packPath, DefaultPermMode)
			}
		},
		func() {
			keyPack.IdIn, err = NewKey(keyPack, packId, KeyId, KeyIn)
			keyPack.keys[0] = keyPack.IdIn
		},
		func() {
			keyPack.IdOut, err = NewKey(keyPack, packId, KeyId, KeyOut)
			keyPack.keys[1] = keyPack.IdOut
		},
		func() {
			keyPack.PayloadIn, err = NewKey(keyPack, packId, KeyPayload, KeyIn)
			keyPack.keys[2] = keyPack.PayloadIn
		},
		func() {
			keyPack.PayloadOut, err = NewKey(keyPack, packId, KeyPayload, KeyOut)
			keyPack.keys[3] = keyPack.PayloadOut
		},
	) != nil {
		keyPack.Close()
		keyPack = nil
	}

	return keyPack, err
}

// Helps to get chatId of a shared pack
func getSharedPackId(src string) (packId uuid.UUID, err error) {
	packId = uuid.UUID{}
	var packageFile gofile.File

	utils.UntilErrorPointer(
		&err,
		func() { packageFile, err = gofile.NewFile(filepath.Join(src, "_package_"), 0o600) },
		func() { _, err = packageFile.ReadAt(packId[:], 0) },
		func() { packageFile.Close() },
	)

	return packId, err
}

func importSharedKeyPack(manager *KeyStore, packId uuid.UUID, src string) (keyPack *KeyPack, err error) {
	utils.UntilErrorPointer(
		&err,
		func() { keyPack, err = newKeyPack(manager, packId) },
		func() { err = keyPack.ImportShared(src) },
	)

	return keyPack, err
}

// generates new key part of the same size for all of the keys
func (p *KeyPack) GenerateKey(keySize int64) (err error) {
	for i := range p.keys {
		err = p.keys[i].GenerateKey(keySize)
		if err != nil {
			return err
		}
	}
	return
}

func (p *KeyPack) ExportShared(dest string) (err error) {
	var packageFile gofile.File

	return utils.UntilErrorPointer(
		&err,
		func() { packageFile, err = gofile.NewFile(filepath.Join(dest, "_package_"), 0o600) },
		func() { err = packageFile.Trunc() },
		func() { _, err = packageFile.Write(p.PackId[:]) },
		func() {
			packageFile.Close()

			for i := range p.keys {
				err = p.keys[i].ExportShared(dest)
				if err != nil {
					return
				}
			}
		},
	)
}

func (p *KeyPack) ImportShared(src string) (err error) {
	for i := range p.keys {
		err = p.keys[i].ImportShared(src)
		if err != nil {
			return err
		}
	}
	return
}

func (p *KeyPack) Close() {
	for key := range p.keys {
		SafeClose(p.keys[key])
	}
}
