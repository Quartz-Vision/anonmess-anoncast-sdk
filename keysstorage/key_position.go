package keysstorage

import (
	"Quartz-Vision/anonmess-client-sdk/utils"
	"io/fs"

	"github.com/Quartz-Vision/gofile"
)

// KeyPosition takes care for accessing and storing current key position, that can be used for encoding/decoding

type KeyPosition struct {
	file gofile.File
}

func NewKeyPosition(filePath string, perm fs.FileMode) (pos *KeyPosition, err error) {
	var file gofile.File
	var size int64

	return pos, utils.UntilErrorPointer(
		&err,
		func() {
			file, err = gofile.NewFile(filePath, 0o600)
		},
		func() {
			if size, err = file.Size(); size == 0 && err == nil {
				_, err = file.Write(utils.Int64ToBytes(0))
			}
		},
		func() {
			pos = &KeyPosition{
				file: file,
			}
		},
	)
}

// Takes the size of data you want to de/encode and returns the position,
// from which you can use the reserved key part
func (p *KeyPosition) Take(dataSize int64) (pos int64, err error) {
	return pos, p.file.TReadWrite(func(txn gofile.Editable) (err error) {
		data := make([]byte, utils.INT_MAX_SIZE)
		_, err = txn.ReadAt(data, 0)
		if err != nil {
			return err
		}
		pos, _ = utils.BytesToInt64(data)
		nextPos := pos + dataSize
		_, err = txn.WriteAt(utils.Int64ToBytes(nextPos), 0)
		return err
	})
}
