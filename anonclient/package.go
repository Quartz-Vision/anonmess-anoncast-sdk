package anonclient

import (
	"errors"
	"io"

	"github.com/Quartz-Vision/anonmess-anoncast-sdk/keystore"
	"github.com/Quartz-Vision/anonmess-anoncast-sdk/utils"
	"github.com/Quartz-Vision/goslice"
	"github.com/google/uuid"
)

type DataPackage struct {
	client    *Client
	ChannelId uuid.UUID
	Payload   []byte
}

var ErrNoKeyPack = errors.New("no key pack for the channel")
var ErrWrongCheckSymbol = errors.New("wrong check symbol")
var ErrKeyNotEnough = errors.New("not enough key length to decode/encode the data")

const CHECK_SYMBOL_B byte = 0b10110010

func (p *DataPackage) MarshalBinary() (data []byte, err error) {
	channelId := make([]byte, utils.UUID_SIZE)
	copy(channelId, p.ChannelId[:])

	payload := make([]byte, len(p.Payload))
	copy(payload, p.Payload)

	var (
		keyPack              *keystore.KeyPack
		ok                   bool
		idKeyPos             int64
		payloadKeyPos        int64
		payloadKeyPosEnc     []byte
		payloadKeyPosEncSize int
		payloadSize          int
		payloadSizeEnc       []byte
		payloadSizeEncSize   int
		idKey                []byte
		payloadKey           []byte
	)

	utils.UntilErrorPointer(
		&err,
		// Key Pack
		func() {
			keyPack, ok = p.client.Keystore.GetKeyPack(p.ChannelId)
			if !ok {
				err = ErrNoKeyPack
			}
		},
		// Payload size encoding
		func() {
			payloadSize = len(payload)
			payloadSizeEnc = utils.Int64ToBytes(int64(payloadSize))
			payloadSizeEncSize = len(payloadSizeEnc)
		},
		// Reading Payload Key
		func() {
			payloadKeyPos, err = keyPack.PayloadOut.Pos.Take(
				int64(payloadSize + payloadSizeEncSize),
			)
			payloadKeyPosEnc = utils.Int64ToBytes(payloadKeyPos)
			payloadKeyPosEncSize = len(payloadKeyPosEnc)
		},
		func() {
			payloadKey = make([]byte, payloadSize+payloadSizeEncSize)
			_, err = keyPack.PayloadOut.ReadAt(payloadKey, payloadKeyPos)
		},
		// Reading ID Key
		func() {
			idKeyPos, err = keyPack.IdOut.Pos.Take(utils.UUID_SIZE + int64(payloadKeyPosEncSize))
		},
		func() {
			idKey = make([]byte, utils.UUID_SIZE+payloadKeyPosEncSize)
			_, err = keyPack.IdOut.ReadAt(idKey, idKeyPos)
		},
	)

	if err == io.EOF {
		return nil, ErrKeyNotEnough
	}

	if err != nil {
		return nil, err
	}

	idKeyPosEnc := utils.Int64ToBytes(idKeyPos)

	packageSize := len(idKeyPosEnc) + utils.UUID_SIZE + payloadKeyPosEncSize + payloadSizeEncSize + payloadSize + 1
	packageSizeEnc := utils.Int64ToBytes(int64(packageSize))

	encodedData := make([]byte, len(packageSizeEnc)+packageSize)

	goslice.Xor(channelId, idKey[:utils.UUID_SIZE])
	goslice.Xor(payloadKeyPosEnc, idKey[utils.UUID_SIZE:])
	goslice.Xor(payloadSizeEnc, payloadKey[:payloadSizeEncSize])
	goslice.Xor(payload, payloadKey[payloadSizeEncSize:])

	goslice.Join(
		encodedData,
		packageSizeEnc,
		idKeyPosEnc,
		channelId,
		payloadKeyPosEnc,
		payloadSizeEnc,
		payload,
	)

	encodedData[len(encodedData)-1] = CHECK_SYMBOL_B

	return encodedData, nil
}

var ErrKeyPackIdDecodeFailed = errors.New("no such key pack")

func (p *DataPackage) UnmarshalBinary(data []byte) (err error) {
	if data[len(data)-1] != CHECK_SYMBOL_B {
		return ErrWrongCheckSymbol
	}

	_, packageSizeLen := utils.BytesToInt64(data)
	data = data[packageSizeLen:]

	idKeyPos, idKeyPosLen := utils.BytesToInt64(data[:utils.INT_MAX_SIZE])
	data = data[idKeyPosLen:]

	var ok bool
	// Don't use utils for the error here since we need maximal speed
	if p.ChannelId, ok = p.client.Keystore.TryDecodePackId(idKeyPos, data[:utils.UUID_SIZE]); !ok {
		return ErrKeyPackIdDecodeFailed
	}
	data = data[utils.UUID_SIZE:]

	var (
		keyPack          *keystore.KeyPack
		payloadKeyPos    int64
		payloadKeyPosLen int
		payloadSize      int64
		payloadSizeLen   int
		idKey            []byte
		payloadKey       []byte
		tmpNum           = make([]byte, utils.INT_MAX_SIZE)
	)

	utils.UntilErrorPointer(
		&err,
		// Key Pack
		func() {
			keyPack, ok = p.client.Keystore.GetKeyPack(p.ChannelId)
			if !ok {
				err = ErrNoKeyPack
			}
		},
		// ID and Payload Key
		func() {
			idKey = make([]byte, utils.INT_MAX_SIZE)
			_, err = keyPack.IdIn.ReadAt(idKey, idKeyPos+utils.UUID_SIZE)
		},
		func() {
			goslice.SetResult(tmpNum, goslice.Xor, data[:utils.INT_MAX_SIZE], idKey)
			payloadKeyPos, payloadKeyPosLen = utils.BytesToInt64(tmpNum)
			data = data[payloadKeyPosLen:]

			payloadKey = make([]byte, utils.INT_MAX_SIZE)
			_, err = keyPack.PayloadIn.ReadAt(payloadKey, payloadKeyPos)
		},
		func() {
			goslice.SetResult(tmpNum, goslice.Xor, data[:utils.INT_MAX_SIZE], payloadKey)
			payloadSize, payloadSizeLen = utils.BytesToInt64(tmpNum)
			data = data[payloadSizeLen:]

			payloadKey = make([]byte, payloadSize)
			_, err = keyPack.PayloadIn.ReadAt(payloadKey, payloadKeyPos+int64(payloadSizeLen))
		},
		// Decoding the payload
		func() {
			p.Payload = make([]byte, payloadSize)
			goslice.SetResult(p.Payload, goslice.Xor, data[:payloadSize], payloadKey[:payloadSize])
		},
	)

	if err == io.EOF {
		return ErrKeyNotEnough
	}
	return err
}
