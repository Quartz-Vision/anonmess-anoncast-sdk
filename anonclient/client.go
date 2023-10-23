package anonclient

import (
	"errors"
	"io"
	"net"
	"path"
	"sync"

	"github.com/Quartz-Vision/anonmess-anoncast-sdk/keystore"
	"github.com/Quartz-Vision/anonmess-anoncast-sdk/utils"
	"github.com/google/uuid"
)

var ErrConnectionClosed = errors.New("connection already closed")
var ErrConnectionFailed = errors.New("connection failed")
var ErrBrokenPackageSend = errors.New("attempted to send a broken package")
var ErrBrokenPackageRecv = errors.New("received a broken package. Dropping connection")

type Client struct {
	conn           net.Conn
	mutex          sync.Mutex
	Keystore       *keystore.KeyStore
	address        string
	maxPackageSize int64
}

func NewClient(dataDirPath string, address string, keyBufferSize int64, maxPackageSize int64) (client *Client, err error) {
	keystorePath := path.Join(dataDirPath, "keystore")
	var store *keystore.KeyStore

	if store, err = keystore.NewKeyStore(keystorePath, keyBufferSize); err == nil {
		return &Client{
			mutex:          sync.Mutex{},
			Keystore:       store,
			address:        address,
			maxPackageSize: maxPackageSize,
		}, nil
	}
	return nil, err
}

// Adds new events to the sending queue. They will be sent to the server
func (c *Client) Write(channelId uuid.UUID, payload []byte) error {
	if c.conn != nil {
		pack := DataPackage{
			client:    c,
			ChannelId: channelId,
			Payload:   payload,
		}

		if buf, err := pack.MarshalBinary(); err != nil {
			return ErrBrokenPackageSend
		} else if _, err := c.conn.Write(buf); err != nil {
			c.Stop()
			return ErrConnectionClosed
		}
	}

	return nil
}

func (c *Client) Stop() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) Start() (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.conn, err = net.Dial("tcp", c.address)
	if err != nil {
		return ErrConnectionFailed
	}

	return nil
}

func (c *Client) Receive() (pack *DataPackage, err error) {
	sizeBuf := make([]byte, utils.INT_MAX_SIZE)

	for c.conn != nil {
		if _, err = io.ReadFull(c.conn, sizeBuf); err != nil {
			c.Stop()
			return nil, ErrConnectionClosed
		}

		// decode package size
		packageSize, sizeDataLength := utils.BytesToInt64(sizeBuf)
		if packageSize <= 0 || packageSize >= c.maxPackageSize {
			return nil, ErrBrokenPackageRecv
		}

		// make a buffer with the whole package
		packageBuf := make([]byte, packageSize+int64(sizeDataLength))
		copy(packageBuf, sizeBuf)
		if _, err = io.ReadFull(c.conn, packageBuf[len(sizeBuf):]); err != nil {
			c.Stop()
			return nil, ErrConnectionClosed
		}

		// decode the package
		pack := DataPackage{
			client: c,
		}
		if err = pack.UnmarshalBinary(packageBuf); err == nil {
			return &pack, nil
		} else if err != ErrKeyPackIdDecodeFailed {
			return nil, ErrBrokenPackageRecv
		}
	}

	return nil, ErrConnectionClosed
}

func (c *Client) Close() {
	c.Stop()
	c.Keystore.Close()
	c.Keystore = nil
}
