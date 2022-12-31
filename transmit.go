package krakyn

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"reflect"
)

/*===============================================
 *             CONSTANT DEFINITIONS
 *===============================================
 */

const (
	ADDR_INTERN string = "127.0.0.1"
	ADDR_ALL    string = "0.0.0.0"
	TCP_PORT    string = "14402"

	MAGIC_VAL string = "krakyn"
	SEP_VAL   string = "*/MSEP/*"

	HEADER_SIZE uint8 = 8
	HEADER_PAD  uint8 = 2

	MESSAGE_DATA uint16 = 0
	CONNECT_DATA uint16 = 1
	QUIT_DATA    uint16 = 2
	ACCEPT_DATA  uint16 = 3
	DENY_DATA    uint16 = 4
	CLIENT_DATA  uint16 = 5

	ENCODE_TEXT string = "TEXT"
	ENCODE_PNG  string = "PNG"
	ENCODE_FILE string = "FILE"
)

/*===============================================
 *             KRAKYN DATA STREAMS
 *===============================================
 */

type Transmission struct {
	Size uint32
	Type uint16
	Data []byte
}

type ConnectData struct {
	Name      string
	PublicKey *rsa.PublicKey
	Signature []byte
}

type AcceptData struct {
	Name       string
	PublicKey  *rsa.PublicKey
	Signature  []byte
	SessionKey []byte
	Config     *ServerConfig
}

type ClientListData struct {
	Names []string
}

type MessageData struct {
	Timestamp string
	Sender    string
	Channel   string
	Encoding  string
	Data      []byte
}

/*===============================================
 *             TRANSMISSION METHODS
 *===============================================
 */

func (tm *Transmission) Encrypt(key []byte) *Transmission {

	etm := &Transmission{
		Type: tm.Type,
	}

	etm.Data = AESEncrypt(key, tm.Data)
	etm.Size = uint32(len(etm.Data))
	return etm
}

func (tm *Transmission) Decrypt(key []byte) *Transmission {
	dtm := &Transmission{
		Type: tm.Type,
	}

	dtm.Data = AESDecrypt(key, tm.Data)
	dtm.Size = uint32(len(dtm.Data))
	return dtm
}

func NewTransmission[T any](dataType uint16, data *T) *Transmission {
	tm := &Transmission{
		Type: dataType,
		Data: Serialise(data),
		Size: 0,
	}

	tm.Size = uint32(len(tm.Data))
	return tm
}

/*===============================================
 *              DATA CONSTRUCTORS
 *===============================================
 */

func NewConnectData(auth *Authenticator) *ConnectData {
	cd := &ConnectData{
		Name:      auth.Name,
		PublicKey: auth.PublicKey,
		Signature: RSASign(auth.PrivateKey, []byte(auth.Name)),
	}

	return cd
}

func NewAcceptData(auth *Authenticator, config *ServerConfig, sk []byte) *AcceptData {
	ad := &AcceptData{
		Name:       auth.Name,
		PublicKey:  auth.PublicKey,
		Signature:  RSASign(auth.PrivateKey, []byte(auth.Name)),
		SessionKey: sk,
		Config:     config,
	}

	return ad
}

func NewClientListData(clients []*Endpoint) *ClientListData {
	cl := new(ClientListData)

	for _, client := range clients {
		cl.Names = append(cl.Names, client.Name)
	}

	return cl
}

func NewTextMessage(sender, channel, text string) *MessageData {
	msg := &MessageData{
		Timestamp: "",
		Sender:    sender,
		Channel:   channel,
		Encoding:  ENCODE_TEXT,
		Data:      []byte(text),
	}

	return msg
}

/*===============================================
 *           DATA STRUCTURE PRINTING
 *===============================================
 */

func (tm *Transmission) Print() {
	fmt.Printf("--- %s ---\n", reflect.TypeOf(Transmission{}).Name())
	fmt.Printf("size: %d type: %d\n\n", tm.Size, tm.Type)
	fmt.Printf("--- %s ---\n\n", reflect.TypeOf(Transmission{}).Name())
}

func (cl *ClientListData) Print() {
	fmt.Printf("--- %s ---\n", reflect.TypeOf(ClientListData{}).Name())
	for _, name := range cl.Names {
		fmt.Printf("%s\n", name)
	}
	fmt.Printf("--- %s ---\n\n", reflect.TypeOf(ClientListData{}).Name())
}

func (m *MessageData) Print() {
	fmt.Printf("--- %s ---\n", reflect.TypeOf(MessageData{}).Name())
	fmt.Printf("%s\n", m.Timestamp)
	fmt.Printf("sender: %s\nchannel: %s\nencoding: %s\nsize: %d (bytes)\n", m.Sender, m.Channel, m.Encoding, len(m.Data))
	fmt.Printf("--- %s ---\n\n", reflect.TypeOf(MessageData{}).Name())
}

/*===============================================
 *         DATA SERIALISATION GENERICS
 *===============================================
 */

func Serialise[T any](t *T) []byte {
	buffer := bytes.Buffer{}
	gob.Register(t)

	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(t)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return buffer.Bytes()
}

func Deserialise[T any](data []byte) *T {
	buffer := bytes.Buffer{}
	buffer.Write(data)

	t := new(T)

	decoder := gob.NewDecoder(&buffer)
	err := decoder.Decode(t)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return t
}
