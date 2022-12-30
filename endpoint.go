/*===============================================
 *             KRAKYN CORE ENDPOINT
 *===============================================
 */

package krakyn

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
)

type Endpoint struct {
	Name       string
	SessionKey []byte
	PublicKey  *rsa.PublicKey
	Conn       net.Conn
	Ready      bool
}

type ServerEndpoint struct {
	*Endpoint
	*ServerConfig
}

func (e *Endpoint) Print() {
	fmt.Printf("--- %s ---\n", reflect.TypeOf(Endpoint{}).Name())

	fmt.Printf("name: %s\nsession key: %x\npublic key: %x\n\naddress: %s\nstatus: %v\n",
		e.Name, e.SessionKey, e.PublicKey, e.Conn.RemoteAddr(), e.Ready)

	fmt.Printf("--- %s ---\n\n", reflect.TypeOf(Endpoint{}).Name())
}

func (e *Endpoint) Transmit(tm *Transmission) error {
	buffer := bytes.Buffer{}
	size := make([]byte, 4)
	id := make([]byte, 2)

	binary.LittleEndian.PutUint32(size, tm.Size)
	binary.LittleEndian.PutUint16(id, tm.Type)

	buffer.Write(size)
	buffer.Write(id)
	buffer.Write(make([]byte, 2))
	buffer.Write(tm.Data)

	_, err := e.Conn.Write(buffer.Bytes())
	return err
}

func (e *Endpoint) Recieve() (*Transmission, error) {
	header := make([]byte, HEADER_SIZE)
	_, err := e.Conn.Read(header)

	if err != nil {
		return nil, err
	} else if len(header) < int(HEADER_SIZE) {
		return nil, fmt.Errorf("failed to get entire header")
	}

	tm := Transmission{
		Size: binary.LittleEndian.Uint32(header[0:4]),
		Type: binary.LittleEndian.Uint16(header[4:6]),
	}

	buffer := make([]byte, tm.Size)
	n, err := io.ReadFull(e.Conn, buffer)

	if err != nil {
		return nil, err
	} else if n < int(tm.Size) {
		return nil, fmt.Errorf("failed to get entire transmission")
	}

	tm.Data = buffer
	return &tm, nil
}

func RemoveEndpoint(list *[]*Endpoint, index int) {
	if len(*list) <= index {
		return
	}

	(*list)[index].Conn.Close()

	if index == 0 {
		(*list) = (*list)[1:]
	} else {
		(*list) = append((*list)[:index], (*list)[index+1:]...)
	}
}

func GetEndpointFromConn(list *[]*Endpoint, conn net.Conn) (int, *Endpoint) {
	for index, e := range *list {
		if conn == e.Conn {
			return index, (*list)[index]
		}
	}

	return -1, nil
}

func RemoveServerEndpoint(list *[]*ServerEndpoint, index int) {
	if len(*list) <= index {
		return
	}

	(*list)[index].Conn.Close()

	if index == 0 {
		(*list) = (*list)[1:]
	} else {
		(*list) = append((*list)[:index], (*list)[index+1:]...)
	}
}

func GetServerEndpointFromConn(list *[]*ServerEndpoint, conn net.Conn) (int, *ServerEndpoint) {
	for index, e := range *list {
		if conn == e.Conn {
			return index, (*list)[index]
		}
	}

	return -1, nil
}
