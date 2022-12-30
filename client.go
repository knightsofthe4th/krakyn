/*===============================================
 *             KRAKYN CLIENT OBJECT
 *===============================================
 */

package krakyn

import (
	"fmt"
	"net"
	"time"
)

type Client struct {
	Callbacks *Callbacks
	Servers   []*ServerEndpoint
	Alive     bool
	*Authenticator
}

type Callbacks struct {
	OnRecieve func(*Transmission, *ServerEndpoint)
	OnAccept  func(*ServerEndpoint)
	OnRemove  func(*ServerEndpoint)
}

func NewClient(callback *Callbacks, user, pass, path string) (*Client, error) {
	auth, err := LoadProfile(user, pass, path)

	if err != nil {
		return nil, err
	}

	c := &Client{
		Callbacks:     callback,
		Servers:       make([]*ServerEndpoint, 0),
		Alive:         true,
		Authenticator: auth,
	}

	return c, nil
}

func (c *Client) Connect(address string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", address, TCP_PORT))

	if err == nil {
		go c.serveConn(conn)
	}

	return err
}

func (c *Client) WaitForQuit() {
	for c.Alive {
		time.Sleep(200 * time.Millisecond)
	}
}

func (c *Client) serveConn(conn net.Conn) {
	server := &ServerEndpoint{&Endpoint{"", nil, nil, conn, false}, &ServerConfig{nil}}
	c.Servers = append(c.Servers, server)

	server.Transmit(NewTransmission(CONNECT_DATA, NewConnectData(c.Authenticator)))

	for {
		stream, err := server.Recieve()

		if err != nil {
			if server.Ready {
				fmt.Printf("closing accepted connection with: %s\n", server.Name)
			} else {
				fmt.Printf("closing raw connection with: %s\n", conn.RemoteAddr())
			}

			index, se := GetServerEndpointFromConn(&c.Servers, conn)

			if c.Callbacks != nil {
				c.Callbacks.OnRemove(se)
			}

			RemoveServerEndpoint(&c.Servers, index)
			fmt.Printf("current server(s) active: %d\n", len(c.Servers))

			break
		}

		c.handleIncoming(conn, stream)
	}
}

func (c *Client) handleIncoming(conn net.Conn, tm *Transmission) {
	index, server := GetServerEndpointFromConn(&c.Servers, conn)

	if tm.Type == ACCEPT_DATA {
		ad := Deserialise[AcceptData](tm.Data)

		if !RSAVerify(ad.PublicKey, []byte(ad.Name), ad.Signature) {
			RemoveServerEndpoint(&c.Servers, index)
			fmt.Println("could not verify server signature")
			return
		}

		server.Name = ad.Name
		server.PublicKey = ad.PublicKey
		server.SessionKey = RSADecrypt(c.PrivateKey, ad.SessionKey)
		server.ServerConfig = ad.Config
		server.Ready = true

		fmt.Printf("authenticated connection with %s\n", server.Name)

		if c.Callbacks != nil {
			c.Callbacks.OnAccept(server)
		}

	} else if tm.Type == MESSAGE_DATA || tm.Type == CLIENT_DATA {
		if server.Ready {
			tm = tm.Decrypt(server.SessionKey)

			if c.Callbacks != nil && server.Ready {
				c.Callbacks.OnRecieve(tm, server)
			}
		}
	}
}
