/*===============================================
 *             KRAKYN SERVER OBJECT
 *===============================================
 */

package krakyn

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Server struct {
	Listener net.Listener
	Clients  []*Endpoint
	Alive    bool
	*Authenticator
	*ServerConfig
}

type ServerConfig struct {
	Channels []string
}

func NewServer(user, pass, path, address string, config *ServerConfig) (*Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", address, TCP_PORT))

	if err != nil {
		return nil, err
	}

	auth, err := LoadProfile(user, pass, path)

	if err != nil {
		return nil, err
	}

	server := &Server{
		Listener:      listener,
		Clients:       make([]*Endpoint, 0),
		Alive:         true,
		ServerConfig:  config,
		Authenticator: auth,
	}

	return server, nil
}

func (s *Server) Process() {
	for s.Alive {
		conn, err := s.Listener.Accept()
		fmt.Printf("connection from %s\n", conn.RemoteAddr().String())

		if err != nil {
			fmt.Println(err.Error())
		}

		go s.serveConn(conn)
	}
}

func (s *Server) Broadcast(tm *Transmission) {
	for _, client := range s.Clients {
		if client.Ready {
			client.Transmit(tm.Encrypt(client.SessionKey))
		}
	}
}

func (s *Server) serveConn(conn net.Conn) {
	client := &Endpoint{"", nil, nil, conn, false}
	s.Clients = append(s.Clients, client)

	for {
		stream, err := client.Recieve()

		if err != nil {
			if client.Ready {
				fmt.Printf("closing accepted connection with: %s\n", client.Name)
			} else {
				fmt.Printf("closing raw connection with: %s\n", conn.RemoteAddr())
			}

			index, _ := GetEndpointFromConn(&s.Clients, conn)
			RemoveEndpoint(&s.Clients, index)

			s.Broadcast(NewTransmission(CLIENT_DATA, NewClientListData(s.Clients)))

			break
		}

		s.handleIncoming(conn, stream)
	}
}

func (s *Server) channelExists(channel string) bool {
	for _, c := range s.Channels {
		if c == channel {
			return true
		}
	}

	return false
}

func (s *Server) handleIncoming(conn net.Conn, tm *Transmission) {
	index, client := GetEndpointFromConn(&s.Clients, conn)

	if tm.Type == CONNECT_DATA {
		cd := Deserialise[ConnectData](tm.Data)

		if !RSAVerify(cd.PublicKey, []byte(cd.Name), cd.Signature) {
			RemoveEndpoint(&s.Clients, index)
			fmt.Println("failed to verify signature...")
			return
		}

		client.Name = cd.Name
		client.PublicKey = cd.PublicKey
		client.SessionKey = AESDeriveKey(GenerateValue32(), nil)
		client.Ready = true

		fmt.Printf("authenticated connection with %s\n", client.Name)

		client.Transmit(NewTransmission(ACCEPT_DATA, NewAcceptData(
			s.Authenticator, s.ServerConfig, RSAEncrypt(client.PublicKey, client.SessionKey))))

		s.Broadcast(NewTransmission(CLIENT_DATA, NewClientListData(s.Clients)))

	} else if tm.Type == MESSAGE_DATA {
		tm = tm.Decrypt(client.SessionKey)
		msg := Deserialise[MessageData](tm.Data)

		if !s.channelExists(msg.Channel) {
			fmt.Printf("channel: %s does not exist\n", msg.Channel)
			return
		}

		msg.Timestamp = strings.Split(time.Now().String(), ".")[0]
		msg.Sender = client.Name
		msg.Print()

		s.Broadcast(NewTransmission(MESSAGE_DATA, msg))
	}
}
