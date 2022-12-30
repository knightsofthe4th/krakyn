package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jacobsa/go-serial/serial"
	k "github.com/knightsofthe4th/krakyn"
)

var gClientData *k.ClientListData
var options serial.OpenOptions
var port io.ReadWriteCloser

type GifData struct {
	URL string `json:"url"`
}

func main() {
	//k.GenerateProfile("BotoftheCrypt", "test", "./bot.krakyn")

	args := os.Args[1:]

	if len(args) < 4 {
		fmt.Println("Usage: {username} {masterkey} {.krakyn file path} {address}")
		return
	}

	cb := k.Callbacks{OnRecieve: serverMessage, OnAccept: serverConnect, OnRemove: serverRemove}
	c, err := k.NewClient(&cb, args[0], args[1], args[2])

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = c.Connect(args[3])

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	options = serial.OpenOptions{
		PortName:        "COM3",
		BaudRate:        9600,
		DataBits:        8,
		StopBits:        1,
		MinimumReadSize: 4,
	}

	port, err = serial.Open(options)

	if err == nil {
		defer port.Close()
	}

	c.WaitForQuit()
}

func serverConnect(e *k.ServerEndpoint) {
	e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
		k.NewTextMessage("0", e.Channels[0], "BotoftheCrypt has been summoned in your humble presence!")).Encrypt(e.SessionKey))

	e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
		&k.MessageData{
			Sender:   "0",
			Channel:  e.Channels[0],
			Encoding: "IMG_URL",
			Data:     []byte("https://media4.giphy.com/media/Yx4sDmie0yZTaimvlx/giphy.gif?cid=ecf05e47kqg2ejklt5zy8s37w7c8608puq6l80w95svz55w1&rid=giphy.gif")}).Encrypt(e.SessionKey))
}

func serverRemove(e *k.ServerEndpoint) {
	fmt.Printf("server: %s is being disconnected\n", e.Name)
}

func serverMessage(tm *k.Transmission, e *k.ServerEndpoint) {
	if tm.Type == k.MESSAGE_DATA {
		msg := k.Deserialise[k.MessageData](tm.Data)
		msg.Print()

		args := strings.SplitN(string(msg.Data), " ", 2)

		if len(args) < 2 {
			return
		}

		if args[0] == "$greet" {
			for _, client := range gClientData.Names {
				if client == args[1] {
					e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
						k.NewTextMessage("0", msg.Channel, msg.Sender+" sends their regards to "+client)).Encrypt(e.SessionKey))

					return
				}
			}

			e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
				k.NewTextMessage("0", msg.Channel, "Oops, no user by the name of '"+args[1]+"'")).Encrypt(e.SessionKey))

		} else if args[0] == "$parrot" {
			e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
				k.NewTextMessage("0", msg.Channel, args[1])).Encrypt(e.SessionKey))

		} else if args[0] == "$gif" {
			response, err := http.Get("https://api.otakugifs.xyz/gif?reaction=" + args[1] + "&format=gif")

			if err != nil {
				fmt.Print(err.Error())
			}

			responseData, err := io.ReadAll(response.Body)
			if err != nil {
				fmt.Print(err.Error())
			}

			var gif GifData
			json.Unmarshal(responseData, &gif)

			if gif.URL != "" {
				e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
					&k.MessageData{
						Sender:   "0",
						Channel:  e.Channels[0],
						Encoding: "IMG_URL",
						Data:     []byte(gif.URL)}).Encrypt(e.SessionKey))

			} else {
				e.Transmit(k.NewTransmission(k.MESSAGE_DATA,
					k.NewTextMessage("0", msg.Channel, "oops, '"+args[1]+"' is not a valid category!")).Encrypt(e.SessionKey))

			}
		} else if args[0] == "$arduino" {

			if port == nil {
				e.Transmit(k.NewTransmission(
					k.MESSAGE_DATA,
					k.NewTextMessage("0", msg.Channel, "oops, arduino not available!")).Encrypt(e.SessionKey))

				return
			}

			n, err := port.Write([]byte(msg.Sender + ":"))
			if err != nil {
				log.Fatalf("port.Write: %d %v", err, n)
			}

			n, err = port.Write([]byte{0})
			if err != nil {
				log.Fatalf("port.Write: %d %v", err, n)
			}

			n, err = port.Write([]byte(args[1]))
			if err != nil {
				log.Fatalf("port.Write: %d %v", err, n)
			}

			n, err = port.Write([]byte{0})
			if err != nil {
				log.Fatalf("port.Write: %d %v", err, n)
			}
		}

	} else if tm.Type == k.CLIENT_DATA {
		cl := k.Deserialise[k.ClientListData](tm.Data)
		gClientData = cl
		cl.Print()
	}
}
