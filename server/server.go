package main

import (
	"fmt"

	"github.com/knightsofthe4th/krakyn"
)

func main() {
	krakyn.GenerateProfile("Test Server", "test", "./ts.krakyn")

	config := &krakyn.ServerConfig{
		Channels: []string{"general", "dev"},
	}

	server, err := krakyn.NewServer("Test Server", "test", "./ts.krakyn", krakyn.ADDR_ALL, config)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("Starting krakyn Server - %s\n\n", server.Name)
	server.Process()
}
