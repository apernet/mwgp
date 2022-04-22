package main

import (
	"encoding/json"
	"fmt"
	"github.com/haruue-net/mwgp"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, "Usage: mwgp [server|client] config.json\n")
}

func startServer(config []byte) (err error) {
	serverConfig := mwgp.ServerConfig{}
	err = json.Unmarshal(config, &serverConfig)
	if err != nil {
		return
	}
	server, err := mwgp.NewServerWithConfig(&serverConfig)
	if err != nil {
		return
	}
	return server.Start()
}

func startClient(config []byte) (err error) {
	clientConfig := mwgp.ClientConfig{}
	err = json.Unmarshal(config, &clientConfig)
	if err != nil {
		return
	}
	client, err := mwgp.NewClientWithConfig(&clientConfig)
	if err != nil {
		return
	}
	return client.Start()
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			printUsage(os.Stdout)
			os.Exit(0)
		}
	}
	if len(os.Args) != 3 {
		printUsage(os.Stderr)
		os.Exit(22)
	}
	subcommand := os.Args[1]
	configPath := os.Args[2]
	config, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read config file %s: %s\n", configPath, err.Error())
	}
	switch subcommand {
	case "server":
		log.Fatal(startServer(config))
	case "client":
		log.Fatal(startClient(config))
	default:
		printUsage(os.Stderr)
		os.Exit(22)
	}

}
