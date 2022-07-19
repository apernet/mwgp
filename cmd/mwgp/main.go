package main

import (
	"encoding/json"
	"fmt"
	"github.com/haruue-net/mwgp"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

var (
	MWGPVersion = "2.0.0"
)

var rootCmd = cobra.Command{
	Use:     "mwgp",
	Version: MWGPVersion,
}

var serverCmd = cobra.Command{
	Use:   "server config.json",
	Short: "Start a mwgp server",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(os.Args) != 1 {
			err = fmt.Errorf("excepted 1 argument as config file")
			return
		}
		configPath := os.Args[0]
		config, err := ioutil.ReadFile(configPath)
		if err != nil {
			return
		}
		err = startServer(config)
		if err != nil {
			return
		}
		return
	},
}

var clientCmd = cobra.Command{
	Use:     "client config.json",
	Short:   "Start a mwgp client",
	Example: "mwgp client config.json",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(os.Args) != 1 {
			err = fmt.Errorf("excepted 1 argument as config file")
			return
		}
		configPath := os.Args[0]
		config, err := ioutil.ReadFile(configPath)
		if err != nil {
			return
		}
		err = startClient(config)
		if err != nil {
			return
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(&serverCmd)
	rootCmd.AddCommand(&clientCmd)
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
	_ = rootCmd.Execute()
}
