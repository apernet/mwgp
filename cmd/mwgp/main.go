package main

import (
	"fmt"
	"github.com/flynn/json5"
	"github.com/haruue-net/mwgp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	_ "github.com/haruue-net/mwgp/resolvers/dns"
	_ "github.com/haruue-net/mwgp/resolvers/hn2etxt"
)

var (
	MWGPVersion = "Unknown"
)

var rootCmd = cobra.Command{
	Use:     "mwgp",
	Version: MWGPVersion,
}

var serverCmd = cobra.Command{
	Use:   "server config.json",
	Short: "Start a mwgp server",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(args) != 1 {
			err = fmt.Errorf("excepted 1 argument as config file")
			return
		}
		serr := startServer(args[0])
		if serr != nil {
			log.Fatalf("[fatal] cannot start server: %s\n", serr.Error())
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
		if len(args) != 1 {
			err = fmt.Errorf("excepted 1 argument as config file")
			return
		}
		serr := startClient(args[0])
		if serr != nil {
			log.Fatalf("[fatal] cannot start client: %s\n", serr.Error())
			return
		}
		return
	},
}

func ensureCacheConfig(cc *mwgp.WGITCacheConfig, instanceSuffix string) {
	if viper.GetBool("no-cache") {
		log.Printf("[info] forward table cache has been disabled\n")
		cc.CacheFilePath = ""
		return
	}
	if viper.GetBool("skip-load-cache") {
		log.Printf("[info] forward table cache loading is disabled\n")
		cc.SkipLoadCache = true
		return
	}
	if cc.CacheFilePath == "" {
		cc.CacheFilePath = viper.GetString("cache-file")
	}
	if cc.CacheFilePath == "" {
		defaultCacheDir, err := os.UserCacheDir()
		if err != nil {
			err = nil
			defaultCacheDir = os.TempDir()
		}
		defaultCacheDir = filepath.Join(defaultCacheDir, "mwgp")
		err = os.MkdirAll(defaultCacheDir, 0755)
		if err != nil {
			log.Printf("[error] forward table cache path not set and cannot create default cache dir at %s, forward table cache will be disabled: %s\n", defaultCacheDir, err.Error())
		}
		cc.CacheFilePath = filepath.Join(defaultCacheDir, fmt.Sprintf("wgit-cache-%s.json", instanceSuffix))
		log.Printf("[warn] forward table cache path not set, using %s\n", cc.CacheFilePath)
	}
}

func init() {
	rootCmd.AddCommand(&serverCmd)
	rootCmd.AddCommand(&clientCmd)

	rootCmd.PersistentFlags().String("cache-file", "", "forward table cache file path")
	rootCmd.PersistentFlags().Bool("no-cache", false, "disable forward table cache")
	rootCmd.PersistentFlags().Bool("skip-load-cache", false, "skip loading forward table cache (but still save it)")

	_ = viper.BindPFlag("cache-file", rootCmd.PersistentFlags().Lookup("cache-file"))
	_ = viper.BindPFlag("no-cache", rootCmd.PersistentFlags().Lookup("no-cache"))
	_ = viper.BindPFlag("skip-load-cache", rootCmd.PersistentFlags().Lookup("skip-load-cache"))

	_ = viper.BindEnv("cache-file", "MWGP_CACHE_FILE")
	_ = viper.BindEnv("no-cache", "MWGP_NO_CACHE")
	_ = viper.BindEnv("skip-load-cache", "MWGP_SKIP_LOAD_CACHE")

	viper.AutomaticEnv()
}

func startServer(configPath string) (err error) {
	config, err := ioutil.ReadFile(configPath)
	if err != nil {
		return
	}
	serverConfig := mwgp.ServerConfig{}
	err = json5.Unmarshal(config, &serverConfig)
	if err != nil {
		return
	}
	ensureCacheConfig(&serverConfig.WGITCacheConfig, serverConfig.Listen)
	server, err := mwgp.NewServerWithConfig(&serverConfig)
	if err != nil {
		return
	}
	return server.Start()
}

func startClient(configPath string) (err error) {
	config, err := ioutil.ReadFile(configPath)
	if err != nil {
		return
	}
	clientConfig := mwgp.ClientConfig{}
	err = json5.Unmarshal(config, &clientConfig)
	if err != nil {
		return
	}
	ensureCacheConfig(&clientConfig.WGITCacheConfig, clientConfig.Listen)
	client, err := mwgp.NewClientWithConfig(&clientConfig)
	if err != nil {
		return
	}
	return client.Start()
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(22)
	}
}
