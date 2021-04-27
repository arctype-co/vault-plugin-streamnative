package main

import (
	"os"

	streamnative "github.com/arctype-co/vault-plugin-streamnative"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})
	logger.Info("Using snctl", "snctl", streamnative.GetSnctl())
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: streamnative.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
