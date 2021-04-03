# Vault StreamNative Secrets Plugin

The Vault StreamNative Secrets Plugin for for [HashiCorp Vault](https://www.vaultproject.io/) allows you to serve dynamic JWTs for your [StreamNative.io](https://www.streamnative.io/) service accounts. StreamNative is a service which provides [Apache Pulsar](https://pulsar.apache.org) as a service. These JWTs can be used directly by your Pulsar clients to authenticate.

## Usage

Quick start: build and run a development Vault server with this plugin loaded.

```
# Build Mock plugin and start Vault dev server with plugin automatically registered
$ make
# Open a new terminal window and export Vault dev server http address
$ export VAULT_ADDR='http://127.0.0.1:8200'
# Enable the Mock plugin
$ make enable
```

Load your StreamNative service account key into vault, and read back a token. These instructions use [snctl](https://docs.streamnative.io/cloud/stable/quickstart/quickstart-snctl), the StreamNative CLI, but you may also download your service account key file from the StreamNative web console.

```
# Configure snctl and log in
snctl config init
snctl login
# Save a key for your service account
snctl -n my-app-org auth export-service-account my-service-account --key-file my-service-account-key.json

# Write your service account key to vault
$ vault write /snio/my-service-account organization=my-app-org cluster=my-cluster key-file=@my-service-account-key.json
Success! Data written to: snio/my-service-account
# Read back a new temporary token
$ vault read /snio/my-service-account
Key      Value
---      -----
token    AYlfaHJHY2lQaUpMRXgJFU7...
```

## Development

Follow the [Vault Plugin Guide](https://learn.hashicorp.com/tutorials/vault/plugin-backends) for reference on Vault plugin architecture and development.

## License

Copyright © 2021 Arctype Corporation. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
