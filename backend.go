package streamnative

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend
}

var _ logical.Factory = Factory

func GetSnctl() string {
	snctl, snctlSet := os.LookupEnv("SNCTL_PATH")
	if snctlSet {
		return snctl
	}
	return "snctl"
}

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(helpText),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			b.paths(),
		),
	}

	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("path"),

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary:  "Retrieve the secret from the map.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary:  "Deletes the secret at the specified location.",
				},
			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := data.Get("path").(string)

	// Decode the data
	var json map[string]interface{}
	ent, err := req.Storage.Get(ctx, path)
	if err != nil {
		b.Logger().Error("Reading from storage failed", "error", err)
		return nil, errwrap.Wrapf("Reading from storage failed: {{err}}", err)
	}
	secretBytes := ent.Value
	if secretBytes == nil {
		resp := logical.ErrorResponse("No value at %v%v", req.MountPoint, path)
		return resp, nil
	}

	b.Logger().Debug("Read path", "path", path)

	if err := jsonutil.DecodeJSON(secretBytes, &json); err != nil {
		b.Logger().Error("JSON decoding failed", "error", err)
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	if err := b.requireSnctlConfig(); err != nil {
		b.Logger().Error("Initializing snctl config failed", "error", err)
		return nil, err
	}

	// snctl -n <organization> auth get-token <cluster> -f <key.json>
	keyFileBytes := json["key-file"]
	org := json["organization"]
	cluster := json["cluster"]
	if keyFileBytes == nil {
		resp := logical.ErrorResponse("No 'key-file' set")
		return resp, nil
	}
	if org == nil {
		resp := logical.ErrorResponse("No 'organization' set")
		return resp, nil
	}
	if cluster == nil {
		resp := logical.ErrorResponse("No 'cluster' set")
		return resp, nil
	}

	// TempFile is always created with 0600 permissions
	tmpKeyFile, err := ioutil.TempFile(os.TempDir(), "snio-key-*.json")
	if err != nil {
		b.Logger().Error("Failed to open temp file", "error", err)
		return nil, err
	}
	defer os.Remove(tmpKeyFile.Name())
	ioutil.WriteFile(tmpKeyFile.Name(), []byte(keyFileBytes.(string)), 0600)

	if err := b.activateServiceAccount(tmpKeyFile.Name()); err != nil {
		b.Logger().Error("Activating service account failed", "error", err)
		return nil, err
	}

	cmd := exec.Command(GetSnctl(), "-n", org.(string), "auth", "get-token", cluster.(string), "-f", tmpKeyFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.Logger().Error("Failed to run `snctl auth get-token`", "error", err, "out", out)
		return nil, err
	}

	outData := map[string]interface{}{
		"token": string(out),
	}

	// Generate the response
	resp := &logical.Response{
		Data: outData,
	}

	return resp, nil
}

func (b *backend) initializeSnctlConfig() error {
	b.Logger().Info("Initializing snctl config")
	cmd := exec.Command(GetSnctl(), "config", "init")
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.Logger().Error("Failed to run `snctl config init`", "error", err, "out", out)
	}
	return err
}

// Initialize once if config dir does not exist.
// snctl config init
func (b *backend) requireSnctlConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errwrap.Wrapf("No user HOME directory: {{err}}", err)
	}
	path := home + "/.snctl"
	// TODO: Enter Mutex here
	_, err = os.ReadDir(path)
	if err != nil {
		// Clear error and attempt to initialize
		err = b.initializeSnctlConfig()
	}
	// Return remaining error, if any.
	return err
}

func (b *backend) activateServiceAccount(secretKey string) error {
	// Set a dummy oauth key. The dummy key is overwritten with per-request data.
	// snctl auth activate-service-account --key-file ~/service-account-key.json
	cmd := exec.Command(GetSnctl(), "auth", "activate-service-account", "--key-file", secretKey)
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.Logger().Error("Failed to run `snctl auth activate-service-account`", "error", err, "out", out)
	}
	return err
}

func (b *backend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := data.Get("path").(string)

	if len(req.Data) == 0 {
		b.Logger().Info("Clearing service account", "path", path)
		// clear the key file
		err := req.Storage.Delete(ctx, path)
		if err != nil {
			b.Logger().Error("Deleting from storage failed", "error", err)
			return nil, errwrap.Wrapf("Deleting from storage failed: {{err}}", err)
		}
		return nil, nil
	}

	// Example key file
	// {"type":"sn_service_account","client_id":"...","client_secret":"...","client_email":"...","issuer_url":"https://auth.streamnative.cloud"}

	// JSON encode the data
	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, errwrap.Wrapf("json encoding failed: {{err}}", err)
	}

	b.Logger().Info("Saving service account")
	// Store kv pairs in map at specified path
	ent := &logical.StorageEntry{
		Key:   path,
		Value: buf,
	}
	err = req.Storage.Put(ctx, ent)
	if err != nil {
		b.Logger().Error("Putting to storage failed", "error", err)
		return nil, errwrap.Wrapf("Putting to storage failed: {{err}}", err)
	}

	return nil, nil
}

func (b *backend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := data.Get("path").(string)

	// Remove entry for specified path
	err := req.Storage.Delete(ctx, path)
	if err != nil {
		b.Logger().Error("Deleting from storage failed", "error", err)
		return nil, errwrap.Wrapf("Deleting from storage failed: {{err}}", err)
	}

	return nil, nil
}

const helpText = `
The StreamNative backend generates Pulsar JWTs on-demand using the StreamNative API.
`
