package credentials

import "encoding/json"

type Credentials struct {
	ServerURL string `json:"ServerURL"`
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
}

type Helper interface {
	Add(*Credentials) error
	Delete(serverURL string) error
	Get(serverURL string) (string, string, error)
	List() (map[string]string, error)
}

func (c *Credentials) Validate() error {
	if c.ServerURL == "" {
		return NewErrCredentialsMissingServerURL()
	}
	return nil
}

type errCredentialsMissingServerURL struct {
	ServerURLMissing bool `json:"ServerURLMissing"`
}

func (e errCredentialsMissingServerURL) Error() string {
	return "credentials missing server URL"
}

func NewErrCredentialsMissingServerURL() error {
	return errCredentialsMissingServerURL{ServerURLMissing: true}
}

type errCredentialsNotFound struct{}

func (e errCredentialsNotFound) Error() string {
	return "credentials not found in native keychain"
}

func ErrCredentialsNotFound() error {
	return errCredentialsNotFound{}
}

func IsErrCredentialsNotFound(err error) bool {
	_, ok := err.(errCredentialsNotFound)
	return ok
}

type invalidVersionAction struct{}

func (e invalidVersionAction) Error() string {
	return "invalid version action"
}

func IsErrInvalidVersionAction(err error) bool {
	_, ok := err.(invalidVersionAction)
	return ok
}

func ParseAction(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func DecodeCredentials(input []byte) (*Credentials, error) {
	var creds Credentials
	if err := json.Unmarshal(input, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func EncodeCredentials(creds *Credentials) ([]byte, error) {
	return json.Marshal(creds)
}
