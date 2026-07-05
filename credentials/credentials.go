package credentials

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

type errCredentialsMissingServerURL struct{}

func (e errCredentialsMissingServerURL) Error() string {
	return "credentials missing server URL"
}

func NewErrCredentialsMissingServerURL() error {
	return errCredentialsMissingServerURL{}
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

func ParseAction(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
