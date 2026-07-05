package credentials

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ExtendedHelper interface includes setup and identities commands
type ExtendedHelper interface {
	Helper
	SetupCommand(args []string) error
	IdentitiesCommand(args []string) error
}

func Serve(h Helper) {
	if len(os.Args) < 2 {
		fmt.Println(usage())
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--version", "-v":
		if v, ok := h.(interface{ Version() string }); ok {
			fmt.Println(v.Version())
		} else {
			fmt.Println("version not implemented")
		}
		os.Exit(0)
	case "--help", "-h":
		fmt.Println(usage())
		os.Exit(0)
	case "setup":
		if ext, ok := h.(ExtendedHelper); ok {
			if err := ext.SetupCommand(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stdout, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		fmt.Println("Setup command not implemented")
		os.Exit(1)
	case "identities":
		if ext, ok := h.(ExtendedHelper); ok {
			if err := ext.IdentitiesCommand(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stdout, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		fmt.Println("Identities command not implemented")
		os.Exit(1)
	}

	if err := HandleCommand(h, os.Args[1], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stdout, err)
		os.Exit(1)
	}
}

func usage() string {
	return `Usage: docker-credential-passage <command>
Commands:
  store      - Store credentials
  get        - Get credentials
  erase      - Delete credentials
  list       - List all credentials
  version    - Show version
  setup      - Setup configuration
  identities - Manage identities`
}

func HandleCommand(h Helper, action string, in io.Reader, out io.Writer) error {
	switch action {
	case "store":
		return Store(h, in)
	case "get":
		return Get(h, in, out)
	case "erase":
		return Erase(h, in)
	case "list":
		return List(h, out)
	case "version":
		if v, ok := h.(interface{ Version() string }); ok {
			fmt.Fprintln(out, v.Version())
		} else {
			fmt.Fprintln(out, "version not implemented")
		}
		return nil
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func Store(h Helper, reader io.Reader) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(reader); err != nil {
		return err
	}

	var creds Credentials
	if err := json.NewDecoder(buffer).Decode(&creds); err != nil {
		return err
	}

	if creds.ServerURL == "" {
		return NewErrCredentialsMissingServerURL()
	}

	return h.Add(&creds)
}

func Get(h Helper, reader io.Reader, writer io.Writer) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(reader); err != nil {
		return err
	}

	serverURL := strings.TrimSpace(buffer.String())
	if len(serverURL) == 0 {
		return NewErrCredentialsMissingServerURL()
	}

	username, secret, err := h.Get(serverURL)
	if err != nil {
		return err
	}

	resp := Credentials{
		ServerURL: serverURL,
		Username:  username,
		Secret:    secret,
	}
	return json.NewEncoder(writer).Encode(resp)
}

func Erase(h Helper, reader io.Reader) error {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(reader); err != nil {
		return err
	}

	serverURL := strings.TrimSpace(buffer.String())
	if len(serverURL) == 0 {
		return NewErrCredentialsMissingServerURL()
	}

	return h.Delete(serverURL)
}

func List(h Helper, writer io.Writer) error {
	servers, err := h.List()
	if err != nil {
		return err
	}
	return json.NewEncoder(writer).Encode(servers)
}
