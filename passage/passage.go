package passage

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/amrkmn/docker-credential-passage/credentials"
)

const (
	PASS_FOLDER = "docker-credential-helpers"
)

// Version is set at build time via ldflags
var Version = "dev"

type Passage struct{}

// Add stores credentials using age encryption
func (p Passage) Add(creds *credentials.Credentials) error {
	if creds == nil {
		return errors.New("missing credentials")
	}

	// Ensure default identity exists
	_, err := ensureDefaultIdentity()
	if err != nil {
		return fmt.Errorf("identity error: %w", err)
	}

	// Ensure recipients file exists
	if err := ensureRecipients(); err != nil {
		return fmt.Errorf("recipients error: %w", err)
	}

	// Load recipients for encryption
	recipients, err := loadRecipients()
	if err != nil {
		return err
	}

	// Encrypt and save
	encoded := encodeServerURL(creds.ServerURL)
	path := filepath.Join(getPassageDirStatic(), PASS_FOLDER, encoded, creds.Username+".age")

	if err := encryptAndSave(path, creds.Secret, recipients); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
}

// Delete removes credentials for a server URL
func (p Passage) Delete(serverURL string) error {
	if serverURL == "" {
		return errors.New("missing server URL")
	}

	encoded := encodeServerURL(serverURL)
	return deleteServerDir(filepath.Join(getPassageDirStatic(), PASS_FOLDER, encoded))
}

// Get retrieves credentials for a server URL
func (p Passage) Get(serverURL string) (string, string, error) {
	if serverURL == "" {
		return "", "", errors.New("missing server URL")
	}

	// Load active identity for decryption
	identity, err := loadActiveIdentity()
	if err != nil {
		return "", "", fmt.Errorf("identity error: %w", err)
	}

	// List available usernames
	encoded := encodeServerURL(serverURL)
	usernames, err := listUsernames(encoded)
	if err != nil {
		return "", "", err
	}

	// Try each username file
	for _, username := range usernames {
		path := filepath.Join(getPassageDirStatic(), PASS_FOLDER, encoded, username+".age")
		secret, err := decryptAndRead(path, identity)
		if err != nil {
			continue
		}
		return username, secret, nil
	}

	return "", "", credentials.ErrCredentialsNotFound()
}

// List returns all stored credentials
func (p Passage) List() (map[string]string, error) {
	servers, err := listPassageDir()
	if err != nil {
		return nil, err
	}

	infos := make(map[string]string)
	for serverURL, usernames := range servers {
		if len(usernames) > 0 {
			infos[serverURL] = usernames[0]
		}
	}

	return infos, nil
}

// GetVersion returns the version string
func (p Passage) Version() string {
	return fmt.Sprintf("docker-credential-passage/%s", Version)
}

// ==================== IDENTITY MANAGEMENT ====================

// identitiesDir returns the directory for identity files
func identitiesDir() string {
	if dir := os.Getenv("DOCKER_CREDENTIAL_PASSAGE_DIR"); dir != "" {
		return filepath.Join(dir, "identities")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".docker-credential-passage", "identities")
}

// defaultIdentityPath returns the path to the default identity
func defaultIdentityPath() string {
	return filepath.Join(identitiesDir(), "default.txt")
}

// publicKeyPath returns the path to a public key file
func publicKeyPath(identityName string) string {
	return filepath.Join(identitiesDir(), identityName+".pub")
}

// ensureDir creates a directory if it doesn't exist
func ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0700)
	}
	return nil
}

// loadIdentity loads a specific identity by name
func loadIdentity(name string) (*age.X25519Identity, error) {
	path := filepath.Join(identitiesDir(), name+".txt")

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open identity file: %w", err)
	}
	defer file.Close()

	identities, err := age.ParseIdentities(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity: %w", err)
	}

	if len(identities) == 0 {
		return nil, errors.New("no identities found in file")
	}

	return identities[0].(*age.X25519Identity), nil
}

// loadDefaultIdentity loads the default identity
func loadDefaultIdentity() (*age.X25519Identity, error) {
	return loadIdentity("default")
}

// loadActiveIdentity loads the currently active identity
func loadActiveIdentity() (*age.X25519Identity, error) {
	name := getActiveIdentityName()
	return loadIdentity(name)
}

// getActiveIdentityName returns the name of the active identity
func getActiveIdentityName() string {
	if name := os.Getenv("DOCKER_CREDENTIAL_PASSAGE_IDENTITY"); name != "" {
		return name
	}
	return "default"
}

// listIdentities returns a list of available identity names
func listIdentities() ([]string, error) {
	dir := identitiesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var identities []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".txt") {
			identities = append(identities, strings.TrimSuffix(name, ".txt"))
		}
	}

	return identities, nil
}

// generateIdentity creates a new identity with formatted output
func generateIdentity(name string) (*age.X25519Identity, error) {
	// Ensure identities directory exists
	if err := ensureDir(identitiesDir()); err != nil {
		return nil, fmt.Errorf("failed to create identities directory: %w", err)
	}

	identityPath := filepath.Join(identitiesDir(), name+".txt")
	publicPath := publicKeyPath(name)

	// Check if identity already exists
	if _, err := os.Stat(identityPath); err == nil {
		return nil, fmt.Errorf("identity '%s' already exists at %s", name, identityPath)
	}

	// Generate new identity
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}

	// Save identity to file
	identityFile, err := os.OpenFile(identityPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity file: %w", err)
	}
	defer identityFile.Close()

	if _, err := identityFile.WriteString(identity.String()); err != nil {
		return nil, fmt.Errorf("failed to write identity: %w", err)
	}

	// Save public key to file
	publicKey := identity.Recipient().String()

	publicFile, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicFile.Close()

	if _, err := publicFile.WriteString(publicKey + "\n"); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	// Print formatted output
	fmt.Printf("✓ Identity created: %s\n", identityPath)
	fmt.Printf("Public key: %s\n", publicKey)
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Backup your identity file! If you lose it, you cannot decrypt your credentials.")
	fmt.Printf("   Identity file: %s\n", identityPath)

	return identity, nil
}

// ensureDefaultIdentity creates default identity if missing
func ensureDefaultIdentity() (*age.X25519Identity, error) {
	identity, err := loadDefaultIdentity()
	if err == nil {
		return identity, nil
	}

	// Generate default identity
	return generateIdentity("default")
}

// ==================== RECIPIENT MANAGEMENT ====================

// recipientsPath returns the path to the recipients file
func recipientsPath() string {
	if path := os.Getenv("DOCKER_CREDENTIAL_PASSAGE_RECIPIENTS"); path != "" {
		return path
	}
	return filepath.Join(getDockerDir(), "store", ".age-recipients")
}

// getDockerDir returns the Docker-specific directory
func getDockerDir() string {
	if dir := os.Getenv("DOCKER_CREDENTIAL_PASSAGE_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".docker-credential-passage")
}

// loadRecipients loads recipients from file (Age CLI compatible format)
func loadRecipients() ([]age.Recipient, error) {
	path := recipientsPath()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []age.Recipient{}, nil
		}
		return nil, fmt.Errorf("failed to open recipients file: %w", err)
	}
	defer file.Close()

	recipients, err := age.ParseRecipients(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipients: %w", err)
	}

	return recipients, nil
}

// saveRecipients saves recipients to file
func saveRecipients(recipients []age.Recipient) error {
	path := recipientsPath()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create recipients file: %w", err)
	}
	defer file.Close()

	// Write header comment
	if _, err := file.WriteString("# Age recipients for docker-credential-passage\n"); err != nil {
		return err
	}

	// Write each recipient
	for _, r := range recipients {
		recipientStr, ok := r.(*age.X25519Recipient)
		if !ok {
			continue
		}
		if _, err := file.WriteString(recipientStr.String() + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// ensureRecipients ensures recipients file exists with default identity
func ensureRecipients() error {
	path := recipientsPath()

	// Check if file exists
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	// Load default identity to get its recipient
	identity, err := loadDefaultIdentity()
	if err != nil {
		return fmt.Errorf("failed to load default identity: %w", err)
	}

	// Create recipients with default identity
	recipients := []age.Recipient{identity.Recipient()}
	return saveRecipients(recipients)
}

// addRecipient adds a recipient to the recipients file
func addRecipient(recipient age.Recipient) error {
	recipients, err := loadRecipients()
	if err != nil {
		return err
	}

	// Check if already exists
	recipientStr := recipient.(*age.X25519Recipient).String()
	for _, r := range recipients {
		if r.(*age.X25519Recipient).String() == recipientStr {
			return nil // Already exists
		}
	}

	recipients = append(recipients, recipient)
	return saveRecipients(recipients)
}

// removeRecipient removes a recipient from the recipients file
func removeRecipient(recipientStr string) error {
	recipients, err := loadRecipients()
	if err != nil {
		return err
	}

	var newRecipients []age.Recipient
	for _, r := range recipients {
		if r.(*age.X25519Recipient).String() != recipientStr {
			newRecipients = append(newRecipients, r)
		}
	}

	return saveRecipients(newRecipients)
}

// listRecipients returns a list of recipient strings
func listRecipients() ([]string, error) {
	recipients, err := loadRecipients()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, r := range recipients {
		result = append(result, r.(*age.X25519Recipient).String())
	}

	return result, nil
}

// ==================== ENCRYPTION/DECRYPTION ====================

// encryptAndSave encrypts content and saves to .age file
func encryptAndSave(path string, content string, recipients []age.Recipient) error {
	if len(recipients) == 0 {
		return errors.New("no recipients specified")
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create output file
	outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	// Encrypt
	w, err := age.Encrypt(outFile, recipients...)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}

	// Write content
	if _, err := io.WriteString(w, content); err != nil {
		return fmt.Errorf("failed to write content: %w", err)
	}

	// Close the writer to flush
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finalize encryption: %w", err)
	}

	return nil
}

// decryptAndRead decrypts .age file and returns content
func decryptAndRead(path string, identity *age.X25519Identity) (string, error) {
	inFile, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer inFile.Close()

	r, err := age.Decrypt(inFile, identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt file: %w", err)
	}

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		return "", fmt.Errorf("failed to read decrypted content: %w", err)
	}

	return strings.TrimSpace(out.String()), nil
}

// deleteServerDir removes the entire server URL directory
func deleteServerDir(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}
	return nil
}

// ==================== HELPER FUNCTIONS ====================

// encodeServerURL encodes a server URL for safe filename
func encodeServerURL(serverURL string) string {
	return base64.URLEncoding.EncodeToString([]byte(serverURL))
}

// decodeServerURL decodes an encoded server URL
func decodeServerURL(encoded string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// getPassageDirStatic returns the passage store directory
func getPassageDirStatic() string {
	if dir := os.Getenv("PASSAGE_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".passage", "store")
}

// listUsernames returns a list of usernames for a specific server URL
func listUsernames(encodedURL string) ([]string, error) {
	dir := filepath.Join(getPassageDirStatic(), PASS_FOLDER, encodedURL)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var usernames []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".age") {
			usernames = append(usernames, strings.TrimSuffix(name, ".age"))
		}
	}

	return usernames, nil
}

// listPassageDir lists all stored credentials
func listPassageDir() (map[string][]string, error) {
	dir := filepath.Join(getPassageDirStatic(), PASS_FOLDER)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]string), nil
		}
		return nil, err
	}

	servers := make(map[string][]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		serverURLEncoded := entry.Name()
		serverURL, err := decodeServerURL(serverURLEncoded)
		if err != nil {
			continue
		}

		usernames, err := listUsernames(serverURLEncoded)
		if err != nil {
			continue
		}

		servers[serverURL] = usernames
	}

	return servers, nil
}

// ==================== COMMAND HANDLERS ====================

// SetupCommand handles the setup subcommand
func (p Passage) SetupCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("Docker Credential Helper - Setup")
		fmt.Println()
		fmt.Println("Available commands:")
		fmt.Println("  docker-credential-passage setup identity [name]")
		fmt.Println("  docker-credential-passage setup recipients")
		fmt.Println()
		fmt.Println("Current identity:", getActiveIdentityName())
		fmt.Println("Recipients file:", recipientsPath())
		return nil
	}

	switch args[0] {
	case "identity":
		return setupIdentityCommand(args[1:])
	case "recipients":
		return setupRecipientsCommand(args[1:])
	default:
		return fmt.Errorf("unknown setup command: %s", args[0])
	}
}

func setupIdentityCommand(args []string) error {
	name := "default"
	if len(args) > 0 {
		name = args[0]
	}

	identity, err := generateIdentity(name)
	if err != nil {
		return err
	}

	// Add default identity to recipients
	if name == "default" {
		if err := addRecipient(identity.Recipient()); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to add recipient: %v\n", err)
		}
	}

	return nil
}

func setupRecipientsCommand(args []string) error {
	if len(args) == 0 {
		recipients, err := listRecipients()
		if err != nil {
			return err
		}
		fmt.Println("Current recipients:")
		if len(recipients) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, r := range recipients {
				fmt.Println("  -", r)
			}
		}
		return nil
	}

	if args[0] == "add" && len(args) == 2 {
		recipient, err := age.ParseX25519Recipient(args[1])
		if err != nil {
			return fmt.Errorf("invalid recipient: %w", err)
		}
		if err := addRecipient(recipient); err != nil {
			return err
		}
		fmt.Printf("✓ Added recipient: %s\n", args[1])
		return nil
	}

	if args[0] == "remove" && len(args) == 2 {
		if err := removeRecipient(args[1]); err != nil {
			return err
		}
		fmt.Printf("✓ Removed recipient: %s\n", args[1])
		return nil
	}

	return fmt.Errorf("invalid recipients command: %s", args[0])
}

// IdentitiesCommand handles the identities subcommand
func (p Passage) IdentitiesCommand(args []string) error {
	if len(args) == 0 {
		// List identities
		identities, err := listIdentities()
		if err != nil {
			return err
		}

		active := getActiveIdentityName()
		fmt.Println("Available identities:")
		if len(identities) == 0 {
			fmt.Println("  (none - run 'docker-credential-passage setup identity' to create)")
		} else {
			for _, id := range identities {
				marker := " "
				if id == active {
					marker = "*"
				}
				fmt.Printf("  %s %s\n", marker, id)
			}
		}
		fmt.Println()
		fmt.Println("Active identity:", active)
		fmt.Println("Set DOCKER_CREDENTIAL_PASSAGE_IDENTITY to change")
		return nil
	}

	if args[0] == "create" {
		name := "default"
		if len(args) > 1 {
			name = args[1]
		}

		identity, err := generateIdentity(name)
		if err != nil {
			return err
		}

		// Add to recipients if default
		if name == "default" {
			if err := addRecipient(identity.Recipient()); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to add recipient: %v\n", err)
			}
		}
		return nil
	}

	return fmt.Errorf("invalid identities command: %s", args[0])
}
