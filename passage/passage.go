package passage

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/amrkmn/docker-credential-passage/credentials"
)

const (
	PASS_FOLDER = "docker-credential-helpers"
)

// version is set at build time via ldflags
var version = "dev"

// SetVersion sets the version string (called from main)
func SetVersion(v string) {
	version = v
}

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
	return version
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

	// Also add to passage identities file if passage is installed
	if err := addToPassageIdentities(identity); err != nil {
		// Don't fail if we can't add to passage, just warn
		fmt.Fprintf(os.Stderr, "Warning: failed to add to passage identities: %v\n", err)
	}

	// Print formatted output
	fmt.Printf("✓ Identity created: %s\n", identityPath)
	fmt.Printf("Public key: %s\n", publicKey)
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Backup your identity file! If you lose it, you cannot decrypt your credentials.")
	fmt.Printf("   Identity file: %s\n", identityPath)

	return identity, nil
}

// addToPassageIdentities adds a newly created identity to ~/.passage/identities file
func addToPassageIdentities(identity *age.X25519Identity) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	passageDir := filepath.Join(home, ".passage")
	identitiesFile := filepath.Join(passageDir, "identities")

	// Check if passage is installed
	if _, err := os.Stat(passageDir); err != nil {
		// Passage not installed, skip
		return nil
	}

	// Format the identity entry
	created := time.Now().Format(time.RFC3339)
	publicKey := identity.Recipient().String()
	secretKey := identity.String()

	entry := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n\n", created, publicKey, secretKey)

	// Append to identities file
	f, err := os.OpenFile(identitiesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open passage identities file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to passage identities file: %w", err)
	}

	return nil
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
		fmt.Println("  docker-credential-passage setup sync")
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
	case "sync":
		return syncIdentitiesCommand()
	default:
		return fmt.Errorf("unknown setup command: %s", args[0])
	}
}

func setupIdentityCommand(args []string) error {
	name := "default"
	if len(args) > 0 {
		name = args[0]
	}

	// Check for existing .passage folder with identities
	if name == "default" {
		identities, err := findExistingPassageIdentities()
		if err == nil && len(identities) > 0 {
			// Found existing identities, show them to the user with useful info
			fmt.Println("Found existing Passage identities:")
			for i, identity := range identities {
				fmt.Printf("  [%d] Created: %s\n", i+1, identity.Created)
				fmt.Printf("       Public: %s\n", identity.PublicKey)
			}
			fmt.Println()
			fmt.Print("Select an identity to use as default (number), or 'n' to create a new one: ")

			var response string
			fmt.Scanln(&response)

			if response == "" || strings.ToLower(response) == "n" || strings.ToLower(response) == "no" {
				// User wants to create a new identity, continue to generateIdentity
			} else {
				// Try to parse the selection
				var selection int
				_, err := fmt.Sscanf(response, "%d", &selection)
				if err != nil || selection < 1 || selection > len(identities) {
					return fmt.Errorf("invalid selection: %s", response)
				}

				selectedIdentity := identities[selection-1]

				// Copy the existing identity to docker-credential-passage location
				if err := copyExistingIdentity(selectedIdentity, name); err != nil {
					return fmt.Errorf("failed to copy existing identity: %w", err)
				}

				fmt.Printf("✓ Using existing Passage identity as default\n")

				// Add to recipients
				identity, err := loadDefaultIdentity()
				if err == nil {
					if err := addRecipient(identity.Recipient()); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to add recipient: %v\n", err)
					}
				}

				return nil
			}
			// User declined or selected to create new, continue to generateIdentity
		}
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

	// Check if passage is installed, prompt to create structure if not
	home, err := os.UserHomeDir()
	if err == nil {
		passageDir := filepath.Join(home, ".passage")
		if _, err := os.Stat(passageDir); err != nil && os.IsNotExist(err) {
			fmt.Println()
			fmt.Println("Note: Passage is not installed (~/.passage not found).")
			fmt.Print("Would you like to create ~/.passage folder for passage integration? [y/N]: ")

			var response string
			fmt.Scanln(&response)

			if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
				// Create passage directory structure
				if err := os.MkdirAll(passageDir, 0700); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to create ~/.passage: %v\n", err)
				} else {
					storeDir := filepath.Join(passageDir, "store")
					if err := os.MkdirAll(storeDir, 0700); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to create ~/.passage/store: %v\n", err)
					} else {
						// Add this identity to passage
						if err := addToPassageIdentities(identity); err != nil {
							fmt.Fprintf(os.Stderr, "Warning: failed to add to passage: %v\n", err)
						} else {
							fmt.Println("✓ Created ~/.passage folder and synced identity")
						}
					}
				}
			}
		}
	}

	return nil
}

// findExistingPassageIdentities looks for existing identities in ~/.passage/identities file
// IdentityInfo holds information about an identity found in the passage file
type IdentityInfo struct {
	Index      int
	Created    string
	PublicKey  string
	FilePath   string
	RawContent string
}

// findExistingPassageIdentities looks for existing identities in ~/.passage/identities file
// findExistingPassageIdentities looks for existing identities in ~/.passage/identities file
func findExistingPassageIdentities() ([]IdentityInfo, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	passageDir := filepath.Join(home, ".passage")

	// Check if .passage folder exists - if not, passage is not installed
	info, err := os.Stat(passageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("passage is not installed (no ~/.passage folder found)")
		}
		return nil, fmt.Errorf("cannot access ~/.passage: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("~/.passage is not a directory")
	}

	// Check for identities file (not folder)
	identitiesFile := filepath.Join(passageDir, "identities")
	info, err = os.Stat(identitiesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("passage identities file not found")
		}
		return nil, fmt.Errorf("cannot access passage identities file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("~/.passage/identities is a directory, expected a file")
	}

	// Check for store folder
	storeDir := filepath.Join(passageDir, "store")
	info, err = os.Stat(storeDir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("passage store folder not found")
	}

	// Read the identities file content
	content, err := os.ReadFile(identitiesFile)
	if err != nil {
		return nil, err
	}

	// Parse the file to extract individual identities with their metadata
	var identities []IdentityInfo
	lines := strings.Split(string(content), "\n")

	var currentIdentity *IdentityInfo
	var currentContent []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for created comment
		if strings.HasPrefix(trimmed, "# created:") {
			// Start of a new identity
			if currentIdentity != nil && len(currentContent) > 0 {
				currentIdentity.RawContent = strings.Join(currentContent, "\n")
				identities = append(identities, *currentIdentity)
			}
			currentIdentity = &IdentityInfo{
				Index:    len(identities),
				FilePath: identitiesFile,
			}
			currentContent = []string{line}
			// Extract created date
			if idx := strings.Index(trimmed, ":"); idx != -1 {
				currentIdentity.Created = strings.TrimSpace(trimmed[idx+1:])
			}
		} else if strings.HasPrefix(trimmed, "# public key:") && currentIdentity != nil {
			currentContent = append(currentContent, line)
			// Extract public key
			if idx := strings.Index(trimmed, ":"); idx != -1 {
				currentIdentity.PublicKey = strings.TrimSpace(trimmed[idx+1:])
			}
		} else if strings.HasPrefix(trimmed, "AGE-SECRET-KEY-") && currentIdentity != nil {
			currentContent = append(currentContent, line)
		} else if trimmed == "" {
			// Empty line - end of current identity
			if currentIdentity != nil && len(currentContent) > 0 {
				currentIdentity.RawContent = strings.Join(currentContent, "\n")
				identities = append(identities, *currentIdentity)
				currentIdentity = nil
				currentContent = nil
			}
		} else if currentIdentity != nil {
			currentContent = append(currentContent, line)
		}
	}

	// Don't forget the last identity
	if currentIdentity != nil && len(currentContent) > 0 {
		currentIdentity.RawContent = strings.Join(currentContent, "\n")
		identities = append(identities, *currentIdentity)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities found in .passage/identities")
	}

	return identities, nil
}

// copyExistingIdentity copies a specific identity from the passage identities file
func copyExistingIdentity(identityInfo IdentityInfo, identityName string) error {
	// Ensure identities directory exists
	if err := ensureDir(identitiesDir()); err != nil {
		return fmt.Errorf("failed to create identities directory: %w", err)
	}

	// Write the identity content to the destination
	destPath := filepath.Join(identitiesDir(), identityName+".txt")
	content := identityInfo.RawContent
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(destPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	// Also save the public key
	destPubPath := filepath.Join(identitiesDir(), identityName+".pub")
	if identityInfo.PublicKey != "" {
		pubKeyContent := identityInfo.PublicKey
		if !strings.HasSuffix(pubKeyContent, "\n") {
			pubKeyContent += "\n"
		}
		if err := os.WriteFile(destPubPath, []byte(pubKeyContent), 0644); err != nil {
			return fmt.Errorf("failed to write public key file: %w", err)
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

// syncIdentitiesCommand syncs all docker-credential-passage identities to passage
// syncIdentitiesCommand syncs all docker-credential-passage identities to passage
// syncIdentitiesCommand syncs all docker-credential-passage identities to passage
func syncIdentitiesCommand() error {
	// Check if passage binary exists in PATH
	passageInstalled := isPassageInstalled()

	// Check if passage directory exists
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	passageDir := filepath.Join(home, ".passage")
	dirExists := false
	if _, err := os.Stat(passageDir); err == nil {
		dirExists = true
	}

	// If neither binary nor directory exists, ask user
	if !passageInstalled && !dirExists {
		fmt.Println("Passage is not detected:")
		fmt.Println("  - passage binary not found in PATH")
		fmt.Println("  - ~/.passage folder not found")
		fmt.Println()
		fmt.Println("To install passage, visit: https://github.com/FiloSottile/passage")
		fmt.Println()
		fmt.Print("Would you like to create ~/.passage folder for passage integration? [y/N]: ")

		var response string
		fmt.Scanln(&response)

		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Sync cancelled. Identities remain in docker-credential-passage only.")
			return nil
		}

		// Create passage directory structure
		if err := os.MkdirAll(passageDir, 0700); err != nil {
			return fmt.Errorf("failed to create ~/.passage directory: %w", err)
		}

		storeDir := filepath.Join(passageDir, "store")
		if err := os.MkdirAll(storeDir, 0700); err != nil {
			return fmt.Errorf("failed to create ~/.passage/store directory: %w", err)
		}

		fmt.Println("✓ Created ~/.passage folder structure")
		fmt.Println("Note: You will need to install passage to use these identities.")
		fmt.Println("      Visit: https://github.com/FiloSottile/passage")
	} else if !passageInstalled {
		// Directory exists but binary not found
		fmt.Println("Note: passage binary not found in PATH, but ~/.passage folder exists.")
		fmt.Println("      You may need to install passage to use these identities.")
		fmt.Println("      Visit: https://github.com/FiloSottile/passage")
		fmt.Println()
	}

	// Get all identities from docker-credential-passage
	identitiesDir := identitiesDir()
	entries, err := os.ReadDir(identitiesDir)
	if err != nil {
		return fmt.Errorf("failed to read identities directory: %w", err)
	}

	var syncedCount int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".txt") {
			continue
		}

		identityName := strings.TrimSuffix(name, ".txt")
		identityPath := filepath.Join(identitiesDir, name)

		// Read the identity
		content, err := os.ReadFile(identityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read identity %s: %v\n", identityName, err)
			continue
		}

		// Parse it to get public key
		identity, err := age.ParseX25519Identity(strings.TrimSpace(string(content)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse identity %s: %v\n", identityName, err)
			continue
		}

		// Add to passage
		if err := addToPassageIdentities(identity); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to sync identity %s: %v\n", identityName, err)
			continue
		}

		syncedCount++
		fmt.Printf("✓ Synced identity: %s\n", identityName)
	}

	fmt.Printf("\n✓ Synced %d identity(ies) to ~/.passage/identities\n", syncedCount)
	return nil
}

// isPassageInstalled checks if the passage binary exists in PATH
func isPassageInstalled() bool {
	_, err := exec.LookPath("passage")
	return err == nil
}
