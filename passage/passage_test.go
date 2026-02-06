package passage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/amrkmn/docker-credential-passage/credentials"
)

func TestPassageVersion(t *testing.T) {
	p := Passage{}
	version := p.Version()
	if version == "" {
		t.Error("Version should not be empty")
	}
	// Check version is either "dev" or in semver format (e.g., 0.1.3)
	if version != "dev" {
		matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+`, version)
		if !matched {
			t.Error("Version should be 'dev' or in semver format (e.g., 0.1.3)")
		}
	}
}

func TestEncodeDecodeServerURL(t *testing.T) {
	testURL := "https://example.com"

	encoded := encodeServerURL(testURL)
	if encoded == "" {
		t.Error("encoded URL should not be empty")
	}

	decoded, err := decodeServerURL(encoded)
	if err != nil {
		t.Errorf("decode failed: %v", err)
	}

	if decoded != testURL {
		t.Errorf("expected %s, got %s", testURL, decoded)
	}
}

func TestPassageAddNilCredentials(t *testing.T) {
	p := Passage{}
	err := p.Add(nil)
	if err == nil {
		t.Error("expected error for nil credentials")
	}
	if !strings.Contains(err.Error(), "missing credentials") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPassageDeleteEmptyURL(t *testing.T) {
	p := Passage{}
	err := p.Delete("")
	if err == nil {
		t.Error("expected error for empty server URL")
	}
	if !strings.Contains(err.Error(), "missing server URL") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPassageGetEmptyURL(t *testing.T) {
	p := Passage{}
	_, _, err := p.Get("")
	if err == nil {
		t.Error("expected error for empty server URL")
	}
	if !strings.Contains(err.Error(), "missing server URL") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIdentityManagement(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()
	t.Setenv("DOCKER_CREDENTIAL_PASSAGE_DIR", tmpDir)

	t.Run("GenerateIdentity", func(t *testing.T) {
		identity, err := generateIdentity("test")
		if err != nil {
			t.Fatalf("Failed to generate identity: %v", err)
		}

		// Verify identity file exists
		identityPath := filepath.Join(identitiesDir(), "test.txt")
		if _, err := os.Stat(identityPath); os.IsNotExist(err) {
			t.Errorf("Identity file not created: %s", identityPath)
		}

		// Verify public key file exists
		publicPath := publicKeyPath("test")
		if _, err := os.Stat(publicPath); os.IsNotExist(err) {
			t.Errorf("Public key file not created: %s", publicPath)
		}

		// Verify we can load it back
		loaded, err := loadIdentity("test")
		if err != nil {
			t.Fatalf("Failed to load identity: %v", err)
		}

		// Verify the loaded identity matches
		if loaded.String() != identity.String() {
			t.Error("Loaded identity doesn't match generated identity")
		}
	})

	t.Run("LoadIdentityNotFound", func(t *testing.T) {
		_, err := loadIdentity("nonexistent")
		if err == nil {
			t.Error("expected error for non-existent identity")
		}
	})

	t.Run("ListIdentities", func(t *testing.T) {
		// Create another identity
		if _, err := generateIdentity("another"); err != nil {
			t.Fatalf("Failed to generate second identity: %v", err)
		}

		identities, err := listIdentities()
		if err != nil {
			t.Fatalf("Failed to list identities: %v", err)
		}

		if len(identities) != 2 {
			t.Errorf("expected 2 identities, got %d", len(identities))
		}

		// Check that both identities are in the list
		found := make(map[string]bool)
		for _, id := range identities {
			found[id] = true
		}
		if !found["test"] || !found["another"] {
			t.Error("Expected identities not found in list")
		}
	})

	t.Run("DuplicateIdentity", func(t *testing.T) {
		_, err := generateIdentity("test")
		if err == nil {
			t.Error("expected error for duplicate identity")
		}
	})
}

func TestRecipientManagement(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()
	t.Setenv("DOCKER_CREDENTIAL_PASSAGE_DIR", tmpDir)

	t.Run("EnsureRecipients", func(t *testing.T) {
		// Generate default identity first
		identity, err := generateIdentity("default")
		if err != nil {
			t.Fatalf("Failed to generate default identity: %v", err)
		}

		// Ensure recipients
		if err := ensureRecipients(); err != nil {
			t.Fatalf("Failed to ensure recipients: %v", err)
		}

		// Verify recipients file exists
		if _, err := os.Stat(recipientsPath()); os.IsNotExist(err) {
			t.Errorf("Recipients file not created")
		}

		// Load and verify
		recipients, err := loadRecipients()
		if err != nil {
			t.Fatalf("Failed to load recipients: %v", err)
		}

		if len(recipients) != 1 {
			t.Errorf("expected 1 recipient, got %d", len(recipients))
		}

		// Verify it matches the default identity
		defaultRecipient := identity.Recipient().String()
		if recipients[0].(*age.X25519Recipient).String() != defaultRecipient {
			t.Error("Recipient doesn't match default identity")
		}
	})

	t.Run("AddRecipient", func(t *testing.T) {
		// Generate another identity
		identity2, err := generateIdentity("second")
		if err != nil {
			t.Fatalf("Failed to generate second identity: %v", err)
		}

		// Add as recipient
		if err := addRecipient(identity2.Recipient()); err != nil {
			t.Fatalf("Failed to add recipient: %v", err)
		}

		// Verify it was added
		recipients, err := loadRecipients()
		if err != nil {
			t.Fatalf("Failed to load recipients: %v", err)
		}

		if len(recipients) != 2 {
			t.Errorf("expected 2 recipients, got %d", len(recipients))
		}
	})

	t.Run("RemoveRecipient", func(t *testing.T) {
		// Get second identity's recipient string
		identity2, _ := loadIdentity("second")
		recipientStr := identity2.Recipient().String()

		// Remove it
		if err := removeRecipient(recipientStr); err != nil {
			t.Fatalf("Failed to remove recipient: %v", err)
		}

		// Verify it was removed
		recipients, err := loadRecipients()
		if err != nil {
			t.Fatalf("Failed to load recipients: %v", err)
		}

		if len(recipients) != 1 {
			t.Errorf("expected 1 recipient after removal, got %d", len(recipients))
		}
	})
}

func TestEncryptionDecryption(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()
	t.Setenv("DOCKER_CREDENTIAL_PASSAGE_DIR", tmpDir)

	t.Run("EncryptAndDecrypt", func(t *testing.T) {
		// Generate identity
		identity, err := generateIdentity("default")
		if err != nil {
			t.Fatalf("Failed to generate identity: %v", err)
		}

		// Create recipients
		recipients := []age.Recipient{identity.Recipient()}

		// Test content
		testContent := "my-secret-password-123"
		testPath := filepath.Join(tmpDir, "test.age")

		// Encrypt
		if err := encryptAndSave(testPath, testContent, recipients); err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(testPath); os.IsNotExist(err) {
			t.Error("Encrypted file not created")
		}

		// Decrypt
		decrypted, err := decryptAndRead(testPath, identity)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if decrypted != testContent {
			t.Errorf("decrypted content doesn't match: expected %q, got %q", testContent, decrypted)
		}
	})

	t.Run("DecryptWithWrongIdentity", func(t *testing.T) {
		// Generate two different identities
		identity1, _ := generateIdentity("first")
		identity2, _ := generateIdentity("second")

		// Encrypt with first identity's recipient
		recipients := []age.Recipient{identity1.Recipient()}
		testPath := filepath.Join(tmpDir, "wrong.age")
		if err := encryptAndSave(testPath, "secret", recipients); err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Try to decrypt with second identity (should fail)
		_, err := decryptAndRead(testPath, identity2)
		if err == nil {
			t.Error("expected error when decrypting with wrong identity")
		}
	})
}

func TestFullWorkflow(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("TEST_FULL_WORKFLOW") != "1" {
		t.Skip("Skipping full workflow test. Set TEST_FULL_WORKFLOW=1 to run")
	}

	// Create temporary directories
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")

	t.Setenv("DOCKER_CREDENTIAL_PASSAGE_DIR", tmpDir)
	t.Setenv("PASSAGE_DIR", storeDir)

	p := Passage{}

	t.Run("FullAddGetDeleteWorkflow", func(t *testing.T) {
		// Add credential
		creds := &credentials.Credentials{
			ServerURL: "https://test.example.com",
			Username:  "testuser",
			Secret:    "testsecret123",
		}

		err := p.Add(creds)
		if err != nil {
			t.Fatalf("Add failed: %v", err)
		}

		// Get credential
		username, secret, err := p.Get(creds.ServerURL)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if username != creds.Username {
			t.Errorf("expected username %s, got %s", creds.Username, username)
		}

		if secret != creds.Secret {
			t.Errorf("expected secret %s, got %s", creds.Secret, secret)
		}

		// List credentials
		list, err := p.List()
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(list) != 1 {
			t.Errorf("expected 1 credential, got %d", len(list))
		}

		if list[creds.ServerURL] != creds.Username {
			t.Error("Listed credential doesn't match")
		}

		// Delete credential
		err = p.Delete(creds.ServerURL)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Verify deletion
		_, _, err = p.Get(creds.ServerURL)
		if err == nil {
			t.Error("expected error for deleted credential")
		}
		if !strings.Contains(err.Error(), "credentials not found") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
