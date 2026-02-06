# Agent Guidelines for docker-credential-passage

## Project Overview
A Docker credential helper using age encryption. Written in Go 1.24.0 with zero external runtime dependencies.

## Build Commands

```bash
# Build the binary
go build -o bin/docker-credential-passage passage/cmd/main.go

# Build with release flags
go build -ldflags="-s -w" -o bin/docker-credential-passage passage/cmd/main.go

# Cross-compile (set GOOS/GOARCH)
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/docker-credential-passage passage/cmd/main.go
```

## Test Commands

```bash
# Run all tests
go test -v ./...

# Run tests for specific package
go test -v ./passage
go test -v ./credentials

# Run single test
go test -v ./passage -run TestPassageVersion
go test -v ./passage -run TestIdentityManagement/GenerateIdentity

# Run integration tests
TEST_FULL_WORKFLOW=1 go test -v ./passage -run TestFullWorkflow
```

## Lint/Format Commands

```bash
# Vet code
go vet ./...

# Check formatting (fails if unformatted)
gofmt -s -l .

# Auto-format code
gofmt -s -w .

# Tidy modules
go mod tidy
```

## Code Style Guidelines

### Formatting
- Use `gofmt` for all Go code
- Tabs for indentation (standard Go style)
- No trailing whitespace
- 80-100 character line limit preferred

### Imports
- Group imports: standard library, third-party, local
- Local imports use full module path: `github.com/amrkmn/docker-credential-passage/...`
- Example:
  ```go
  import (
      "bytes"
      "encoding/base64"
      "os"

      "filippo.io/age"

      "github.com/amrkmn/docker-credential-passage/credentials"
  )
  ```

### Naming Conventions
- **Packages**: lowercase, single word (e.g., `credentials`, `passage`)
- **Exported**: PascalCase (e.g., `Passage`, `Add`, `Credentials`)
- **Unexported**: camelCase (e.g., `ensureDir`, `loadIdentity`)
- **Constants**: camelCase or PascalCase (avoid ALL_CAPS)
- **Interfaces**: noun ending in "-er" (e.g., `Helper`, `ExtendedHelper`)
- **Test functions**: `Test` + function name (e.g., `TestPassageVersion`)
- **Test sub-tests**: Descriptive names using `t.Run()`

### Types
- Explicit error return types
- Struct tags for JSON: `` `json:"fieldName"` ``
- Interface definitions in dedicated files

### Error Handling
- Always check errors explicitly
- Wrap errors with context: `fmt.Errorf("context: %w", err)`
- Return early on errors
- Custom error types for specific cases:
  ```go
  type errCredentialsNotFound struct{}
  func (e errCredentialsNotFound) Error() string { return "..." }
  ```
- Use sentinel error functions (e.g., `ErrCredentialsNotFound()`)

### Functions
- Keep functions focused and under 50 lines when possible
- Use early returns to reduce nesting
- Document exported functions with comments starting with function name
- Group related functions with section comments: `// ==================== SECTION NAME ====================`

### Testing
- Use `t.TempDir()` for temporary directories
- Use `t.Setenv()` for environment variables in tests
- Table-driven tests with sub-tests using `t.Run()`
- Skip integration tests by default:
  ```go
  if os.Getenv("TEST_FULL_WORKFLOW") != "1" {
      t.Skip("...")
  }
  ```
- Check error messages contain expected text

### Project Structure
```
├── credentials/          # Credential helper interface
│   ├── credentials.go   # Types and errors
│   └── helper.go        # Helper interface and command handling
├── passage/             # Main implementation
│   ├── passage.go       # Core logic
│   ├── passage_test.go  # Tests
│   └── cmd/
│       └── main.go      # Entry point
├── .github/workflows/   # CI/CD
│   └── ci.yml
├── go.mod               # Module definition (Go 1.24.0)
└── bin/                 # Build output
```

### Environment Variables
- `DOCKER_CREDENTIAL_PASSAGE_IDENTITY`: Active identity name
- `DOCKER_CREDENTIAL_PASSAGE_DIR`: Config directory
- `PASSAGE_DIR`: Storage location

### Security
- Identity files: `0600` permissions
- Directories: `0700` permissions
- Public files: `0644` permissions
- Always use `defer` to close files

## CI/CD
The CI runs: `go test -v ./...`, `go build`, `go vet ./...`, and `gofmt` check.
