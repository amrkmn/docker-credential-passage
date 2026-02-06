# docker-credential-passage

Secure Docker credential storage using [age](https://age-encryption.org) encryption. **Pure Go** implementation with **zero external dependencies**.

## Features

- 🔐 **Zero dependencies** - Uses `filippo.io/age` Go package
- 📦 **Single binary** - Download and run, no installation needed
- 🔑 **Multiple identities** - Support for different encryption keys
- 🐳 **Docker compatible** - Full credential helper protocol

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh
```

Or install to a custom directory:
```bash
INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh
```

### Build from Source

```bash
git clone https://github.com/amrkmn/docker-credential-passage.git
cd docker-credential-passage
go build -o bin/docker-credential-passage passage/cmd/main.go
```

## Quick Start

### 1. Create Identity

Generate your encryption key:

```bash
docker-credential-passage setup identity
```

**⚠️ Backup this file**: `~/.docker-credential-passage/identities/default.txt`

### 2. Configure Docker

Edit `~/.docker/config.json`:

```json
{
  "credsStore": "passage"
}
```

### 3. Login

```bash
docker login registry.example.com
```

## Commands

```bash
# Setup
docker-credential-passage setup              # Show setup info
docker-credential-passage setup identity     # Create identity
docker-credential-passage identities         # List identities

# Docker operations
docker-credential-passage store              # Store credentials (from stdin)
docker-credential-passage get                # Get credentials (from stdin)
docker-credential-passage erase              # Delete credentials (from stdin)
docker-credential-passage list               # List all credentials
docker-credential-passage version            # Show version
```

## Environment Variables

- `DOCKER_CREDENTIAL_PASSAGE_IDENTITY` - Active identity name (default: `default`)
- `DOCKER_CREDENTIAL_PASSAGE_DIR` - Config directory (default: `~/.docker-credential-passage`)
- `PASSAGE_DIR` - Storage location (default: `~/.passage/store`)

## Multiple Identities

Use different keys for different registries:

```bash
# Create work identity
docker-credential-passage setup identity work

# Use it
DOCKER_CREDENTIAL_PASSAGE_IDENTITY=work docker login company.registry.com
```

## Storage Location

```
~/.docker-credential-passage/
├── identities/
│   ├── default.txt         # Private key (BACKUP THIS!)
│   └── work.txt            # Additional identities
└── store/.age-recipients   # Encryption recipients

~/.passage/store/
└── docker-credential-helpers/
    └── <base64-url>/
        └── username.age    # Encrypted credentials
```

## Optional: Use with Passage CLI

To access Docker credentials via passage:

```bash
# Add Docker's public key to passage
cat ~/.docker-credential-passage/identities/default.pub >> ~/.passage/store/.age-recipients

# Then use passage CLI
passage show docker-credential-helpers/<encoded-url>/username
```

## Troubleshooting

**"identity error: failed to open identity file"**
→ Run `docker-credential-passage setup identity`

**"credentials not found"**
→ Login first: `docker login registry.example.com`

**Lost identity file?**
→ Credentials are **permanently lost** with no recovery. Always backup your identity file!

## License

MIT License
