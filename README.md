# keyvault - Cryptographic Key Lifecycle Manager

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Complete cryptographic key lifecycle management with rotation and storage.**

Manage cryptographic keys throughout their entire lifecycle - generation, rotation, storage, and destruction.

## 🚀 Features

- **Key Generation**: Generate RSA, ECDSA, AES, and other cryptographic keys
- **Lifecycle Management**: Track key status from generation to destruction
- **Key Rotation**: Automated key rotation with configurable policies
- **Key Storage**: Secure key storage with multiple backend support
- **Policy Enforcement**: Enforce key policies for compliance
- **Comprehensive Reporting**: Detailed lifecycle and rotation reports

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/keyvault.git
cd keyvault
go build -o keyvault ./cmd/keyvault
sudo mv keyvault /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/keyvault/cmd/keyvault@latest
```

## 🎯 Usage

### Generate Key

```bash
# Generate a new cryptographic key
keyvault generate --algorithm rsa --key-size 2048
```

### List Keys

```bash
# List all keys in vault
keyvault list
```

### Rotate Key

```bash
# Rotate an existing key
keyvault rotate key-123
```

### Schedule Rotation

```bash
# Schedule key rotation
keyvault schedule key-123 --policy policy-90-days
```

### Check Rotations

```bash
# Check rotation schedules
keyvault check
```

### Export/Import Key

```bash
# Export a key
keyvault export key-123

# Import a key
keyvault import key.pem
```

### Generate Report

```bash
# Generate key vault report
keyvault report
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/keyvault/pkg/lifecycle"
    "github.com/hallucinaut/keyvault/pkg/storage"
    "github.com/hallucinaut/keyvault/pkg/rotation"
)

func main() {
    // Create lifecycle manager
    manager := lifecycle.NewKeyLifecycleManager()
    
    // Generate key
    key, err := manager.GenerateKey(lifecycle.AlgorithmRSA, 2048, []lifecycle.KeyUsage{
        lifecycle.UsageEncryption, lifecycle.UsageDecryption,
    })
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Generated key: %s\n", key.ID)
    
    // Activate key
    err = manager.ActivateKey(key.ID)
    if err != nil {
        panic(err)
    }
    
    // Store key
    keyStorage := storage.NewKeyStorage(&storage.StorageConfig{
        Backend: storage.BackendMemory,
    })
    
    metadata := storage.KeyMetadata{
        ID:        key.ID,
        Algorithm: string(key.Algorithm),
        KeySize:   key.KeySize,
    }
    
    keyData, _ := manager.ExportKeyPEM(key.ID)
    keyStorage.StoreKey(key.ID, keyData, metadata)
    
    // Set up rotation
    rotationManager := rotation.NewRotationManager()
    rotationManager.AddPolicy(rotation.CreateDefaultPolicy())
    
    schedule, _ := rotationManager.CreateSchedule(key.ID, "default")
    fmt.Printf("Next rotation: %s\n", schedule.NextRotation.Format("2006-01-02"))
    
    // Check rotation status
    overdue := rotationManager.GetOverdueKeys()
    fmt.Printf("Overdue keys: %d\n", len(overdue))
}
```

## 📚 Supported Algorithms

| Algorithm | Key Sizes | Use Case |
|-----------|-----------|----------|
| RSA | 2048, 3072, 4096 | Encryption, Signing |
| ECDSA | 256, 384, 521 | Signing, Key Agreement |
| AES | 128, 192, 256 | Symmetric Encryption |
| ChaCha20 | 256 | Stream Encryption |
| Ed25519 | 256 | Digital Signatures |

## 🏗️ Key Lifecycle States

| State | Description |
|-------|-------------|
| Generated | Key created but not yet active |
| Active | Key is in use |
| Deprecated | Key being phased out |
| Revoked | Key revoked due to compromise |
| Destroyed | Key securely deleted |

## 🔄 Rotation Policies

| Policy | Rotation Period | Max Rotations | Auto Rotate |
|--------|----------------|---------------|-------------|
| 90 Day | 90 days | 10 | No |
| 180 Day | 180 days | 8 | Yes |
| Annual | 365 days | 5 | Yes |

## 🏗️ Architecture

```
keyvault/
├── cmd/
│   └── keyvault/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── lifecycle/
│   │   ├── lifecycle.go    # Key lifecycle management
│   │   └── lifecycle_test.go # Unit tests
│   ├── storage/
│   │   ├── storage.go      # Key storage
│   │   └── storage_test.go # Unit tests
│   └── rotation/
│       ├── rotation.go     # Key rotation
│       └── rotation_test.go # Unit tests
└── README.md
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/lifecycle -run TestGenerateKey
```

## 📋 Example Output

```
$ keyvault generate

Generate Cryptographic Key
==========================

Available Policies:

[1] RSA 2048 Standard
    ID: policy-rsa-2048
    Algorithm: rsa
    Key Size: 2048
    Max Lifetime: 365h0m0s
    Auto Rotate: false

[2] RSA 4098 High Security
    ID: policy-rsa-4096
    Algorithm: rsa
    Key Size: 4096
    Max Lifetime: 730h0m0s
    Auto Rotate: true

Generating sample keys...

[1] Key Generated:
    ID: key-1234567890
    Algorithm: rsa
    Key Size: 2048 bits
    Status: generated
    Created: 2024-01-15 10:30:00
    Expires: 2025-01-15 10:30:00
```

## 🔒 Security Use Cases

- **Key Generation**: Generate secure cryptographic keys
- **Key Storage**: Store keys securely with encryption
- **Key Rotation**: Automatically rotate keys per policy
- **Key Lifecycle**: Track keys from creation to destruction
- **Compliance**: Meet regulatory key management requirements

## 🛡️ Best Practices

1. **Use strong algorithms**: Prefer RSA-4096, ECDSA-384, or AES-256
2. **Regular rotation**: Rotate keys every 90-180 days
3. **Secure storage**: Use HSM or encrypted storage
4. **Access control**: Limit key access to authorized personnel
5. **Audit logging**: Log all key operations
6. **Backup keys**: Maintain secure key backups
7. **Destroy properly**: Securely destroy old keys

## 📄 License

MIT License

## 🙏 Acknowledgments

- Cryptographic standards bodies
- Key management community
- Security professionals

## 🔗 Resources

- [NIST Key Management](https://csrc.nist.gov/projects/key-management)
- [RFC 8017 - PKCS #1](https://tools.ietf.org/html/rfc8017)
- [FIPS 186-4 - Digital Signature Standard](https://csrc.nist.gov/publications/detail/fips/186/4/final)

---

**build with GPU by [hallucinaut](https://github.com/hallucinaut)**