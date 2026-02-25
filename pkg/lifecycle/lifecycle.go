// Package lifecycle provides cryptographic key lifecycle management.
package lifecycle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// KeyAlgorithm represents supported key algorithms.
type KeyAlgorithm string

const (
	AlgorithmRSA      KeyAlgorithm = "rsa"
	AlgorithmECDSA    KeyAlgorithm = "ecdsa"
	AlgorithmAES      KeyAlgorithm = "aes"
	AlgorithmChaCha20 KeyAlgorithm = "chacha20"
	AlgorithmEd25519  KeyAlgorithm = "ed25519"
)

// KeyStatus represents key lifecycle status.
type KeyStatus string

const (
	StatusGenerated   KeyStatus = "generated"
	StatusActive      KeyStatus = "active"
	StatusDeprecated  KeyStatus = "deprecated"
	StatusRevoked     KeyStatus = "revoked"
	StatusDestroyed   KeyStatus = "destroyed"
)

// KeyUsage represents key usage purposes.
type KeyUsage string

const (
	UsageEncryption   KeyUsage = "encryption"
	UsageDecryption   KeyUsage = "decryption"
	UsageSignature    KeyUsage = "signature"
	UsageVerify       KeyUsage = "verify"
	UsageKeyAgreement KeyUsage = "key_agreement"
	UsageAll          KeyUsage = "all"
)

// KeyLifecycle represents a key's lifecycle information.
type KeyLifecycle struct {
	ID             string
	Algorithm      KeyAlgorithm
	KeySize        int
	Status         KeyStatus
	CreatedAt      time.Time
	ActivatedAt    time.Time
	DeactivatedAt  *time.Time
	ExpiresAt      time.Time
	RotatedAt      []time.Time
	DestroyedAt    *time.Time
	Usage          []KeyUsage
	Owner          string
	Description    string
	Metadata       map[string]string
}

// Key represents a cryptographic key.
type Key struct {
	ID          string
	PublicKey   interface{}
	PrivateKey  interface{}
	Lifecycle   *KeyLifecycle
	Algorithm   KeyAlgorithm
	KeySize     int
	Status      KeyStatus
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// KeyLifecycleManager manages key lifecycle.
type KeyLifecycleManager struct {
	keys     map[string]*Key
	policies map[string]KeyPolicy
}

// KeyPolicy represents a key policy.
type KeyPolicy struct {
	ID                string
	Name              string
	MinKeySize        int
	MaxKeySize        int
	AllowedAlgorithms []KeyAlgorithm
	MaxLifetime       time.Duration
	MinRotationPeriod time.Duration
	MaxRotationPeriod time.Duration
	AllowedUsages     []KeyUsage
	RequireRotation   bool
	AutoRotate        bool
}

// NewKeyLifecycleManager creates a new key lifecycle manager.
func NewKeyLifecycleManager() *KeyLifecycleManager {
	return &KeyLifecycleManager{
		keys:     make(map[string]*Key),
		policies: make(map[string]KeyPolicy),
	}
}

// AddKey adds a key to the manager.
func (m *KeyLifecycleManager) AddKey(key *Key) error {
	if key.ID == "" {
		return fmt.Errorf("key ID is required")
	}

	if key.Status != StatusGenerated && key.Status != StatusActive {
		return fmt.Errorf("invalid key status: %s", key.Status)
	}

	m.keys[key.ID] = key
	return nil
}

// GetKey returns a key by ID.
func (m *KeyLifecycleManager) GetKey(keyID string) (*Key, error) {
	key, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

// ListKeys returns all keys.
func (m *KeyLifecycleManager) ListKeys() []*Key {
	keys := make([]*Key, 0, len(m.keys))
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys
}

// ListActiveKeys returns active keys.
func (m *KeyLifecycleManager) ListActiveKeys() []*Key {
	var activeKeys []*Key
	for _, key := range m.keys {
		if key.Status == StatusActive {
			activeKeys = append(activeKeys, key)
		}
	}
	return activeKeys
}

// GenerateKey generates a new cryptographic key.
func (m *KeyLifecycleManager) GenerateKey(algorithm KeyAlgorithm, keySize int, usage []KeyUsage) (*Key, error) {
	// Validate algorithm
	if !isValidAlgorithm(algorithm) {
		return nil, fmt.Errorf("invalid algorithm: %s", algorithm)
	}

	// Validate key size
	if !isValidKeySize(algorithm, keySize) {
		return nil, fmt.Errorf("invalid key size for %s: %d", algorithm, keySize)
	}

	// Validate usage
	if !isValidUsage(usage) {
		return nil, fmt.Errorf("invalid key usage")
	}

	// Generate key
	var publicKey, privateKey interface{}
	var err error

	switch algorithm {
	case AlgorithmRSA:
		publicKey, privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case AlgorithmECDSA:
		// In production: use elliptic curve
		publicKey, privateKey, err = generateECKey(keySize)
	case AlgorithmAES:
		// In production: generate AES key
		publicKey, privateKey, err = generateAESKey(keySize)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	// Create key
	key := &Key{
		ID:         fmt.Sprintf("key-%d", time.Now().UnixNano()),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Algorithm:  algorithm,
		KeySize:    keySize,
		Status:     StatusGenerated,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour), // Default 1 year
		Lifecycle: &KeyLifecycle{
			ID:        fmt.Sprintf("lifecycle-%d", time.Now().UnixNano()),
			Algorithm: algorithm,
			KeySize:   keySize,
			Status:    StatusGenerated,
			CreatedAt: time.Now(),
			Usage:     usage,
			Metadata:  make(map[string]string),
		},
	}

	// Add to manager
	m.keys[key.ID] = key

	return key, nil
}

// ActivateKey activates a key.
func (m *KeyLifecycleManager) ActivateKey(keyID string) error {
	key, err := m.GetKey(keyID)
	if err != nil {
		return err
	}

	if key.Status != StatusGenerated {
		return fmt.Errorf("key must be in generated status: %s", key.Status)
	}

	key.Status = StatusActive
	key.Lifecycle.Status = StatusActive
	key.Lifecycle.ActivatedAt = &time.Now()

	return nil
}

// DeactivateKey deactivates a key.
func (m *KeyLifecycleManager) DeactivateKey(keyID string) error {
	key, err := m.GetKey(keyID)
	if err != nil {
		return err
	}

	if key.Status != StatusActive {
		return fmt.Errorf("key must be in active status: %s", key.Status)
	}

	key.Status = StatusDeprecated
	key.Lifecycle.Status = StatusDeprecated
	now := time.Now()
	key.Lifecycle.DeactivatedAt = &now

	return nil
}

// RevokeKey revokes a key.
func (m *KeyLifecycleManager) RevokeKey(keyID string, reason string) error {
	key, err := m.GetKey(keyID)
	if err != nil {
		return err
	}

	if key.Lifecycle.Metadata == nil {
		key.Lifecycle.Metadata = make(map[string]string)
	}
	key.Lifecycle.Metadata["revocation_reason"] = reason

	key.Status = StatusRevoked
	key.Lifecycle.Status = StatusRevoked
	now := time.Now()
	key.Lifecycle.DeactivatedAt = &now

	return nil
}

// DestroyKey destroys a key.
func (m *KeyLifecycleManager) DestroyKey(keyID string) error {
	key, err := m.GetKey(keyID)
	if err != nil {
		return err
	}

	if key.Status != StatusRevoked && key.Status != StatusDeprecated {
		return fmt.Errorf("key must be revoked or deprecated before destruction: %s", key.Status)
	}

	// Clear private key
	key.PrivateKey = nil

	key.Status = StatusDestroyed
	key.Lifecycle.Status = StatusDestroyed
	now := time.Now()
	key.Lifecycle.DestroyedAt = &now

	return nil
}

// RotateKey rotates a key.
func (m *KeyLifecycleManager) RotateKey(keyID string) (*Key, error) {
	key, err := m.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	if key.Status != StatusActive {
		return nil, fmt.Errorf("key must be active for rotation: %s", key.Status)
	}

	// Generate new key
	newKey, err := m.GenerateKey(key.Algorithm, key.KeySize, key.Lifecycle.Usage)
	if err != nil {
		return nil, err
	}

	// Set rotation metadata
	now := time.Now()
	newKey.Lifecycle.OldKeyID = key.ID
	newKey.Lifecycle.RotatedAt = append(newKey.Lifecycle.RotatedAt, now)

	// Activate new key
	newKey.Status = StatusActive
	newKey.Lifecycle.Status = StatusActive
	newKey.Lifecycle.ActivatedAt = &now

	// Add new key
	m.keys[newKey.ID] = newKey

	return newKey, nil
}

// CheckKeyExpiration checks if keys have expired.
func (m *KeyLifecycleManager) CheckKeyExpiration() []*Key {
	var expiredKeys []*Key
	now := time.Now()

	for _, key := range m.keys {
		if key.Status == StatusActive && now.After(key.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	return expiredKeys
}

// AddPolicy adds a key policy.
func (m *KeyLifecycleManager) AddPolicy(policy KeyPolicy) {
	m.policies[policy.ID] = policy
}

// GetPolicy returns a policy by ID.
func (m *KeyLifecycleManager) GetPolicy(policyID string) (*KeyPolicy, error) {
	policy, ok := m.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	return &policy, nil
}

// ListPolicies returns all policies.
func (m *KeyLifecycleManager) ListPolicies() []KeyPolicy {
	policies := make([]KeyPolicy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}
	return policies
}

// ValidateKeyAgainstPolicy validates a key against a policy.
func (m *KeyLifecycleManager) ValidateKeyAgainstPolicy(keyID, policyID string) (bool, []string) {
	key, err := m.GetKey(keyID)
	if err != nil {
		return false, []string{fmt.Sprintf("Key not found: %s", keyID)}
	}

	policy, err := m.GetPolicy(policyID)
	if err != nil {
		return false, []string{fmt.Sprintf("Policy not found: %s", policyID)}
	}

	var issues []string

	// Check algorithm
	if !containsKeyAlgorithm(policy.AllowedAlgorithms, key.Algorithm) {
		issues = append(issues, fmt.Sprintf("Algorithm %s not allowed by policy", key.Algorithm))
	}

	// Check key size
	if key.KeySize < policy.MinKeySize || key.KeySize > policy.MaxKeySize {
		issues = append(issues, fmt.Sprintf("Key size %d not within policy range (%d-%d)", key.KeySize, policy.MinKeySize, policy.MaxKeySize))
	}

	// Check usage
	if !containsKeyUsage(policy.AllowedUsages, KeyUsageAll) {
		for _, usage := range key.Lifecycle.Usage {
			if !containsKeyUsage(policy.AllowedUsages, usage) {
				issues = append(issues, fmt.Sprintf("Usage %s not allowed by policy", usage))
			}
		}
	}

	return len(issues) == 0, issues
}

// ExportKeyPEM exports a key in PEM format.
func (m *KeyLifecycleManager) ExportKeyPEM(keyID string) ([]byte, error) {
	key, err := m.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	// In production: export actual key
	// For demo: return placeholder
	return []byte("-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----"), nil
}

// ImportKeyPEM imports a key from PEM format.
func (m *KeyLifecycleManager) ImportKeyPEM(pemData []byte, usage []KeyUsage) (*Key, error) {
	// In production: import actual key
	// For demo: create placeholder key
	key := &Key{
		ID:         fmt.Sprintf("imported-%d", time.Now().UnixNano()),
		Algorithm:  AlgorithmRSA,
		KeySize:    2048,
		Status:     StatusGenerated,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
		Lifecycle: &KeyLifecycle{
			ID:        fmt.Sprintf("lifecycle-imported-%d", time.Now().UnixNano()),
			Algorithm: AlgorithmRSA,
			KeySize:   2048,
			Status:    StatusGenerated,
			CreatedAt: time.Now(),
			Usage:     usage,
			Metadata:  make(map[string]string),
		},
	}

	m.keys[key.ID] = key
	return key, nil
}

// isValidAlgorithm checks if algorithm is valid.
func isValidAlgorithm(algorithm KeyAlgorithm) bool {
	validAlgorithms := []KeyAlgorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmAES, AlgorithmChaCha20, AlgorithmEd25519}
	for _, valid := range validAlgorithms {
		if algorithm == valid {
			return true
		}
	}
	return false
}

// isValidKeySize checks if key size is valid for algorithm.
func isValidKeySize(algorithm KeyAlgorithm, keySize int) bool {
	switch algorithm {
	case AlgorithmRSA:
		return keySize >= 2048 && keySize <= 8192
	case AlgorithmECDSA:
		return keySize >= 256 && keySize <= 521
	case AlgorithmAES:
		return keySize == 128 || keySize == 192 || keySize == 256
	default:
		return keySize > 0
	}
}

// isValidUsage checks if key usage is valid.
func isValidUsage(usages []KeyUsage) bool {
	if len(usages) == 0 {
		return false
	}
	validUsages := map[KeyUsage]bool{
		UsageEncryption: true, UsageDecryption: true,
		UsageSignature: true, UsageVerify: true,
		UsageKeyAgreement: true, UsageAll: true,
	}
	for _, usage := range usages {
		if !validUsages[usage] {
			return false
		}
	}
	return true
}

// containsKeyAlgorithm checks if slice contains algorithm.
func containsKeyAlgorithm(slice []KeyAlgorithm, item KeyAlgorithm) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// containsKeyUsage checks if slice contains usage.
func containsKeyUsage(slice []KeyUsage, item KeyUsage) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GenerateCommonPolicies generates common key policies.
func GenerateCommonPolicies() []KeyPolicy {
	return []KeyPolicy{
		{
			ID:                "policy-rsa-2048",
			Name:              "RSA 2048 Standard",
			MinKeySize:        2048,
			MaxKeySize:        2048,
			AllowedAlgorithms: []KeyAlgorithm{AlgorithmRSA},
			MaxLifetime:       365 * 24 * time.Hour,
			MinRotationPeriod: 90 * 24 * time.Hour,
			MaxRotationPeriod: 180 * 24 * time.Hour,
			AllowedUsages:     []KeyUsage{UsageEncryption, UsageDecryption, UsageSignature, UsageVerify},
			RequireRotation:   true,
			AutoRotate:        false,
		},
		{
			ID:                "policy-rsa-4096",
			Name:              "RSA 4098 High Security",
			MinKeySize:        4096,
			MaxKeySize:        4096,
			AllowedAlgorithms: []KeyAlgorithm{AlgorithmRSA},
			MaxLifetime:       730 * 24 * time.Hour,
			MinRotationPeriod: 180 * 24 * time.Hour,
			MaxRotationPeriod: 365 * 24 * time.Hour,
			AllowedUsages:     []KeyUsage{UsageEncryption, UsageDecryption, UsageSignature, UsageVerify},
			RequireRotation:   true,
			AutoRotate:        true,
		},
		{
			ID:                "policy-aes-256",
			Name:              "AES-256 Symmetric",
			MinKeySize:        256,
			MaxKeySize:        256,
			AllowedAlgorithms: []KeyAlgorithm{AlgorithmAES},
			MaxLifetime:       180 * 24 * time.Hour,
			MinRotationPeriod: 30 * 24 * time.Hour,
			MaxRotationPeriod: 90 * 24 * time.Hour,
			AllowedUsages:     []KeyUsage{UsageEncryption, UsageDecryption},
			RequireRotation:   true,
			AutoRotate:        true,
		},
	}
}

// GenerateReport generates lifecycle report.
func (m *KeyLifecycleManager) GenerateReport() string {
	keys := m.ListKeys()

	var report string
	report += "=== Key Lifecycle Report ===\n\n"

	report += "Total Keys: " + fmt.Sprintf("%d\n", len(keys))

	activeCount := 0
	generatedCount := 0
	deprecatedCount := 0
	revokedCount := 0
	destroyedCount := 0
	for _, key := range keys {
		switch key.Status {
		case StatusActive:
			activeCount++
		case StatusGenerated:
			generatedCount++
		case StatusDeprecated:
			deprecatedCount++
		case StatusRevoked:
			revokedCount++
		case StatusDestroyed:
			destroyedCount++
		}
	}

	report += "Active: " + fmt.Sprintf("%d\n", activeCount)
	report += "Generated: " + fmt.Sprintf("%d\n", generatedCount)
	report += "Deprecated: " + fmt.Sprintf("%d\n", deprecatedCount)
	report += "Revoked: " + fmt.Sprintf("%d\n", revokedCount)
	report += "Destroyed: " + fmt.Sprintf("%d\n", destroyedCount)

	if len(keys) > 0 {
		report += "\nKey Details:\n"
		for i, key := range keys {
			report += fmt.Sprintf("\n[%d] %s\n", i+1, key.ID)
			report += "    Algorithm: " + string(key.Algorithm) + "\n"
			report += "    Key Size: " + fmt.Sprintf("%d bits\n", key.KeySize)
			report += "    Status: " + string(key.Status) + "\n"
			report += "    Created: " + key.CreatedAt.Format("2006-01-02 15:04:05") + "\n"
			report += "    Expires: " + key.ExpiresAt.Format("2006-01-02 15:04:05") + "\n"
		}
	}

	return report
}

// GetLifecycle returns lifecycle.
func GetLifecycle(lifecycle *KeyLifecycle) *KeyLifecycle {
	return lifecycle
}

// GetKey returns key.
func GetKey(key *Key) *Key {
	return key
}