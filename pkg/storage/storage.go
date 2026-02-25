// Package storage provides key storage capabilities.
package storage

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StorageBackend represents a storage backend.
type StorageBackend string

const (
	BackendFile StorageBackend = "file"
	BackendMemory StorageBackend = "memory"
	BackendEncryption StorageBackend = "encryption"
	BackendHardware StorageBackend = "hardware"
)

// StorageConfig represents storage configuration.
type StorageConfig struct {
	Backend      StorageBackend
	Path         string
	EncryptionKey []byte
	MaxKeys      int
	CacheTTL     time.Duration
}

// KeyStorage manages key storage.
type KeyStorage struct {
	config    *StorageConfig
	keys      map[string][]byte // keyID -> key data
	lock      sync.RWMutex
	metadata  map[string]KeyMetadata
}

// KeyMetadata represents key metadata.
type KeyMetadata struct {
	ID          string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Algorithm   string
	KeySize     int
	Status      string
	Owner       string
	Description string
	Tags        []string
}

// NewKeyStorage creates a new key storage.
func NewKeyStorage(config *StorageConfig) *KeyStorage {
	if config == nil {
		config = &StorageConfig{
			Backend: BackendMemory,
		}
	}

	return &KeyStorage{
		config:   config,
		keys:     make(map[string][]byte),
		metadata: make(map[string]KeyMetadata),
	}
}

// SetConfig sets storage configuration.
func (s *KeyStorage) SetConfig(config *StorageConfig) {
	s.config = config
}

// GetConfig returns storage configuration.
func (s *KeyStorage) GetConfig() *StorageConfig {
	return s.config
}

// StoreKey stores a key.
func (s *KeyStorage) StoreKey(keyID string, keyData []byte, metadata KeyMetadata) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check max keys limit
	if s.config.MaxKeys > 0 && len(s.keys) >= s.config.MaxKeys {
		return fmt.Errorf("maximum keys limit reached: %d", s.config.MaxKeys)
	}

	// Store key data
	s.keys[keyID] = keyData

	// Store metadata
	metadata.UpdatedAt = time.Now()
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = time.Now()
	}
	s.metadata[keyID] = metadata

	return nil
}

// GetKey retrieves a key.
func (s *KeyStorage) GetKey(keyID string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	keyData, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return keyData, nil
}

// DeleteKey deletes a key.
func (s *KeyStorage) DeleteKey(keyID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.keys, keyID)
	delete(s.metadata, keyID)

	return nil
}

// ListKeys returns all key IDs.
func (s *KeyStorage) ListKeys() []string {
	s.lock.RLock()
	defer s.lock.RUnlock()

	keys := make([]string, 0, len(s.keys))
	for keyID := range s.keys {
		keys = append(keys, keyID)
	}

	return keys
}

// GetMetadata returns key metadata.
func (s *KeyStorage) GetMetadata(keyID string) (*KeyMetadata, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	metadata, ok := s.metadata[keyID]
	if !ok {
		return nil, fmt.Errorf("metadata not found: %s", keyID)
	}

	return &metadata, nil
}

// ListMetadata returns all key metadata.
func (s *KeyStorage) ListMetadata() []KeyMetadata {
	s.lock.RLock()
	defer s.lock.RUnlock()

	metadata := make([]KeyMetadata, 0, len(s.metadata))
	for _, m := range s.metadata {
		metadata = append(metadata, m)
	}

	return metadata
}

// UpdateMetadata updates key metadata.
func (s *KeyStorage) UpdateMetadata(keyID string, updates map[string]string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	metadata, ok := s.metadata[keyID]
	if !ok {
		return fmt.Errorf("metadata not found: %s", keyID)
	}

	// Update metadata
	for key, value := range updates {
		switch key {
		case "owner":
			metadata.Owner = value
		case "description":
			metadata.Description = value
		}
	}

	metadata.UpdatedAt = time.Now()
	s.metadata[keyID] = metadata

	return nil
}

// FileStorage manages file-based key storage.
type FileStorage struct {
	basePath string
	memory   *KeyStorage
}

// NewFileStorage creates a new file storage.
func NewFileStorage(basePath string) *FileStorage {
	return &FileStorage{
		basePath: basePath,
		memory:   NewKeyStorage(&StorageConfig{Backend: BackendFile}),
	}
}

// SaveKey saves a key to file.
func (s *FileStorage) SaveKey(keyID string, keyData []byte) error {
	keyPath := filepath.Join(s.basePath, keyID+".key")

	// Create directory if not exists
	if err := os.MkdirAll(s.basePath, 0700); err != nil {
		return err
	}

	// Write key file
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return err
	}

	return nil
}

// LoadKey loads a key from file.
func (s *FileStorage) LoadKey(keyID string) ([]byte, error) {
	keyPath := filepath.Join(s.basePath, keyID+".key")

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

// DeleteKeyFile deletes a key file.
func (s *FileStorage) DeleteKeyFile(keyID string) error {
	keyPath := filepath.Join(s.basePath, keyID+".key")

	if err := os.Remove(keyPath); err != nil {
		return err
	}

	return nil
}

// ListKeyFiles lists all key files.
func (s *FileStorage) ListKeyFiles() ([]string, error) {
	var keyFiles []string

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) == ".key" {
			keyID := filepath.Base(entry.Name())[:len(filepath.Base(entry.Name()))-4]
			keyFiles = append(keyFiles, keyID)
		}
	}

	return keyFiles, nil
}

// EncryptKey encrypts key data.
func EncryptKey(keyData []byte, encryptionKey []byte) ([]byte, error) {
	// In production: use proper encryption (AES-GCM)
	// For demo: base64 encode with XOR
	encrypted := make([]byte, len(keyData))
	for i := range keyData {
		encrypted[i] = keyData[i] ^ encryptionKey[i%len(encryptionKey)]
	}

	return encrypted, nil
}

// DecryptKey decrypts key data.
func DecryptKey(encryptedData []byte, encryptionKey []byte) ([]byte, error) {
	// In production: use proper decryption (AES-GCM)
	// For demo: base64 decode with XOR
	decrypted := make([]byte, len(encryptedData))
	for i := range encryptedData {
		decrypted[i] = encryptedData[i] ^ encryptionKey[i%len(encryptionKey)]
	}

	return decrypted, nil
}

// GenerateRandomKey generates a random encryption key.
func GenerateRandomKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// EncodeKey encodes key for storage.
func EncodeKey(keyData []byte) string {
	return base64.StdEncoding.EncodeToString(keyData)
}

// DecodeKey decodes key from storage.
func DecodeKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// ValidateKey validates key data.
func ValidateKey(keyData []byte, algorithm string, keySize int) bool {
	// In production: validate key format and size
	// For demo: check minimum length
	return len(keyData) >= keySize/8
}

// StorageManager manages storage operations.
type StorageManager struct {
	backends map[StorageBackend]*KeyStorage
}

// NewStorageManager creates a new storage manager.
func NewStorageManager() *StorageManager {
	return &StorageManager{
		backends: make(map[StorageBackend]*KeyStorage),
	}
}

// AddBackend adds a storage backend.
func (m *StorageManager) AddBackend(backend StorageBackend, storage *KeyStorage) {
	m.backends[backend] = storage
}

// GetBackend returns a storage backend.
func (m *StorageManager) GetBackend(backend StorageBackend) (*KeyStorage, error) {
	storage, ok := m.backends[backend]
	if !ok {
		return nil, fmt.Errorf("backend not found: %s", backend)
	}

	return storage, nil
}

// StoreKey stores a key to all backends.
func (m *StorageManager) StoreKey(keyID string, keyData []byte, metadata KeyMetadata) error {
	for _, storage := range m.backends {
		if err := storage.StoreKey(keyID, keyData, metadata); err != nil {
			return err
		}
	}

	return nil
}

// GetKey retrieves a key from all backends.
func (m *StorageManager) GetKey(keyID string) ([]byte, error) {
	var keyData []byte
	var lastError error

	for backend, storage := range m.backends {
		data, err := storage.GetKey(keyID)
		if err == nil {
			keyData = data
			lastError = nil
			break
		}
		lastError = err

		// Log backend failure
		fmt.Printf("Backend %s failed: %v\n", backend, err)
	}

	if lastError != nil {
		return nil, lastError
	}

	return keyData, nil
}

// ListKeys lists keys from all backends.
func (m *StorageManager) ListKeys() []string {
	allKeys := make(map[string]bool)

	for _, storage := range m.backends {
		for _, keyID := range storage.ListKeys() {
			allKeys[keyID] = true
		}
	}

	keys := make([]string, 0, len(allKeys))
	for keyID := range allKeys {
		keys = append(keys, keyID)
	}

	return keys
}

// GenerateReport generates storage report.
func (m *StorageManager) GenerateReport() string {
	var report string
	report += "=== Key Storage Report ===\n\n"

	report += "Backends: " + fmt.Sprintf("%d\n", len(m.backends))

	for backend, storage := range m.backends {
		report += "\nBackend: " + string(backend) + "\n"
		report += "  Keys: " + fmt.Sprintf("%d\n", len(storage.ListKeys()))

		metadata := storage.ListMetadata()
		report += "  Metadata entries: " + fmt.Sprintf("%d\n", len(metadata))
	}

	return report
}

// GetKeyStorage returns storage.
func GetKeyStorage(storage *KeyStorage) *KeyStorage {
	return storage
}

// GetKeyMetadata returns metadata.
func GetKeyMetadata(metadata *KeyMetadata) *KeyMetadata {
	return metadata
}