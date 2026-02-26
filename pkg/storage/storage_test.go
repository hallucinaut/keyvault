package storage

import (
	"bytes"
	"os"
	"testing"
)

func TestNewKeyStorage(t *testing.T) {
	storage := NewKeyStorage(nil)
	if storage == nil {
		t.Fatal("Expected storage to be created")
	}
	if storage.keys == nil {
		t.Error("Expected keys map to be initialized")
	}
}

func TestStoreKey(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{
		Backend: BackendMemory,
		MaxKeys: 10,
	})

	metadata := KeyMetadata{
		ID:        "key-001",
		Algorithm: "rsa",
		KeySize:   2048,
	}

	err := storage.StoreKey("key-001", []byte("key-data"), metadata)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	keys := storage.ListKeys()
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}
}

func TestGetKey(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{Backend: BackendMemory})

	storage.StoreKey("key-001", []byte("key-data"), KeyMetadata{ID: "key-001"})

	keyData, err := storage.GetKey("key-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(keyData) != "key-data" {
		t.Errorf("Expected 'key-data', got '%s'", string(keyData))
	}
}

func TestDeleteKey(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{Backend: BackendMemory})

	storage.StoreKey("key-001", []byte("key-data"), KeyMetadata{ID: "key-001"})
	storage.DeleteKey("key-001")

	_, err := storage.GetKey("key-001")
	if err == nil {
		t.Error("Expected error for deleted key")
	}
}

func TestListKeys(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{Backend: BackendMemory})

	storage.StoreKey("key-001", []byte("data1"), KeyMetadata{ID: "key-001"})
	storage.StoreKey("key-002", []byte("data2"), KeyMetadata{ID: "key-002"})

	keys := storage.ListKeys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}

func TestGetMetadata(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{Backend: BackendMemory})

	storage.StoreKey("key-001", []byte("data"), KeyMetadata{
		ID:        "key-001",
		Algorithm: "rsa",
		KeySize:   2048,
	})

	metadata, err := storage.GetMetadata("key-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if metadata.Algorithm != "rsa" {
		t.Errorf("Expected algorithm 'rsa', got '%s'", metadata.Algorithm)
	}
}

func TestUpdateMetadata(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{Backend: BackendMemory})

	storage.StoreKey("key-001", []byte("data"), KeyMetadata{ID: "key-001", Owner: "original"})

	err := storage.UpdateMetadata("key-001", map[string]string{
		"owner": "updated",
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	metadata, _ := storage.GetMetadata("key-001")
	if metadata.Owner != "updated" {
		t.Errorf("Expected owner 'updated', got '%s'", metadata.Owner)
	}
}

func TestNewFileStorage(t *testing.T) {
	storage := NewFileStorage("/tmp/test_storage")
	if storage == nil {
		t.Fatal("Expected file storage to be created")
	}
}

func TestEncodeKey(t *testing.T) {
	keyData := []byte("test-key-data")
	encoded := EncodeKey(keyData)

	if encoded == "" {
		t.Error("Expected non-empty encoded key")
	}
}

func TestDecodeKey(t *testing.T) {
	keyData := []byte("test-key-data")
	encoded := EncodeKey(keyData)

	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(decoded) != string(keyData) {
		t.Errorf("Expected '%s', got '%s'", string(keyData), string(decoded))
	}
}

func TestValidateKey(t *testing.T) {
	keyData := make([]byte, 32)
	valid := ValidateKey(keyData, "rsa", 256)
	if !valid {
		t.Error("Expected key to be valid")
	}
}

func TestNewStorageManager(t *testing.T) {
	manager := NewStorageManager()
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}
}

func TestCrypto(t *testing.T) {
	keyData := []byte("my-secret-key-data-to-encrypt")
	encKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256

	encrypted, err := EncryptKey(keyData, encKey)
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	if bytes.Equal(encrypted, keyData) {
		t.Fatal("Encrypted data is identical to plain data")
	}

	decrypted, err := DecryptKey(encrypted, encKey)
	if err != nil {
		t.Fatalf("DecryptKey failed: %v", err)
	}

	if !bytes.Equal(decrypted, keyData) {
		t.Fatalf("Decrypted data does not match original. Got %s, want %s", string(decrypted), string(keyData))
	}
}

func TestFileStorage(t *testing.T) {
	dir, err := os.MkdirTemp("", "keyvault_storage_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	fs := NewFileStorage(dir)
	keyID := "test-key-123"
	keyData := []byte("file-storage-key-data")

	// Test SaveKey
	if err := fs.SaveKey(keyID, keyData); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	// Test ListKeyFiles
	files, err := fs.ListKeyFiles()
	if err != nil {
		t.Fatalf("ListKeyFiles failed: %v", err)
	}
	if len(files) != 1 || files[0] != keyID {
		t.Fatalf("Expected 1 key file '%s', got %v", keyID, files)
	}

	// Test LoadKey
	loaded, err := fs.LoadKey(keyID)
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}
	if !bytes.Equal(loaded, keyData) {
		t.Fatalf("Loaded key mismatch. Got %s, want %s", string(loaded), string(keyData))
	}

	// Test DeleteKeyFile
	if err := fs.DeleteKeyFile(keyID); err != nil {
		t.Fatalf("DeleteKeyFile failed: %v", err)
	}
	
	// Ensure list is empty
	files, err = fs.ListKeyFiles()
	if err != nil {
		t.Fatalf("ListKeyFiles failed: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("Expected 0 key files after deletion, got %v", files)
	}
}
