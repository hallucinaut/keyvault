package storage

import (
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
	// RSA 256 means 32 bytes minimum
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

func TestStorageResult(t *testing.T) {
	storage := NewKeyStorage(&StorageConfig{Backend: BackendMemory})

	storage.StoreKey("key-001", []byte("data"), KeyMetadata{ID: "key-001"})

	keys := storage.ListKeys()
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}
}