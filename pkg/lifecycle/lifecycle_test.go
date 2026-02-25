package lifecycle

import (
	"testing"
	"time"
)

func TestNewKeyLifecycleManager(t *testing.T) {
	manager := NewKeyLifecycleManager()
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}
	if manager.keys == nil {
		t.Error("Expected keys map to be initialized")
	}
}

func TestAddKey(t *testing.T) {
	manager := NewKeyLifecycleManager()
	key := &Key{
		ID:      "key-001",
		Algorithm: AlgorithmRSA,
		KeySize: 2048,
		Status:  StatusGenerated,
		Lifecycle: &KeyLifecycle{
			ID:        "lifecycle-001",
			Algorithm: AlgorithmRSA,
			KeySize:   2048,
			Status:    StatusGenerated,
		},
	}

	err := manager.AddKey(key)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	retrievedKey, err := manager.GetKey("key-001")
	if err != nil {
		t.Errorf("Unexpected error getting key: %v", err)
	}
	if retrievedKey.ID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", retrievedKey.ID)
	}
}

func TestGetKey(t *testing.T) {
	manager := NewKeyLifecycleManager()
	key := &Key{
		ID:        "key-001",
		Algorithm: AlgorithmRSA,
		Status:    StatusGenerated,
		Lifecycle: &KeyLifecycle{
			ID:        "lifecycle-001",
			Algorithm: AlgorithmRSA,
			Status:    StatusGenerated,
		},
	}

	err := manager.AddKey(key)
	if err != nil {
		t.Fatalf("Failed to add key: %v", err)
	}

	retrievedKey, err := manager.GetKey("key-001")
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}
	if retrievedKey.ID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", retrievedKey.ID)
	}
}

func TestListKeys(t *testing.T) {
	manager := NewKeyLifecycleManager()
	key1 := &Key{ID: "key-001", Algorithm: AlgorithmRSA, Status: StatusGenerated}
	key2 := &Key{ID: "key-002", Algorithm: AlgorithmECDSA, Status: StatusGenerated}

	manager.AddKey(key1)
	manager.AddKey(key2)

	keys := manager.ListKeys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}

func TestActivateKey(t *testing.T) {
	manager := NewKeyLifecycleManager()
	key := &Key{
		ID:      "key-001",
		Algorithm: AlgorithmRSA,
		Status:  StatusGenerated,
		Lifecycle: &KeyLifecycle{
			ID:       "lifecycle-001",
			Algorithm: AlgorithmRSA,
			Status:   StatusGenerated,
		},
	}
	manager.AddKey(key)

	err := manager.ActivateKey("key-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	key, _ = manager.GetKey("key-001")
	if key.Status != StatusActive {
		t.Errorf("Expected status 'active', got '%s'", key.Status)
	}
}

func TestDeactivateKey(t *testing.T) {
	manager := NewKeyLifecycleManager()
	key := &Key{
		ID:      "key-001",
		Algorithm: AlgorithmRSA,
		Status:  StatusActive,
		Lifecycle: &KeyLifecycle{
			Algorithm: AlgorithmRSA,
			Status:    StatusActive,
		},
	}
	manager.AddKey(key)

	err := manager.DeactivateKey("key-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	key, _ = manager.GetKey("key-001")
	if key.Status != StatusDeprecated {
		t.Errorf("Expected status 'deprecated', got '%s'", key.Status)
	}
}

func TestRevokeKey(t *testing.T) {
	manager := NewKeyLifecycleManager()
	key := &Key{
		ID:        "key-001",
		Algorithm: AlgorithmRSA,
		Status:    StatusActive,
		Lifecycle: &KeyLifecycle{
			ID:        "lifecycle-001",
			Algorithm: AlgorithmRSA,
			Status:    StatusActive,
			Metadata:  make(map[string]string),
		},
	}

	err := manager.AddKey(key)
	if err != nil {
		t.Fatalf("Failed to add key: %v", err)
	}

	err = manager.RevokeKey("key-001", "Test reason")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	key, _ = manager.GetKey("key-001")
	if key.Status != StatusRevoked {
		t.Errorf("Expected status 'revoked', got '%s'", key.Status)
	}
}

func TestGenerateCommonPolicies(t *testing.T) {
	policies := GenerateCommonPolicies()

	if len(policies) == 0 {
		t.Error("Expected at least one policy")
	}

	// Check that policies have required fields
	for i, policy := range policies {
		if policy.ID == "" {
			t.Errorf("Policy %d has empty ID", i)
		}
		if policy.Name == "" {
			t.Errorf("Policy %d has empty name", i)
		}
	}
}

func TestGetLifecycle(t *testing.T) {
	lifecycle := &KeyLifecycle{
		ID:        "lifecycle-001",
		Algorithm: AlgorithmRSA,
		Status:    StatusActive,
	}

	retrieved := GetLifecycle(lifecycle)
	if retrieved.ID != "lifecycle-001" {
		t.Errorf("Expected ID 'lifecycle-001', got '%s'", retrieved.ID)
	}
}

func TestKey_Getter(t *testing.T) {
	key := &Key{
		ID:        "key-001",
		Algorithm: AlgorithmRSA,
		Status:    StatusActive,
	}

	retrieved := GetKey(key)
	if retrieved.ID != "key-001" {
		t.Errorf("Expected ID 'key-001', got '%s'", retrieved.ID)
	}
}

func TestKeyLifecycle_Structure(t *testing.T) {
	lifecycle := KeyLifecycle{
		ID:        "lifecycle-001",
		Algorithm: AlgorithmRSA,
		KeySize:   2048,
		Status:    StatusActive,
		CreatedAt: time.Now(),
		Usage:     []KeyUsage{UsageEncryption, UsageDecryption},
		Metadata:  map[string]string{"key": "value"},
	}

	if lifecycle.KeySize != 2048 {
		t.Errorf("Expected KeySize 2048, got %d", lifecycle.KeySize)
	}
	if len(lifecycle.Usage) != 2 {
		t.Errorf("Expected 2 usages, got %d", len(lifecycle.Usage))
	}
}

func TestKey_Structure(t *testing.T) {
	key := Key{
		ID:        "key-001",
		Algorithm: AlgorithmRSA,
		KeySize:   2048,
		Status:    StatusActive,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}

	if key.KeySize != 2048 {
		t.Errorf("Expected KeySize 2048, got %d", key.KeySize)
	}
	if key.Status != StatusActive {
		t.Errorf("Expected status 'active', got '%s'", key.Status)
	}
}

func TestKeyPolicy(t *testing.T) {
	policy := KeyPolicy{
		ID:                "policy-001",
		Name:              "Test Policy",
		MinKeySize:        2048,
		MaxKeySize:        4096,
		AllowedAlgorithms: []KeyAlgorithm{AlgorithmRSA},
		MaxLifetime:       365 * 24 * time.Hour,
	}

	if policy.MinKeySize != 2048 {
		t.Errorf("Expected MinKeySize 2048, got %d", policy.MinKeySize)
	}
	if policy.Name != "Test Policy" {
		t.Errorf("Expected name 'Test Policy', got '%s'", policy.Name)
	}
}