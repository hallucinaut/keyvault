package rotation

import (
	"testing"
	"time"
)

func TestNewRotationManager(t *testing.T) {
	manager := NewRotationManager()
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}
	if manager.policies == nil {
		t.Error("Expected policies map to be initialized")
	}
}

func TestAddPolicy(t *testing.T) {
	manager := NewRotationManager()
	policy := RotationPolicy{
		ID:             "policy-001",
		Name:           "Test Policy",
		RotationPeriod: 90 * 24 * time.Hour,
		MaxRotations:   10,
	}

	manager.AddPolicy(policy)
	policies := manager.ListPolicies()

	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].ID != "policy-001" {
		t.Errorf("Expected policy ID 'policy-001', got '%s'", policies[0].ID)
	}
}

func TestGetPolicy(t *testing.T) {
	manager := NewRotationManager()
	policy := RotationPolicy{
		ID:   "policy-001",
		Name: "Test Policy",
	}
	manager.AddPolicy(policy)

	retrievedPolicy, err := manager.GetPolicy("policy-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if retrievedPolicy.Name != "Test Policy" {
		t.Errorf("Expected policy name 'Test Policy', got '%s'", retrievedPolicy.Name)
	}
}

func TestListPolicies(t *testing.T) {
	manager := NewRotationManager()

	manager.AddPolicy(RotationPolicy{ID: "policy-001", Name: "Policy 1"})
	manager.AddPolicy(RotationPolicy{ID: "policy-002", Name: "Policy 2"})

	policies := manager.ListPolicies()
	if len(policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policies))
	}
}

func TestCreateSchedule(t *testing.T) {
	manager := NewRotationManager()
	manager.AddPolicy(CreateDefaultPolicy())

	schedule, err := manager.CreateSchedule("key-001", "default")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if schedule == nil {
		t.Fatal("Expected schedule to be created")
	}
	if schedule.KeyID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", schedule.KeyID)
	}
}

func TestGetSchedule(t *testing.T) {
	manager := NewRotationManager()
	manager.AddPolicy(CreateDefaultPolicy())
	manager.CreateSchedule("key-001", "default")

	schedule, err := manager.GetSchedule("key-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if schedule.KeyID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", schedule.KeyID)
	}
}

func TestUpdateSchedule(t *testing.T) {
	manager := NewRotationManager()
	manager.AddPolicy(CreateDefaultPolicy())
	manager.CreateSchedule("key-001", "default")

	err := manager.UpdateSchedule("key-001", map[string]interface{}{
		"status": "scheduled",
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	schedule, _ := manager.GetSchedule("key-001")
	if schedule.Status != "scheduled" {
		t.Errorf("Expected status 'scheduled', got '%s'", schedule.Status)
	}
}

func TestRegisterHandler(t *testing.T) {
	manager := NewRotationManager()
	handlerCalled := false

	handler := func(event *RotationEvent) error {
		handlerCalled = true
		return nil
	}

	manager.RegisterHandler(handler)

	event := &RotationEvent{
		ID:     "event-001",
		KeyID:  "key-001",
		Status: "completed",
	}

	// Manually trigger handler
	for _, h := range manager.handlers {
		_ = h(event)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called")
	}
}

func TestGetOverdueKeys(t *testing.T) {
	manager := NewRotationManager()
	manager.AddPolicy(CreateDefaultPolicy())

	// Create a schedule with past rotation date
	schedule := &RotationSchedule{
		KeyID:        "key-001",
		NextRotation: time.Now().Add(-1 * time.Hour), // Past
		Status:       "overdue",
	}
	manager.schedules["key-001"] = schedule

	overdueKeys := manager.GetOverdueKeys()
	if len(overdueKeys) == 0 {
		t.Error("Expected overdue keys")
	}
}

func TestGetUpcomingRotations(t *testing.T) {
	manager := NewRotationManager()
	manager.AddPolicy(CreateDefaultPolicy())
	manager.CreateSchedule("key-001", "default")

	// Manually set next rotation to be within 30 days
	schedule, _ := manager.GetSchedule("key-001")
	schedule.NextRotation = time.Now().Add(15 * 24 * time.Hour)

	upcoming := manager.GetUpcomingRotations(30 * 24 * time.Hour)
	if len(upcoming) == 0 {
		t.Error("Expected upcoming rotations")
	}
}

func TestCreateDefaultPolicy(t *testing.T) {
	policy := CreateDefaultPolicy()

	if policy.ID != "default" {
		t.Errorf("Expected policy ID 'default', got '%s'", policy.ID)
	}
	if policy.RotationPeriod == 0 {
		t.Error("Expected non-zero rotation period")
	}
}

func TestCreateCommonPolicies(t *testing.T) {
	policies := CreateCommonPolicies()

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

func TestGetRotationManager(t *testing.T) {
	manager := NewRotationManager()
	retrieved := GetRotationManager(manager)

	if retrieved != manager {
		t.Error("Expected manager to be the same instance")
	}
}

func TestGetRotationPolicy(t *testing.T) {
	policy := &RotationPolicy{
		ID:   "policy-001",
		Name: "Test Policy",
	}

	retrieved := GetRotationPolicy(policy)
	if retrieved.ID != "policy-001" {
		t.Errorf("Expected ID 'policy-001', got '%s'", retrieved.ID)
	}
}

func TestGetRotationSchedule(t *testing.T) {
	schedule := &RotationSchedule{
		KeyID:   "key-001",
		Status:  "scheduled",
		NextRotation: time.Now(),
	}

	retrieved := GetRotationSchedule(schedule)
	if retrieved.KeyID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", retrieved.KeyID)
	}
}

func TestGetRotationEvent(t *testing.T) {
	event := &RotationEvent{
		ID:      "event-001",
		KeyID:   "key-001",
		Status:  "completed",
		Reason:  "Scheduled rotation",
	}

	retrieved := GetRotationEvent(event)
	if retrieved.ID != "event-001" {
		t.Errorf("Expected ID 'event-001', got '%s'", retrieved.ID)
	}
}

func TestRotationPolicy_Structure(t *testing.T) {
	policy := RotationPolicy{
		ID:                 "policy-001",
		Name:               "Test Policy",
		Description:        "Test description",
		RotationPeriod:     90 * 24 * time.Hour,
		MaxRotations:       10,
		GracePeriod:        7 * 24 * time.Hour,
		NotifyBefore:       14 * 24 * time.Hour,
		AutoRotate:         false,
		Enabled:            true,
		BackwardCompatible: true,
		CleanupOldKeys:     true,
	}

	if policy.RotationPeriod != 90*24*time.Hour {
		t.Errorf("Expected RotationPeriod 90 days, got %v", policy.RotationPeriod)
	}
	if !policy.Enabled {
		t.Error("Expected Enabled to be true")
	}
}

func TestRotationSchedule_Structure(t *testing.T) {
	schedule := RotationSchedule{
		KeyID:          "key-001",
		LastRotation:   time.Now().Add(-90 * 24 * time.Hour),
		NextRotation:   time.Now().Add(90 * 24 * time.Hour),
		TotalRotations: 1,
		MaxRotations:   10,
		Status:         "scheduled",
	}

	if schedule.KeyID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", schedule.KeyID)
	}
	if schedule.Status != "scheduled" {
		t.Errorf("Expected status 'scheduled', got '%s'", schedule.Status)
	}
}

func TestRotationEvent_Structure(t *testing.T) {
	event := RotationEvent{
		ID:        "event-001",
		KeyID:     "key-001",
		OldKeyID:  "key-001",
		NewKeyID:  "key-002",
		RotatedAt: time.Now(),
		Reason:    "Scheduled rotation",
		Status:    "completed",
		Metadata:  map[string]string{"key": "value"},
	}

	if event.KeyID != "key-001" {
		t.Errorf("Expected key ID 'key-001', got '%s'", event.KeyID)
	}
	if event.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", event.Status)
	}
}