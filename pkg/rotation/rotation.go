// Package rotation provides key rotation capabilities.
package rotation

import (
	"fmt"
	"time"
)

// RotationPolicy represents a key rotation policy.
type RotationPolicy struct {
	ID                  string
	Name                string
	Description         string
	RotationPeriod      time.Duration
	MaxRotations        int
	GracePeriod         time.Duration
	NotifyBefore        time.Duration
	AutoRotate          bool
	Enabled             bool
	BackwardCompatible  bool
	CleanupOldKeys      bool
}

// RotationSchedule represents a key rotation schedule.
type RotationSchedule struct {
	KeyID           string
	LastRotation    time.Time
	NextRotation    time.Time
	TotalRotations  int
	MaxRotations    int
	Status          string // scheduled, pending, completed, overdue
	LastReason      string
	NextReason      string
}

// RotationEvent represents a rotation event.
type RotationEvent struct {
	ID            string
	KeyID         string
	OldKeyID      string
	NewKeyID      string
	RotatedAt     time.Time
	Reason        string
	Status        string
	Error         error
	Metadata      map[string]string
}

// RotationManager manages key rotation.
type RotationManager struct {
	policies      map[string]RotationPolicy
	schedules     map[string]*RotationSchedule
	events        []RotationEvent
	handlers      []RotationHandler
}

// RotationHandler handles rotation events.
type RotationHandler func(event *RotationEvent) error

// NewRotationManager creates a new rotation manager.
func NewRotationManager() *RotationManager {
	return &RotationManager{
		policies:  make(map[string]RotationPolicy),
		schedules: make(map[string]*RotationSchedule),
		events:    make([]RotationEvent, 0),
		handlers:  make([]RotationHandler, 0),
	}
}

// AddPolicy adds a rotation policy.
func (m *RotationManager) AddPolicy(policy RotationPolicy) {
	m.policies[policy.ID] = policy
}

// GetPolicy returns a policy by ID.
func (m *RotationManager) GetPolicy(policyID string) (*RotationPolicy, error) {
	policy, ok := m.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	return &policy, nil
}

// ListPolicies returns all policies.
func (m *RotationManager) ListPolicies() []RotationPolicy {
	policies := make([]RotationPolicy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}
	return policies
}

// CreateSchedule creates a rotation schedule for a key.
func (m *RotationManager) CreateSchedule(keyID string, policyID string) (*RotationSchedule, error) {
	policy, err := m.GetPolicy(policyID)
	if err != nil {
		return nil, err
	}

	schedule := &RotationSchedule{
		KeyID:        keyID,
		LastRotation: time.Time{},
		NextRotation: time.Now().Add(policy.RotationPeriod),
		TotalRotations: 0,
		MaxRotations:   policy.MaxRotations,
		Status:         "scheduled",
	}

	m.schedules[keyID] = schedule
	return schedule, nil
}

// GetSchedule returns a rotation schedule.
func (m *RotationManager) GetSchedule(keyID string) (*RotationSchedule, error) {
	schedule, ok := m.schedules[keyID]
	if !ok {
		return nil, fmt.Errorf("schedule not found: %s", keyID)
	}
	return schedule, nil
}

// ListSchedules returns all schedules.
func (m *RotationManager) ListSchedules() []*RotationSchedule {
	schedules := make([]*RotationSchedule, 0, len(m.schedules))
	for _, schedule := range m.schedules {
		schedules = append(schedules, schedule)
	}
	return schedules
}

// UpdateSchedule updates a rotation schedule.
func (m *RotationManager) UpdateSchedule(keyID string, updates map[string]interface{}) error {
	schedule, err := m.GetSchedule(keyID)
	if err != nil {
		return err
	}

	for key, value := range updates {
		switch key {
		case "next_rotation":
			if t, ok := value.(time.Time); ok {
				schedule.NextRotation = t
			}
		case "status":
			if s, ok := value.(string); ok {
				schedule.Status = s
			}
		}
	}

	return nil
}

// RegisterHandler registers a rotation handler.
func (m *RotationManager) RegisterHandler(handler RotationHandler) {
	m.handlers = append(m.handlers, handler)
}

// RotateKey rotates a key.
func (m *RotationManager) RotateKey(keyID string, newKeyID string, reason string) (*RotationEvent, error) {
	schedule, err := m.GetSchedule(keyID)
	if err != nil {
		return nil, err
	}

	// Check if rotation is allowed
	if schedule.TotalRotations >= schedule.MaxRotations {
		return nil, fmt.Errorf("maximum rotations reached for key: %s", keyID)
	}

	// Create rotation event
	event := &RotationEvent{
		ID:         fmt.Sprintf("rotate-%d", time.Now().UnixNano()),
		KeyID:      keyID,
		OldKeyID:   keyID,
		NewKeyID:   newKeyID,
		RotatedAt:  time.Now(),
		Reason:     reason,
		Status:     "completed",
		Metadata:   make(map[string]string),
	}

	// Update schedule
	schedule.TotalRotations++
	schedule.LastRotation = time.Now()
	schedule.LastReason = reason

	// Calculate next rotation
	if policy, err := m.GetPolicy("default"); err == nil {
		schedule.NextRotation = time.Now().Add(policy.RotationPeriod)
	}

	// Store event
	m.events = append(m.events, *event)

	// Trigger handlers
	for _, handler := range m.handlers {
		if err := handler(event); err != nil {
			event.Status = "failed"
			event.Error = err
			return event, err
		}
	}

	return event, nil
}

// CheckSchedules checks rotation schedules and returns overdue keys.
func (m *RotationManager) CheckSchedules() []*RotationSchedule {
	now := time.Now()
	var overdueSchedules []*RotationSchedule

	for keyID, schedule := range m.schedules {
		if now.After(schedule.NextRotation) {
			schedule.Status = "overdue"
			overdueSchedules = append(overdueSchedules, schedule)

			// Update schedule
			m.schedules[keyID] = schedule
		}
	}

	return overdueSchedules
}

// GetOverdueKeys returns keys that need rotation.
func (m *RotationManager) GetOverdueKeys() []string {
	overdueSchedules := m.CheckSchedules()
	var keyIDs []string

	for _, schedule := range overdueSchedules {
		keyIDs = append(keyIDs, schedule.KeyID)
	}

	return keyIDs
}

// GetUpcomingRotations returns keys with upcoming rotations.
func (m *RotationManager) GetUpcomingRotations(within time.Duration) []*RotationSchedule {
	now := time.Now()
	var upcomingSchedules []*RotationSchedule

	for _, schedule := range m.schedules {
		if !schedule.NextRotation.IsZero() && schedule.NextRotation.Before(now.Add(within)) {
			upcomingSchedules = append(upcomingSchedules, schedule)
		}
	}

	return upcomingSchedules
}

// GetRotationHistory returns rotation history for a key.
func (m *RotationManager) GetRotationHistory(keyID string) []RotationEvent {
	var history []RotationEvent

	for _, event := range m.events {
		if event.KeyID == keyID || event.NewKeyID == keyID {
			history = append(history, event)
		}
	}

	return history
}

// GenerateReport generates rotation report.
func (m *RotationManager) GenerateReport() string {
	schedules := m.ListSchedules()

	var report string
	report += "=== Key Rotation Report ===\n\n"

	report += "Rotation Policies: " + fmt.Sprintf("%d\n", len(m.policies))
	report += "Active Schedules: " + fmt.Sprintf("%d\n", len(schedules))

	overdueCount := 0
	scheduledCount := 0
	completedCount := 0

	for _, schedule := range schedules {
		switch schedule.Status {
		case "overdue":
			overdueCount++
		case "scheduled":
			scheduledCount++
		case "completed":
			completedCount++
		}
	}

	report += "\nSchedule Status:\n"
	report += "  Overdue: " + fmt.Sprintf("%d\n", overdueCount)
	report += "  Scheduled: " + fmt.Sprintf("%d\n", scheduledCount)
	report += "  Completed: " + fmt.Sprintf("%d\n", completedCount)

	if len(schedules) > 0 {
		report += "\nSchedule Details:\n"
		for i, schedule := range schedules {
			report += fmt.Sprintf("\n[%d] Key: %s\n", i+1, schedule.KeyID)
			report += "    Status: " + schedule.Status + "\n"
			report += "    Last Rotation: " + schedule.LastRotation.Format("2006-01-02 15:04:05") + "\n"
			report += "    Next Rotation: " + schedule.NextRotation.Format("2006-01-02 15:04:05") + "\n"
			report += "    Total Rotations: " + fmt.Sprintf("%d/%d\n", schedule.TotalRotations, schedule.MaxRotations)
			report += "    Last Reason: " + schedule.LastReason + "\n"
		}
	}

	if len(m.events) > 0 {
		report += "\nRecent Rotation Events:\n"
		for i, event := range m.events {
			if i >= 10 {
				break
			}
			report += fmt.Sprintf("\n[%d] %s\n", i+1, event.ID)
			report += "    Key: " + event.KeyID + " -> " + event.NewKeyID + "\n"
			report += "    Rotated: " + event.RotatedAt.Format("2006-01-02 15:04:05") + "\n"
			report += "    Reason: " + event.Reason + "\n"
			report += "    Status: " + event.Status + "\n"
		}
	}

	return report
}

// CreateDefaultPolicy creates default rotation policy.
func CreateDefaultPolicy() RotationPolicy {
	return RotationPolicy{
		ID:                 "default",
		Name:               "Default Rotation Policy",
		Description:        "Default key rotation policy",
		RotationPeriod:     90 * 24 * time.Hour,
		MaxRotations:       10,
		GracePeriod:        7 * 24 * time.Hour,
		NotifyBefore:       14 * 24 * time.Hour,
		AutoRotate:         false,
		Enabled:            true,
		BackwardCompatible: true,
		CleanupOldKeys:     true,
	}
}

// CreateCommonPolicies creates common rotation policies.
func CreateCommonPolicies() []RotationPolicy {
	return []RotationPolicy{
		{
			ID:                "policy-90-days",
			Name:              "90 Day Rotation",
			Description:       "Rotate keys every 90 days",
			RotationPeriod:    90 * 24 * time.Hour,
			MaxRotations:      10,
			GracePeriod:       7 * 24 * time.Hour,
			NotifyBefore:      14 * 24 * time.Hour,
			AutoRotate:        false,
			Enabled:           true,
			BackwardCompatible: true,
			CleanupOldKeys:    true,
		},
		{
			ID:                "policy-180-days",
			Name:              "180 Day Rotation",
			Description:       "Rotate keys every 180 days",
			RotationPeriod:    180 * 24 * time.Hour,
			MaxRotations:      8,
			GracePeriod:       14 * 24 * time.Hour,
			NotifyBefore:      30 * 24 * time.Hour,
			AutoRotate:        true,
			Enabled:           true,
			BackwardCompatible: true,
			CleanupOldKeys:    true,
		},
		{
			ID:                "policy-365-days",
			Name:              "Annual Rotation",
			Description:       "Rotate keys annually",
			RotationPeriod:    365 * 24 * time.Hour,
			MaxRotations:      5,
			GracePeriod:       30 * 24 * time.Hour,
			NotifyBefore:      60 * 24 * time.Hour,
			AutoRotate:        true,
			Enabled:           true,
			BackwardCompatible: false,
			CleanupOldKeys:    false,
		},
	}
}

// GetRotationManager returns manager.
func GetRotationManager(manager *RotationManager) *RotationManager {
	return manager
}

// GetRotationPolicy returns policy.
func GetRotationPolicy(policy *RotationPolicy) *RotationPolicy {
	return policy
}

// GetRotationSchedule returns schedule.
func GetRotationSchedule(schedule *RotationSchedule) *RotationSchedule {
	return schedule
}

// GetRotationEvent returns event.
func GetRotationEvent(event *RotationEvent) *RotationEvent {
	return event
}