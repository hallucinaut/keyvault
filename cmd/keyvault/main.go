package main

import (
	"os/signal"
	"syscall"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hallucinaut/keyvault/pkg/lifecycle"
	"github.com/hallucinaut/keyvault/pkg/storage"
	"github.com/hallucinaut/keyvault/pkg/rotation"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "generate":
		generateKey()
	case "list":
		listKeys()
	case "rotate":
		rotateKey()
	case "schedule":
		scheduleRotation()
	case "check":
		checkRotations()
	case "export":
		exportKey()
	case "import":
		importKey()
	case "report":
		generateReport()
	case "help", "--help", "-h":
		printUsage()
	case "version":
		fmt.Printf("keyvault version %s\n", version)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`keyvault - Cryptographic Key Lifecycle Manager

Usage:
  keyvault <command> [options]

Commands:
  generate    Generate a new cryptographic key
  list        List all keys
  rotate      Rotate a key
  schedule    Schedule key rotation
  check       Check rotation schedules
  export      Export a key
  import      Import a key
  report      Generate key vault report
  help        Show this help message
  version     Show version information

Examples:
  keyvault generate --algorithm rsa --key-size 2048
  keyvault list
  keyvault rotate key-123
  keyvault schedule key-123 --policy policy-90-days
`)
}

func generateKey() {
	fmt.Println("Generate Cryptographic Key")
	fmt.Println("==========================")
	fmt.Println()

	manager := lifecycle.NewKeyLifecycleManager()

	// Add common policies
	policies := lifecycle.GenerateCommonPolicies()
	for _, policy := range policies {
		manager.AddPolicy(policy)
	}

	fmt.Println("Available Policies:")
	for i, policy := range policies {
		fmt.Printf("\n[%d] %s\n", i+1, policy.Name)
		fmt.Printf("    ID: %s\n", policy.ID)
		fmt.Printf("    Algorithm: %s\n", policy.AllowedAlgorithms[0])
		fmt.Printf("    Key Size: %d\n", policy.MinKeySize)
		fmt.Printf("    Max Lifetime: %v\n", policy.MaxLifetime)
		fmt.Printf("    Auto Rotate: %v\n", policy.AutoRotate)
	}

	fmt.Println()

	// Demo mode - generate sample keys
	fmt.Println("Generating sample keys...")
	fmt.Println()

	algorithms := []lifecycle.KeyAlgorithm{lifecycle.AlgorithmRSA, lifecycle.AlgorithmRSA, lifecycle.AlgorithmAES}
	keySizes := []int{2048, 4096, 256}
	usages := [][]lifecycle.KeyUsage{
		{lifecycle.UsageEncryption, lifecycle.UsageDecryption},
		{lifecycle.UsageSignature, lifecycle.UsageVerify},
		{lifecycle.UsageEncryption, lifecycle.UsageDecryption},
	}

	for i, alg := range algorithms {
		key, err := manager.GenerateKey(alg, keySizes[i], usages[i])
		if err != nil {
			fmt.Printf("Error generating key %d: %v\n", i+1, err)
			continue
		}

		fmt.Printf("[%d] Key Generated:\n", i+1)
		fmt.Printf("    ID: %s\n", key.ID)
		fmt.Printf("    Algorithm: %s\n", key.Algorithm)
		fmt.Printf("    Key Size: %d bits\n", key.KeySize)
		fmt.Printf("    Status: %s\n", key.Status)
		fmt.Printf("    Created: %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Expires: %s\n", key.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	fmt.Println(manager.GenerateReport())
}

func listKeys() {
	fmt.Println("Key Vault Contents")
	fmt.Println("==================")
	fmt.Println()

	manager := lifecycle.NewKeyLifecycleManager()

	// Generate some keys for demo
	policies := lifecycle.GenerateCommonPolicies()
	for _, policy := range policies {
		manager.AddPolicy(policy)
	}

	for _, policy := range policies {
		if len(policy.AllowedAlgorithms) > 0 {
			key, err := manager.GenerateKey(policy.AllowedAlgorithms[0], policy.MinKeySize, []lifecycle.KeyUsage{policy.AllowedUsages[0]})
			if err == nil {
				_ = key
			}
		}
	}

	keys := manager.ListKeys()

	fmt.Printf("Total Keys: %d\n\n", len(keys))

	if len(keys) == 0 {
		fmt.Println("No keys in vault")
		return
	}

	fmt.Println("Keys:")
	for i, key := range keys {
		fmt.Printf("\n[%d] %s\n", i+1, key.ID)
		fmt.Printf("    Algorithm: %s\n", key.Algorithm)
		fmt.Printf("    Key Size: %d bits\n", key.KeySize)
		fmt.Printf("    Status: %s\n", key.Status)
		fmt.Printf("    Created: %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Expires: %s\n", key.ExpiresAt.Format("2006-01-02 15:04:05"))
	}

	fmt.Println()
	fmt.Println(manager.GenerateReport())
}

func rotateKey() {
	fmt.Println("Key Rotation")
	fmt.Println("============")
	fmt.Println()

	manager := lifecycle.NewKeyLifecycleManager()

	// Generate a key
	key, err := manager.GenerateKey(lifecycle.AlgorithmRSA, 2048, []lifecycle.KeyUsage{lifecycle.UsageEncryption, lifecycle.UsageDecryption})
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}

	fmt.Printf("Original Key: %s\n", key.ID)
	fmt.Println()

	// Activate the key
	err = manager.ActivateKey(key.ID)
	if err != nil {
		fmt.Printf("Error activating key: %v\n", err)
		return
	}

	fmt.Printf("Key activated: %s\n", key.ID)
	fmt.Println()

	// Create rotation schedule
	rotationManager := rotation.NewRotationManager()
	rotationManager.AddPolicy(rotation.CreateDefaultPolicy())

	schedule, err := rotationManager.CreateSchedule(key.ID, "default")
	if err != nil {
		fmt.Printf("Error creating schedule: %v\n", err)
		return
	}

	fmt.Printf("Rotation schedule created:\n")
	fmt.Printf("  Key ID: %s\n", schedule.KeyID)
	fmt.Printf("  Next Rotation: %s\n", schedule.NextRotation.Format("2006-01-02 15:04:05"))
	fmt.Println()

	// Simulate rotation
	fmt.Println("Simulating key rotation...")
	newKey, err := manager.RotateKey(key.ID)
	if err != nil {
		fmt.Printf("Error rotating key: %v\n", err)
		return
	}

	fmt.Printf("\nKey rotated successfully:\n")
	fmt.Printf("  Original Key: %s\n", key.ID)
	fmt.Printf("  New Key: %s\n", newKey.ID)
	fmt.Printf("  Rotated At: %s\n", newKey.CreatedAt.Format("2006-01-02 15:04:05"))

	fmt.Println()
	fmt.Println(rotationManager.GenerateReport())
}

func scheduleRotation() {
	fmt.Println("Schedule Key Rotation")
	fmt.Println("=====================")
	fmt.Println()

	rotationManager := rotation.NewRotationManager()

	// Add policies
	policies := rotation.CreateCommonPolicies()
	for _, policy := range policies {
		rotationManager.AddPolicy(policy)
	}

	fmt.Println("Available Rotation Policies:")
	for i, policy := range policies {
		fmt.Printf("\n[%d] %s\n", i+1, policy.Name)
		fmt.Printf("    ID: %s\n", policy.ID)
		fmt.Printf("    Rotation Period: %v\n", policy.RotationPeriod)
		fmt.Printf("    Max Rotations: %d\n", policy.MaxRotations)
		fmt.Printf("    Auto Rotate: %v\n", policy.AutoRotate)
	}

	fmt.Println()

	// Create schedules for demo keys
	keyIDs := []string{"key-001", "key-002", "key-003"}
	policyIDs := []string{"policy-90-days", "policy-180-days", "policy-365-days"}

	fmt.Println("Creating rotation schedules...")
	fmt.Println()

	for i, keyID := range keyIDs {
		policyID := policyIDs[i%len(policyIDs)]
		schedule, err := rotationManager.CreateSchedule(keyID, policyID)
		if err != nil {
			fmt.Printf("Error creating schedule for %s: %v\n", keyID, err)
			continue
		}

		fmt.Printf("[%d] Key %s -> Policy %s\n", i+1, keyID, policyID)
		fmt.Printf("    Next Rotation: %s\n", schedule.NextRotation.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Status: %s\n\n", schedule.Status)
	}

	fmt.Println(rotationManager.GenerateReport())
}

func checkRotations() {
	fmt.Println("Check Rotation Schedules")
	fmt.Println("========================")
	fmt.Println()

	rotationManager := rotation.NewRotationManager()

	// Add policy
	rotationManager.AddPolicy(rotation.CreateDefaultPolicy())

	// Create schedules
	keyIDs := []string{"key-001", "key-002", "key-003"}
	policyID := "policy-90-days"

	for _, keyID := range keyIDs {
		rotationManager.CreateSchedule(keyID, policyID)
	}

	// Check for overdue rotations
	overdueKeys := rotationManager.GetOverdueKeys()

	fmt.Printf("Keys needing rotation: %d\n\n", len(overdueKeys))

	if len(overdueKeys) == 0 {
		fmt.Println("All keys are up to date with rotation schedules")
	} else {
		fmt.Println("Overdue keys:")
		for i, keyID := range overdueKeys {
			fmt.Printf("  [%d] %s\n", i+1, keyID)
		}
	}

	fmt.Println()
	fmt.Println("Upcoming rotations (within 30 days):")
	upcoming := rotationManager.GetUpcomingRotations(30 * 24 * time.Hour)
	if len(upcoming) == 0 {
		fmt.Println("  No upcoming rotations")
	} else {
		for i, schedule := range upcoming {
			fmt.Printf("  [%d] %s - %s\n", i+1, schedule.KeyID, schedule.NextRotation.Format("2006-01-02"))
		}
	}

	fmt.Println()
	fmt.Println(rotationManager.GenerateReport())
}

func exportKey() {
	fmt.Println("Export Key")
	fmt.Println("==========")
	fmt.Println()

	manager := lifecycle.NewKeyLifecycleManager()

	// Generate a key
	key, err := manager.GenerateKey(lifecycle.AlgorithmRSA, 2048, []lifecycle.KeyUsage{lifecycle.UsageEncryption, lifecycle.UsageDecryption})
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}

	fmt.Printf("Key: %s\n", key.ID)
	fmt.Println()

	// Export key
	exported, err := manager.ExportKeyPEM(key.ID)
	if err != nil {
		fmt.Printf("Error exporting key: %v\n", err)
		return
	}

	fmt.Printf("Exported Key (PEM format):\n%s\n", string(exported))
}

func importKey() {
	fmt.Println("Import Key")
	fmt.Println("==========")
	fmt.Println()

	manager := lifecycle.NewKeyLifecycleManager()

	// Import a key
	importedKey, err := manager.ImportKeyPEM([]byte("-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----"), []lifecycle.KeyUsage{lifecycle.UsageEncryption, lifecycle.UsageDecryption})
	if err != nil {
		fmt.Printf("Error importing key: %v\n", err)
		return
	}

	fmt.Printf("Key Imported:\n")
	fmt.Printf("  ID: %s\n", importedKey.ID)
	fmt.Printf("  Algorithm: %s\n", importedKey.Algorithm)
	fmt.Printf("  Key Size: %d bits\n", importedKey.KeySize)
	fmt.Printf("  Status: %s\n", importedKey.Status)
}

func generateReport() {
	fmt.Println("=== Key Vault Report ===")
	fmt.Println()

	// Lifecycle report
	lifecycleManager := lifecycle.NewKeyLifecycleManager()
	policies := lifecycle.GenerateCommonPolicies()
	for _, policy := range policies {
		lifecycleManager.AddPolicy(policy)
	}

	fmt.Println("Key Lifecycle:")
	fmt.Printf("  Policies: %d\n", len(lifecycleManager.ListPolicies()))
	fmt.Println()

	// Storage report
	keyStorage := storage.NewKeyStorage(&storage.StorageConfig{
		Backend: storage.BackendMemory,
	})

	fmt.Println("Key Storage:")
	fmt.Printf("  Backend: %s\n", keyStorage.GetConfig().Backend)
	fmt.Println()

	// Rotation report
	rotationManager := rotation.NewRotationManager()
	rotationPolicies := rotation.CreateCommonPolicies()
	for _, policy := range rotationPolicies {
		rotationManager.AddPolicy(policy)
	}

	fmt.Println("Key Rotation:")
	fmt.Printf("  Policies: %d\n", len(rotationManager.ListPolicies()))
	fmt.Println()

	fmt.Println(rotationManager.GenerateReport())
}