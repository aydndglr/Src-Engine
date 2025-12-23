//go:build windows

package license

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
)

// GetHWID: Cihazın benzersiz kimliğini oluşturur.
// Anakart UUID'sini alır, bulamazsa Hostname kullanır.
func GetHWID() string {
	// 1. Yöntem: WMIC ile Anakart UUID (En güvenilir)
	uuid, err := getWmicUUID()
	if err == nil && uuid != "" {
		return hash(uuid)
	}

	// 2. Yöntem: Hostname (Yedek)
	hostname, _ := os.Hostname()
	return hash(hostname + "-fallback")
}

func getWmicUUID() (string, error) {
	// wmic csproduct get uuid
	cmd := exec.Command("wmic", "csproduct", "get", "uuid")
	// Pencere açılmasını engelle (Arka plan)
	cmd.SysProcAttr = &useSysProcAttr
	
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "UUID" {
			return trimmed, nil
		}
	}
	return "", nil
}

func hash(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}