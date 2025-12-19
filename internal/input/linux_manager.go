//go:build linux

package input

import (
	"fmt"
	"os"
	"os/exec"
	"src-engine/internal/protocol"
)

// LinuxManager: Linux için xdotool kullanan yönetici
type LinuxManager struct{}

// NewManager: Linux için fabrika fonksiyonu
func NewManager() (Manager, error) {
	return &LinuxManager{}, nil
}

func (m *LinuxManager) Apply(ev protocol.InputEvent) error {
	switch ev.Device {
	case protocol.DeviceMouse:
		return m.handleMouse(ev)
	case protocol.DeviceKeyboard:
		return m.handleKeyboard(ev)
	default:
		return nil
	}
}

func (m *LinuxManager) handleMouse(ev protocol.InputEvent) error {
	// 1. Hareket
	if ev.Action == protocol.MouseMove {
		return runXdo("mousemove", fmt.Sprint(ev.X), fmt.Sprint(ev.Y))
	}

	// 2. Tıklama ve Tekerlek
	switch ev.Action {
	case protocol.MouseDown:
		btn := btnToXdo(ev.Flags)
		return runXdo("mousemove", fmt.Sprint(ev.X), fmt.Sprint(ev.Y), "mousedown", btn)

	case protocol.MouseUp:
		btn := btnToXdo(ev.Flags)
		return runXdo("mousemove", fmt.Sprint(ev.X), fmt.Sprint(ev.Y), "mouseup", btn)

	case protocol.MouseWheel:
		if ev.Wheel < 0 {
			return runXdo("click", "4")
		}
		return runXdo("click", "5")
	}

	return nil
}

func (m *LinuxManager) handleKeyboard(ev protocol.InputEvent) error {
	// Metin Yazma
	if ev.Action == protocol.KeyText {
		if ev.Text == "" {
			return nil
		}
		return runXdo("type", "--delay", "0", ev.Text)
	}
	return nil
}

// --- Yardımcılar ---

func btnToXdo(flags uint8) string {
	if flags == 1 {
		return "1"
	}
	if flags == 2 {
		return "3"
	}
	if flags == 4 {
		return "2"
	}
	return "1"
}

func runXdo(args ...string) error {
	cmd := exec.Command("xdotool", args...)
	cmd.Env = os.Environ()
	return cmd.Run()
}