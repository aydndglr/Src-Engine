//go:build linux

package input

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"src-engine/internal/protocol"
)

// LinuxManager: Linux için xdotool kullanan yönetici
type LinuxManager struct {
	screenWidth  int
	screenHeight int
}

// NewManager: Linux için fabrika fonksiyonu
func NewManager() (Manager, error) {
	// Ekran çözünürlüğünü öğren (Absolute mouse hesaplaması için şart)
	// Çıktı örneği: "1920 1080"
	out, err := exec.Command("xdotool", "getdisplaygeometry").Output()
	w, h := 1920, 1080 // Varsayılan (Fallback)

	if err == nil {
		parts := strings.Fields(string(out))
		if len(parts) >= 2 {
			wInt, _ := strconv.Atoi(parts[0])
			hInt, _ := strconv.Atoi(parts[1])
			if wInt > 0 && hInt > 0 {
				w, h = wInt, hInt
			}
		}
	} else {
		fmt.Println("⚠️ LinuxManager: Ekran çözünürlüğü alınamadı, varsayılan 1920x1080 kullanılıyor.")
	}

	return &LinuxManager{
		screenWidth:  w,
		screenHeight: h,
	}, nil
}

// Reset: Bağlantı koptuğunda takılı kalan tuşları kurtarır.
func (m *LinuxManager) Reset() {
	// Kritik tuşları serbest bırak (CTRL, ALT, SHIFT, SUPER/WIN)
	// Linux'ta xdotool ile bunları yukarı kaldırmak sistemi kurtarır.
	_ = runXdo("keyup", "Control_L", "Control_R", "Alt_L", "Alt_R", "Shift_L", "Shift_R", "Super_L", "Super_R")
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
	// Frontend artık 0-65535 (Absolute) değer gönderiyor.
	// Linux (xdotool) piksel bekler. Dönüşüm yapıyoruz:
	
	realX := (int(ev.X) * m.screenWidth) / 65535
	realY := (int(ev.Y) * m.screenHeight) / 65535

	// 1. Hareket
	if ev.Action == protocol.MouseMove {
		return runXdo("mousemove", fmt.Sprint(realX), fmt.Sprint(realY))
	}

	// 2. Tıklama ve Tekerlek
	switch ev.Action {
	case protocol.MouseDown:
		btn := btnToXdo(ev.Flags)
		// Önce konuma git, sonra bas (mousemove + mousedown)
		return runXdo("mousemove", fmt.Sprint(realX), fmt.Sprint(realY), "mousedown", btn)

	case protocol.MouseUp:
		btn := btnToXdo(ev.Flags)
		return runXdo("mousemove", fmt.Sprint(realX), fmt.Sprint(realY), "mouseup", btn)

	case protocol.MouseWheel:
		// X11'de Tekerlek buton gibidir: 4=Yukarı, 5=Aşağı
		if ev.Wheel > 0 {
			return runXdo("click", "4")
		} else if ev.Wheel < 0 {
			return runXdo("click", "5")
		}
	}

	return nil
}

func (m *LinuxManager) handleKeyboard(ev protocol.InputEvent) error {
	// 1. Metin Yazma (En güvenlisi)
	if ev.Action == protocol.KeyText {
		if ev.Text == "" {
			return nil
		}
		// --delay 0: Gecikmesiz yaz
		return runXdo("type", "--delay", "0", ev.Text)
	}

	// 2. Özel Tuşlar (CTRL, ALT vs.)
	// Not: xdotool ham JS keycode (örn: 13, 65) tanımaz. 
	// Linux için tam bir Keymap tablosu gerekir (JS -> Keysym).
	// Şimdilik sadece metin yazma ve temel komutlar aktif.
	// İleride buraya CGO ile XTestFakeKeyEvent eklenecek.
	
	return nil
}

// --- Yardımcılar ---

func btnToXdo(flags uint8) string {
	if flags == 1 {
		return "1" // Sol
	}
	if flags == 2 {
		return "3" // Sağ (Linux'ta sağ tık genelde 3'tür)
	}
	if flags == 4 {
		return "2" // Orta
	}
	return "1"
}

func runXdo(args ...string) error {
	cmd := exec.Command("xdotool", args...)
	// cmd.Env = os.Environ() // Gerekirse açılabilir
	return cmd.Run()
}