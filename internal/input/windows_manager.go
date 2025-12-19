//go:build windows

package input

import (
	"src-engine/internal/protocol"
	"syscall"
	"unsafe"
	"time"
)

// --- Windows API Tanımları ---
var (
	user32            = syscall.NewLazyDLL("user32.dll")
	procSendInput     = user32.NewProc("SendInput")
	procGetSystemMet  = user32.NewProc("GetSystemMetrics")
	procMapVirtualKey = user32.NewProc("MapVirtualKeyW") // 🔥 YENİ: Dinamik Tuş Eşleme
)

// Sistem Metrikleri (Ekran Çözünürlüğü için)
const (
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
)

const (
	INPUT_MOUSE    = 0
	INPUT_KEYBOARD = 1
)

// Mouse Flags
const (
	MOUSEEVENTF_MOVE       = 0x0001
	MOUSEEVENTF_LEFTDOWN   = 0x0002
	MOUSEEVENTF_LEFTUP     = 0x0004
	MOUSEEVENTF_RIGHTDOWN  = 0x0008
	MOUSEEVENTF_RIGHTUP    = 0x0010
	MOUSEEVENTF_MIDDLEDOWN = 0x0020
	MOUSEEVENTF_MIDDLEUP   = 0x0040
	MOUSEEVENTF_WHEEL      = 0x0800
	MOUSEEVENTF_ABSOLUTE   = 0x8000
)

// Keyboard Flags
const (
	KEYEVENTF_EXTENDEDKEY = 0x0001
	KEYEVENTF_KEYUP       = 0x0002
	KEYEVENTF_UNICODE     = 0x0004
	KEYEVENTF_SCANCODE    = 0x0008
)

// MapVirtualKey Types
const (
	MAPVK_VK_TO_VSC = 0
)

// C Yapıları (Windows SendInput uyumlu)
type INPUT struct {
	Type     uint32
	_padding uint32 // 64-bit hizalama için gerekli
	Data     [32]byte
}

type MOUSEINPUT struct {
	Dx, Dy      int32
	MouseData   uint32
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type KEYBDINPUT struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type WindowsManager struct {
	screenWidth  int32
	screenHeight int32
}

func NewManager() (Manager, error) {
	// Ekran çözünürlüğünü al
	w, _, _ := procGetSystemMet.Call(SM_CXSCREEN)
	h, _, _ := procGetSystemMet.Call(SM_CYSCREEN)

	return &WindowsManager{
		screenWidth:  int32(w),
		screenHeight: int32(h),
	}, nil
}

// 🔥 YENİ: Reset Fonksiyonu
// Bağlantı koptuğunda (veya Engine kapandığında) çağrılır.
// Basılı kalma ihtimali olan tehlikeli tuşları (CTRL, ALT, SHIFT, WIN) serbest bırakır.
func (m *WindowsManager) Reset() {
	criticalKeys := []uint16{
		0x10, // VK_SHIFT
		0x11, // VK_CONTROL
		0x12, // VK_MENU (ALT)
		0x5B, // VK_LWIN (Sol Win)
		0x5C, // VK_RWIN (Sağ Win)
	}

	for _, vk := range criticalKeys {
		// Virtual Key -> Scan Code çevrimi yap
		sc, _, _ := procMapVirtualKey.Call(uintptr(vk), MAPVK_VK_TO_VSC)
		
		// Tuşu serbest bırak (KeyUp)
		sendScancode(uint16(sc), KEYEVENTF_KEYUP|KEYEVENTF_SCANCODE)
	}
	
	// İşletim sistemine nefes aldır
	time.Sleep(10 * time.Millisecond)
}

func (m *WindowsManager) Apply(ev protocol.InputEvent) error {
	switch ev.Device {
	case protocol.DeviceMouse:
		return m.handleMouse(ev)
	case protocol.DeviceKeyboard:
		if ev.Action == protocol.KeyText {
			return m.handleText(ev)
		}
		return m.handleKeyboard(ev)
	default:
		return nil
	}
}

func (m *WindowsManager) handleMouse(ev protocol.InputEvent) error {
	var mi MOUSEINPUT
	mi.DwFlags = MOUSEEVENTF_ABSOLUTE // Mutlak Pozisyon Modu

	// 1. Hareket (Move)
	// Frontend (Electron) artık bize 0-65535 aralığında "hazır" veri gönderiyor.
	// Çarpma/Bölme yapmamıza gerek yok. Direkt olduğu gibi kullanıyoruz.
	// Bu sayede "Mouse Kayması" veya "Sol üstte takılma" sorunu %100 çözülür.
	mi.Dx = int32(ev.X)
	mi.Dy = int32(ev.Y)
	mi.DwFlags |= MOUSEEVENTF_MOVE

	// 2. Tıklama (Action)
	// Viewer tarafında Action: 0=Move, 1=Down, 2=Up, 3=Wheel
	switch ev.Action {
	case protocol.MouseDown:
		if ev.Flags == 1 {
			mi.DwFlags |= MOUSEEVENTF_LEFTDOWN
		} else if ev.Flags == 2 {
			mi.DwFlags |= MOUSEEVENTF_RIGHTDOWN
		} else if ev.Flags == 4 {
			mi.DwFlags |= MOUSEEVENTF_MIDDLEDOWN
		}
	case protocol.MouseUp:
		if ev.Flags == 1 {
			mi.DwFlags |= MOUSEEVENTF_LEFTUP
		} else if ev.Flags == 2 {
			mi.DwFlags |= MOUSEEVENTF_RIGHTUP
		} else if ev.Flags == 4 {
			mi.DwFlags |= MOUSEEVENTF_MIDDLEUP
		}
	case protocol.MouseWheel:
		mi.DwFlags |= MOUSEEVENTF_WHEEL
		mi.MouseData = uint32(ev.Wheel) // Tekerlek miktarı
	}

	return sendMouseInput(mi)
}

func (m *WindowsManager) handleText(ev protocol.InputEvent) error {
	if ev.Text == "" {
		return nil
	}
	// Unicode karakterleri gönder
	for _, char := range ev.Text {
		// Bas
		_ = sendUnicodeInput(uint16(char), 0)
		// Çek
		_ = sendUnicodeInput(uint16(char), KEYEVENTF_KEYUP)
	}
	return nil
}

func (m *WindowsManager) handleKeyboard(ev protocol.InputEvent) error {
	// 🔥 YENİ MANTIK: Dinamik Mapping
	// Eski "switch-case" listesini kaldırdık.
	// Tarayıcıdan gelen KeyCode, Windows VirtualKey ile %99 uyumludur.
	// Bunu "MapVirtualKey" ile ScanCode'a çeviriyoruz.
	
	vk := ev.Key
	scanCode, _, _ := procMapVirtualKey.Call(uintptr(vk), MAPVK_VK_TO_VSC)

	if scanCode == 0 {
		return nil // Tanımsız tuş
	}

	flags := uint32(KEYEVENTF_SCANCODE)

	// Action 2 = KeyUp (Tuşu Bırakma)
	if ev.Action == 2 {
		flags |= KEYEVENTF_KEYUP
	}

	// Extended Key Kontrolü (Yön tuşları, Insert, Delete, Home, End vs.)
	// Frontend bu flag'i doğru gönderiyor.
	if ev.Flags == 1 {
		flags |= KEYEVENTF_EXTENDEDKEY
	}

	return sendScancode(uint16(scanCode), flags)
}

// --- Yardımcılar ---

func sendMouseInput(mi MOUSEINPUT) error {
	var in INPUT
	in.Type = INPUT_MOUSE
	*(*MOUSEINPUT)(unsafe.Pointer(&in.Data[0])) = mi
	return sendInput(in)
}

func sendScancode(scanCode uint16, flags uint32) error {
	var in INPUT
	in.Type = INPUT_KEYBOARD
	ki := (*KEYBDINPUT)(unsafe.Pointer(&in.Data[0]))
	ki.WScan = scanCode
	ki.DwFlags = flags
	return sendInput(in)
}

func sendUnicodeInput(char uint16, flags uint32) error {
	var in INPUT
	in.Type = INPUT_KEYBOARD
	ki := (*KEYBDINPUT)(unsafe.Pointer(&in.Data[0]))
	ki.WScan = char
	ki.DwFlags = KEYEVENTF_UNICODE | flags
	return sendInput(in)
}

func sendInput(in INPUT) error {
	ret, _, err := procSendInput.Call(
		uintptr(1),
		uintptr(unsafe.Pointer(&in)),
		unsafe.Sizeof(in),
	)
	if ret == 0 {
		return err
	}
	return nil
}