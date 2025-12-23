//go:build windows

package win32

import (
	"syscall"
	"time"
	"unsafe"
)

// --- Windows API Tanımları ---
var (
	user32 = syscall.NewLazyDLL("user32.dll")

	procSendInput     = user32.NewProc("SendInput")
	procGetSystemMet  = user32.NewProc("GetSystemMetrics")
	procMapVirtualKey = user32.NewProc("MapVirtualKeyW")
)

// Sistem Metrikleri
const (
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
)

// Windows Input Tipleri
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

// C Yapıları (Windows API uyumlu)
type INPUT struct {
	Type     uint32
	_padding uint32 // 64-bit hizalama
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

// InputManager: Windows giriş yöneticisi
type InputManager struct {
	screenWidth  int32
	screenHeight int32
}

func NewInputManager() *InputManager {
	w, _, _ := procGetSystemMet.Call(SM_CXSCREEN)
	h, _, _ := procGetSystemMet.Call(SM_CYSCREEN)

	return &InputManager{
		screenWidth:  int32(w),
		screenHeight: int32(h),
	}
}

// MoveMouse: Fareyi mutlak konuma taşır (0-65535 aralığı)
func (m *InputManager) MoveMouse(x, y uint16) error {
	var mi MOUSEINPUT
	mi.Dx = int32(x)
	mi.Dy = int32(y)
	mi.DwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
	return sendMouseInput(mi)
}

// MouseClick: Genel tıklama
func (m *InputManager) MouseClick(flags uint32) error {
	var mi MOUSEINPUT
	mi.DwFlags = flags
	return sendMouseInput(mi)
}

// 🔥 KOLAYLIK FONKSİYONLARI (Manager.go bunlara ihtiyaç duyuyor)
func (m *InputManager) MouseLeftDown() error   { return m.MouseClick(MOUSEEVENTF_LEFTDOWN) }
func (m *InputManager) MouseLeftUp() error     { return m.MouseClick(MOUSEEVENTF_LEFTUP) }
func (m *InputManager) MouseRightDown() error  { return m.MouseClick(MOUSEEVENTF_RIGHTDOWN) }
func (m *InputManager) MouseRightUp() error    { return m.MouseClick(MOUSEEVENTF_RIGHTUP) }
func (m *InputManager) MouseMiddleDown() error { return m.MouseClick(MOUSEEVENTF_MIDDLEDOWN) }
func (m *InputManager) MouseMiddleUp() error   { return m.MouseClick(MOUSEEVENTF_MIDDLEUP) }

// MouseWheel: Tekerlek hareketi
func (m *InputManager) MouseWheel(delta int16) error {
	var mi MOUSEINPUT
	mi.DwFlags = MOUSEEVENTF_WHEEL
	mi.MouseData = uint32(delta)
	return sendMouseInput(mi)
}

// KeyScancode: Fiziksel tuş basımı (Oyunlar/Kısayollar)
func (m *InputManager) KeyScancode(vk uint16, up bool, extended bool) error {
	scanCode, _, _ := procMapVirtualKey.Call(uintptr(vk), 0)
	if scanCode == 0 {
		return nil
	}

	flags := uint32(KEYEVENTF_SCANCODE)
	if up {
		flags |= KEYEVENTF_KEYUP
	}
	if extended {
		flags |= KEYEVENTF_EXTENDEDKEY
	}

	return sendScancode(uint16(scanCode), flags)
}

// 🔥 EKSİK OLAN FONKSİYON BU (Manager.go bunu arıyor)
// KeyUnicode: Metin yazma (Chat vb. için)
func (m *InputManager) KeyUnicode(char rune) error {
	// Tuşa Bas
	_ = sendUnicodeInput(uint16(char), 0)
	// Tuşu Bırak
	_ = sendUnicodeInput(uint16(char), KEYEVENTF_KEYUP)
	return nil
}

// Reset: Takılı kalan tuşları temizler
func (m *InputManager) Reset() {
	criticalKeys := []uint16{0x10, 0x11, 0x12, 0x5B, 0x5C} // SHIFT, CTRL, ALT, WIN
	for _, vk := range criticalKeys {
		scanCode, _, _ := procMapVirtualKey.Call(uintptr(vk), 0)
		sendScancode(uint16(scanCode), KEYEVENTF_KEYUP|KEYEVENTF_SCANCODE)
	}
	time.Sleep(10 * time.Millisecond)
}

// --- Yardımcı Fonksiyonlar ---

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