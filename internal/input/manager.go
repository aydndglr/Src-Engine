package input

import (
	"src-engine/internal/protocol"
)

// Manager: Klavye ve Mouse kontrolünü sağlayan arayüz.
type Manager interface {
	// Apply: Gelen input paketini işletim sistemine uygular
	Apply(ev protocol.InputEvent) error
	Reset()
}

// DİKKAT: NewManager fonksiyonunu buradan sildik.
// Artık o fonksiyon windows_manager.go ve linux_manager.go içinde yaşayacak.