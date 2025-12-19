package clipboard

import (
	"context"
	"fmt"
	"sync"
	"golang.design/x/clipboard"
)

// ClipboardManager: Pano senkronizasyonunu yönetir.
type ClipboardManager struct {
	mu           sync.Mutex
	lastText     string
	sendCallback func(text string) // Panoda değişiklik olunca burayı tetikleyeceğiz
}

// Init: Pano sistemini başlatır.
func Init() error {
	return clipboard.Init()
}

// NewManager: Yeni yönetici oluşturur.
func NewManager() *ClipboardManager {
	return &ClipboardManager{}
}

// SetCallback: Pano değiştiğinde çağrılacak fonksiyonu ayarlar (Ağa göndermek için).
func (m *ClipboardManager) SetCallback(cb func(text string)) {
	m.sendCallback = cb
}

// StartWatcher: Bilgisayarın panosunu dinlemeye başlar (Host veya Client çalıştırır).
func (m *ClipboardManager) StartWatcher(ctx context.Context) {
	// Pano değişikliklerini izleyen kanal
	ch := clipboard.Watch(ctx, clipboard.FmtText)
	
	go func() {
		for data := range ch {
			text := string(data)
			
			m.mu.Lock()
			// Kendi yazdığımızı tekrar okuyup döngüye (loop) girmeyelim
			if text == m.lastText {
				m.mu.Unlock()
				continue
			}
			m.lastText = text
			m.mu.Unlock()

			// Eğer callback tanımlıysa (yani ağa bağlıysak) gönder
			if m.sendCallback != nil {
				fmt.Println("📋 Pano kopyalandı, karşıya gönderiliyor...")
				m.sendCallback(text)
			}
		}
	}()
}

// SetClipboard: Karşıdan gelen metni bizim panoya yazar.
func (m *ClipboardManager) Write(text string) {
	m.mu.Lock()
	// Döngüyü kırmak için son yazılanı güncelliyoruz
	m.lastText = text 
	m.mu.Unlock()

	clipboard.Write(clipboard.FmtText, []byte(text))
	fmt.Println("📋 Karşıdan gelen metin panoya yazıldı.")
}