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
	// Pano servisini başlat
	err := clipboard.Init()
	if err != nil {
		return fmt.Errorf("pano sistemi başlatılamadı: %w", err)
	}
	return nil
}

// NewManager: Yeni yönetici oluşturur.
func NewManager() *ClipboardManager {
	return &ClipboardManager{}
}

// SetCallback: Pano değiştiğinde çağrılacak fonksiyonu ayarlar (Ağa göndermek için).
func (m *ClipboardManager) SetCallback(cb func(text string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendCallback = cb
}

// StartWatcher: Bilgisayarın panosunu dinlemeye başlar.
func (m *ClipboardManager) StartWatcher(ctx context.Context) {
	// Sadece metin formatını izliyoruz (Resim kopyalama şu an desteklenmiyor)
	ch := clipboard.Watch(ctx, clipboard.FmtText)

	go func() {
		for data := range ch {
			text := string(data)

			m.mu.Lock()
			// ECHO CANCELLATION:
			// Eğer panodaki metin, en son bizim ağdan alıp yazdığımız metinse
			// bunu tekrar ağa gönderme. Yoksa sonsuz döngü olur (A->B->A->B...)
			if text == m.lastText {
				m.mu.Unlock()
				continue
			}
			// Yerel kullanıcı yeni bir şey kopyaladı, bunu kaydet
			m.lastText = text
			cb := m.sendCallback
			m.mu.Unlock()

			// Ağa gönder
			if cb != nil {
				fmt.Printf("📋 Pano Değişti (%d karakter), gönderiliyor...\n", len(text))
				
				// Bloklamaması için goroutine içinde çağırabiliriz
				// ama ağ sırası bozulmasın diye düz çağırıyoruz.
				cb(text)
			}
		}
	}()
}

// Write: Karşıdan gelen metni yerel panoya yazar.
func (m *ClipboardManager) Write(text string) {
	m.mu.Lock()
	// Döngüyü kırmak için: "Bunu ben yazdım, tekrar okursan yoksay" diyoruz.
	m.lastText = text
	m.mu.Unlock()

	// İşletim sistemi panosuna yaz
	clipboard.Write(clipboard.FmtText, []byte(text))
	
	// Bilgi ver
	if len(text) > 20 {
		fmt.Printf("📋 Ağdan Pano Geldi: %s...\n", text[:20])
	} else {
		fmt.Printf("📋 Ağdan Pano Geldi: %s\n", text)
	}
}