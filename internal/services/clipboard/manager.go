package clipboard

import (
	"context"
	"fmt"
	"sync"

	"golang.design/x/clipboard"
)

type Manager struct {
	mu           sync.Mutex
	lastText     string
	sendCallback func(text string) // Pano değişince burayı tetikleyeceğiz
}

// Init: Pano servisini sistem seviyesinde başlatır (Main veya App.go'da çağrılmalı)
func Init() error {
	err := clipboard.Init()
	if err != nil {
		return fmt.Errorf("pano sistemi başlatılamadı: %w", err)
	}
	return nil
}

// NewManager: Yeni yönetici oluşturur.
func NewManager() *Manager {
	return &Manager{}
}

// SetCallback: Pano değiştiğinde çağrılacak fonksiyonu ayarlar (Chat üzerinden göndermek için).
func (m *Manager) SetCallback(cb func(text string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendCallback = cb
}

// StartWatcher: Bilgisayarın panosunu dinlemeye başlar.
func (m *Manager) StartWatcher(ctx context.Context) {
	// Sadece metin formatını izliyoruz
	ch := clipboard.Watch(ctx, clipboard.FmtText)

	go func() {
		for data := range ch {
			text := string(data)

			m.mu.Lock()
			// ECHO CANCELLATION:
			// Eğer panodaki metin, en son bizim ağdan alıp yazdığımız metinse
			// bunu tekrar ağa gönderme. Yoksa sonsuz döngü olur.
			if text == m.lastText {
				m.mu.Unlock()
				continue
			}
			
			// Yerel kullanıcı yeni bir şey kopyaladı
			m.lastText = text
			cb := m.sendCallback
			m.mu.Unlock()

			// Ağa gönder (Callback varsa)
			if cb != nil {
				fmt.Printf("📋 Pano Değişti (%d karakter), gönderiliyor...\n", len(text))
				cb(text)
			}
		}
	}()
}

// Write: Karşıdan gelen metni yerel panoya yazar.
func (m *Manager) Write(text string) {
	m.mu.Lock()
	// Döngüyü kırmak için: "Bunu ben yazdım, tekrar okursan yoksay" diyoruz.
	m.lastText = text
	m.mu.Unlock()

	// İşletim sistemi panosuna yaz
	clipboard.Write(clipboard.FmtText, []byte(text))
	
	fmt.Println("📋 Ağdan Pano Geldi ve Yazıldı.")
}