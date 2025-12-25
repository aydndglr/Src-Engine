/*package chat

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"src-engine-v2/internal/config"
	"sync"
)

type Manager struct {
	activeConn net.Conn
	mu         sync.Mutex
	
	// Mesaj geldiğinde tetiklenecek fonksiyon (UI'a iletmek için)
	onMessage func(string)
}

func NewManager() *Manager {
	return &Manager{}
}

// SetCallback: Gelen mesajı yakalamak için
func (m *Manager) SetCallback(cb func(string)) {
	m.onMessage = cb
}

// Start: 9004 portunu dinler
func (m *Manager) Start(ln net.Listener) {
	fmt.Printf("💬 Sohbet Servisi Hazır (Port: %d)\n", config.PortChat)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}

		m.mu.Lock()
		if m.activeConn != nil {
			conn.Close()
			m.mu.Unlock()
			continue
		}
		m.activeConn = conn
		m.mu.Unlock()

		fmt.Println("💬 Sohbet Bağlantısı Kuruldu.")
		go m.readLoop(conn)
	}
}

// Send: Karşı tarafa mesaj gönderir
func (m *Manager) Send(text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeConn == nil {
		return fmt.Errorf("bağlantı yok")
	}

	data := []byte(text)
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(data)))

	// Header Yaz
	if _, err := m.activeConn.Write(header); err != nil {
		return err
	}
	// Mesaj Yaz
	if _, err := m.activeConn.Write(data); err != nil {
		return err
	}

	return nil
}

func (m *Manager) readLoop(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		if m.activeConn != nil {
			m.activeConn.Close()
			m.activeConn = nil
		}
		m.mu.Unlock()
		fmt.Println("💬 Sohbet Bağlantısı Koptu.")
	}()

	header := make([]byte, 4)

	for {
		// 1. Uzunluk Oku
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}

		length := binary.LittleEndian.Uint32(header)
		if length > 1024*10 { // Max 10KB mesaj (Spam koruması)
			return
		}

		// 2. Metni Oku
		msgBuf := make([]byte, length)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return
		}

		text := string(msgBuf)
		
		// Logla veya UI'a ilet
		fmt.Printf("📩 Gelen Mesaj: %s\n", text)
		
		if m.onMessage != nil {
			m.onMessage(text)
		}
	}
}
	*/

	package chat

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"src-engine-v2/internal/config"
	"sync"
	"time"
)

type Manager struct {
	activeConn net.Conn
	mu         sync.Mutex
	
	// Mesaj geldiğinde tetiklenecek fonksiyon (UI'a iletmek için)
	onMessage func(string)
}

func NewManager() *Manager {
	return &Manager{}
}

// SetCallback: Gelen mesajı yakalamak için
func (m *Manager) SetCallback(cb func(string)) {
	m.onMessage = cb
}

// Start: 9004 portunu dinler
func (m *Manager) Start(ln net.Listener) {
	fmt.Printf("💬 Sohbet Servisi Hazır (Port: %d)\n", config.PortChat)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("❌ Chat Accept Hatası:", err)
			return
		}

		m.mu.Lock()
		// 🔥 KRİTİK DÜZELTME: Eski bağlantı varsa kapat, YENİYE İZİN VER.
		// Eskiden 'continue' diyip yeniyi atıyorduk, şimdi eskisini atıyoruz.
		if m.activeConn != nil {
			fmt.Println("⚠️ Yeni sohbet bağlantısı geldi, eski oturum düşürülüyor.")
			m.activeConn.Close()
		}
		m.activeConn = conn
		m.mu.Unlock()

		fmt.Println("💬 Sohbet Bağlantısı Kuruldu:", conn.RemoteAddr())

		// TCP KeepAlive Ayarları (Kopmaları hızlı anlasın)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(10 * time.Second)
		}

		go m.readLoop(conn)
	}
}

// Send: Karşı tarafa mesaj gönderir
func (m *Manager) Send(text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.activeConn == nil {
		return fmt.Errorf("sohbet bağlantısı yok")
	}

	data := []byte(text)
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(data)))

	// Yazma zaman aşımı (5 saniye içinde gitmezse hata ver)
	_ = m.activeConn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// 1. Header Yaz
	if _, err := m.activeConn.Write(header); err != nil {
		return err
	}
	// 2. Mesaj Yaz
	if _, err := m.activeConn.Write(data); err != nil {
		return err
	}

	// Zaman aşımını sıfırla
	_ = m.activeConn.SetWriteDeadline(time.Time{})

	return nil
}

func (m *Manager) readLoop(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		// Sadece kopan bağlantı "aktif" olansa activeConn'u null yap.
		// Yoksa yeni gelen bağlantıyı yanlışlıkla null yapabiliriz (Race Condition).
		if m.activeConn == conn {
			m.activeConn = nil
		}
		m.mu.Unlock()
		conn.Close()
		fmt.Println("💬 Sohbet Bağlantısı Koptu.")
	}()

	header := make([]byte, 4)

	for {
		// 1. Uzunluk Oku
		if _, err := io.ReadFull(conn, header); err != nil {
			if err != io.EOF {
				fmt.Println("❌ Chat Okuma Hatası (Header):", err)
			}
			return
		}

		length := binary.LittleEndian.Uint32(header)
		
		// 🔥 LİMİT ARTIRILDI: 10KB -> 5MB
		// Pano verisi (büyük metinler) gelebileceği için limiti artırdık.
		if length > 5*1024*1024 { 
			fmt.Println("⚠️ Çok büyük chat paketi, bağlantı kesiliyor.")
			return
		}

		// 2. Metni Oku
		msgBuf := make([]byte, length)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			fmt.Println("❌ Chat Okuma Hatası (Body):", err)
			return
		}

		text := string(msgBuf)
		
		// Logla veya UI'a ilet
		// fmt.Printf("📩 Gelen Mesaj: %s\n", text) // Çok spam olmasın diye kapattım
		
		if m.onMessage != nil {
			m.onMessage(text)
		}
	}
}