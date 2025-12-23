package chat

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