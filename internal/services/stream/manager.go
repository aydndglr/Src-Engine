//go:build windows

package stream

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"src-engine-v2/internal/config"
	"src-engine-v2/internal/platform/win32"
)

// Input Protocol Sabitleri (V2)
const (
	InputHeaderSize = 14
	MaxTextLen      = 256
)

// Manager: Video yayını ve Input yönetim servisi
type Manager struct {
	Config   *config.Config
	Capturer *win32.DxgiCapturer
	Encoder  *Encoder
	Input    *win32.InputManager

	// Durum Yönetimi
	activeConn net.Conn
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		Config:   cfg,
		Capturer: win32.NewDxgiCapturer(0), // 0 = Birincil Ekran
		Input:    win32.NewInputManager(),
		stopChan: make(chan struct{}),
	}
}

// Start: Belirtilen listener üzerinden bağlantıları kabul eder
func (m *Manager) Start(ln net.Listener) {
	fmt.Printf("🎥 Stream Servisi Hazır (Port: %d)\n", config.PortStream)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}

		m.mu.Lock()
		if m.activeConn != nil {
			conn.Close() // Meşgul
			m.mu.Unlock()
			continue
		}
		m.activeConn = conn
		m.running = true
		m.stopChan = make(chan struct{}) // Kanalı yenile
		m.mu.Unlock()

		fmt.Println("🎥 Yeni İzleyici Bağlandı:", conn.RemoteAddr())

		m.handleConnection(conn)
	}
}

func (m *Manager) handleConnection(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		if m.activeConn != nil {
			m.activeConn.Close()
			m.activeConn = nil
		}
		m.running = false
		m.mu.Unlock()

		m.Capturer.Close()
		if m.Encoder != nil {
			m.Encoder.Close()
		}
		fmt.Println("🎥 Yayın Sonlandı.")
	}()

	// 1. Video Başlatma
	if err := m.Capturer.Start(); err != nil {
		fmt.Println("❌ Capture hatası:", err)
		return
	}
	realW, realH := m.Capturer.Size()

	// Encoder başlat
	// Not: FPS değeri Config'den geliyor (25 veya 30 ne ayarladıysan)
	enc, err := NewEncoder(realW, realH, m.Config.Video.Width, m.Config.Video.Height, m.Config.Video.FPS)
	if err != nil {
		fmt.Println("❌ Encoder hatası:", err)
		return
	}
	m.Encoder = enc

	sendChan := make(chan []byte, 5)

	var wg sync.WaitGroup
	wg.Add(3)

	// A) Input Okuyucu
	go func() {
		defer wg.Done()
		m.readInputLoop(conn)
		close(m.stopChan)
	}()

	// B) Video Yakalayıcı
	go func() {
		defer wg.Done()
		m.captureLoop(sendChan)
	}()

	// C) Video Gönderici
	go func() {
		defer wg.Done()
		m.writeLoop(conn, sendChan)
	}()

	<-m.stopChan
}

// --- LOOPLAR ---

func (m *Manager) captureLoop(out chan<- []byte) {
	// FPS ayarını Config'den alıyoruz (Sen 25 yaptıysan 25 çalışır)
	interval := time.Second / time.Duration(m.Config.Video.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if len(out) >= cap(out)-1 {
				continue
			}

			img, err := m.Capturer.Capture()
			if err != nil {
				continue
			}

			data := m.Encoder.Encode(img)
			if len(data) == 0 {
				continue
			}

			select {
			case out <- data:
			case <-m.stopChan:
				return
			}
		}
	}
}

func (m *Manager) writeLoop(conn net.Conn, in <-chan []byte) {
	// Bitrate seviyeleri (kbps)
	levels := []int{500, 800, 1200, 1800, 2500, 4000}
	levelIdx := 3 // Başlangıç: 1800

	lastCheck := time.Now()
	congestedStart := time.Time{}
	relaxedStart := time.Time{}

	headerBuf := make([]byte, 4)

	for {
		select {
		case <-m.stopChan:
			return
		case data, ok := <-in:
			if !ok {
				return
			}

			// --- ADAPTIVE BITRATE LOGIC ---
			now := time.Now()
			if now.Sub(lastCheck) > 2*time.Second {
				qSize := len(in)

				if qSize >= 3 {
					relaxedStart = time.Time{}
					if congestedStart.IsZero() {
						congestedStart = now
					} else if now.Sub(congestedStart) > 2*time.Second {
						if levelIdx > 0 {
							levelIdx--
							m.Encoder.SetBitrate(levels[levelIdx])
							fmt.Printf("📉 Bitrate Düşürüldü: %d kbps\n", levels[levelIdx])
						}
						congestedStart = time.Time{}
						lastCheck = now
					}
				} else if qSize == 0 {
					congestedStart = time.Time{}
					if relaxedStart.IsZero() {
						relaxedStart = now
					} else if now.Sub(relaxedStart) > 5*time.Second {
						if levelIdx < len(levels)-1 {
							levelIdx++
							m.Encoder.SetBitrate(levels[levelIdx])
							fmt.Printf("📈 Bitrate Artırıldı: %d kbps\n", levels[levelIdx])
						}
						relaxedStart = time.Time{}
						lastCheck = now
					}
				}
			}

			// 1. RAW MOD KONTROLÜ
			// Electron header bekler, o yüzden RawMode kapalıysa boyutu gönderiyoruz.
			if !m.Config.Video.RawMode {
				binary.LittleEndian.PutUint32(headerBuf, uint32(len(data)))
				if _, err := conn.Write(headerBuf); err != nil {
					return
				}
			}

			// 2. Veriyi Yaz
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}
}

func (m *Manager) readInputLoop(conn net.Conn) {
	header := make([]byte, InputHeaderSize)
	for {
		// Header Oku
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}

		// Protokol Parse
		device := header[0]
		action := header[1]
		flags := uint32(header[2])

		x := binary.LittleEndian.Uint16(header[4:6])
		y := binary.LittleEndian.Uint16(header[6:8])
		wheel := int16(binary.LittleEndian.Uint16(header[8:10]))
		key := binary.LittleEndian.Uint16(header[10:12])
		textLen := int(binary.LittleEndian.Uint16(header[12:14]))

		// Text varsa oku (Klavye için)
		var textBuf []byte
		if textLen > 0 {
			if textLen > MaxTextLen {
				return // Protokol hatası
			}
			textBuf = make([]byte, textLen)
			if _, err := io.ReadFull(conn, textBuf); err != nil {
				return
			}
		}

		// --- MOUSE VE KLAVYE İŞLEME (DÜZELTİLMİŞ) ---
		switch device {
		case 0: // Mouse
			// 1. Önce Hareketi Uygula
			_ = m.Input.MoveMouse(x, y)

			// 2. Tıklamaları Çevir (Electron Flags -> Windows API)
			// Electron: 1=Sol, 2=Sağ, 4=Orta
			
			if action == 1 { // MouseDown
				if flags&1 != 0 { m.Input.MouseLeftDown() }
				if flags&2 != 0 { m.Input.MouseRightDown() }
				if flags&4 != 0 { m.Input.MouseMiddleDown() }
			} else if action == 2 { // MouseUp
				if flags&1 != 0 { m.Input.MouseLeftUp() }
				if flags&2 != 0 { m.Input.MouseRightUp() }
				if flags&4 != 0 { m.Input.MouseMiddleUp() }
			} else if action == 3 { // Wheel
				m.Input.MouseWheel(wheel)
			}

		case 1: // Keyboard
			if action == 4 && len(textBuf) > 0 {
				// Unicode Karakter Yazma (Chat gibi)
				runes := []rune(string(textBuf))
				for _, r := range runes {
					m.Input.KeyUnicode(r)
				}
			} else {
				// Standart Tuşlar (Oyun/Kısayol)
				if action == 1 { // Down
					_ = m.Input.KeyScancode(key, false, (flags&1) != 0)
				} else if action == 2 { // Up
					_ = m.Input.KeyScancode(key, true, (flags&1) != 0)
				}
			}
		}
	}
}