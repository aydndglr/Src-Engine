package audio

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"src-engine-v2/internal/config"

	"github.com/gen2brain/malgo"
)

// Ses Ayarları
const (
	SampleRate = 48000
	Channels   = 2
	Format     = malgo.FormatS16 // 16-bit Signed Integer
)

type Manager struct {
	ctx      *malgo.AllocatedContext
	device   *malgo.Device
	
	activeConn net.Conn
	mu         sync.Mutex
	running    bool
	
	// Ses Verisi Kanalı
	dataChan chan []byte
}

func NewManager() *Manager {
	// Malgo Context başlat (Logları kapat)
	ctx, err := malgo.InitContext(nil, malgo.ContextConfig{}, func(message string) {})
	if err != nil {
		log.Println("⚠️ Ses sistemi başlatılamadı:", err)
		return nil
	}

	return &Manager{
		ctx:      ctx,
		dataChan: make(chan []byte, 50), // Tampon
	}
}

// Start: 9002 portundan gelen bağlantıyı kabul eder ve sesi basar
func (m *Manager) Start(ln net.Listener) {
	if m.ctx == nil {
		return // Ses sistemi yoksa hiç başlama
	}
	
	fmt.Printf("🔊 Ses Servisi Hazır (Port: %d)\n", config.PortAudio)

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
		m.mu.Unlock()

		fmt.Println("🔊 Ses Dinleyicisi Bağlandı.")
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
		
		m.stopCapture()
		fmt.Println("🔊 Ses Yayını Bitti.")
	}()

	// 1. Ses Yakalamayı Başlat
	if err := m.startCapture(); err != nil {
		fmt.Println("❌ Ses yakalama hatası:", err)
		return
	}

	// 2. Gönderim Döngüsü
	headerBuf := make([]byte, 4)
	for data := range m.dataChan {
		// Header (Size)
		binary.LittleEndian.PutUint32(headerBuf, uint32(len(data)))

		// Yaz (Timeout ile)
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(headerBuf); err != nil {
			return
		}
		if _, err := conn.Write(data); err != nil {
			return
		}
	}
}

func (m *Manager) startCapture() error {
	deviceConfig := malgo.DefaultDeviceConfig(malgo.Loopback)
	deviceConfig.Capture.Format = Format
	deviceConfig.Capture.Channels = Channels
	deviceConfig.SampleRate = SampleRate
	deviceConfig.Alsa.NoMMap = 1

	// Callback: Ses kartından veri geldikçe burası tetiklenir
	onRecv := func(pOutput, pInput []byte, frameCount uint32) {
		if frameCount == 0 {
			return
		}
		
		// Veriyi kopyala (Malgo buffer'ı uçucudur)
		// pInput boyutu = frameCount * Channels * BytesPerSample(2)
		packet := make([]byte, len(pInput))
		copy(packet, pInput)

		// Kanal üzerinden göndericiye ilet
		// Kanal doluysa bu paketi at (Drop) - Gecikme olmasın
		select {
		case m.dataChan <- packet:
		default:
		}
	}

	callbacks := malgo.DeviceCallbacks{
		Data: onRecv,
	}

	device, err := malgo.InitDevice(m.ctx.Context, deviceConfig, callbacks)
	if err != nil {
		return err
	}

	if err := device.Start(); err != nil {
		return err
	}

	m.device = device
	return nil
}

func (m *Manager) stopCapture() {
	if m.device != nil {
		m.device.Uninit()
		m.device = nil
	}
	// Kanalı boşalt
	for len(m.dataChan) > 0 {
		<-m.dataChan
	}
}

func (m *Manager) Close() {
	m.stopCapture()
	if m.ctx != nil {
		m.ctx.Free()
		m.ctx = nil
	}
}