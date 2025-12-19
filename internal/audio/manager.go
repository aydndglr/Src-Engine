package audio

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/gen2brain/malgo"
)

// Ses Ayarları
const (
	sampleRate = 48000
	channels   = 2
	// Opus olmadığı için buffer boyutunu malgo'ya bırakacağız ama
	// ağ için makul bir chunk boyutu belirliyoruz.
)

// Manager: Ses işlemlerini yönetir
type Manager struct {
	ctx      *malgo.AllocatedContext
	device   *malgo.Device
	
	sendChan func([]byte) // Veriyi ağa gönderecek callback
	
	// Client oynatma tamponu
	playQueue chan int16
	
	mu       sync.Mutex
	running  bool
}

// NewManager: Ses yöneticisini hazırlar
func NewManager() (*Manager, error) {
	ctx, err := malgo.InitContext(nil, malgo.ContextConfig{}, func(message string) {
		// Logları yut
	})
	if err != nil {
		return nil, err
	}

	return &Manager{
		ctx:       ctx,
		playQueue: make(chan int16, sampleRate*channels), // 1 saniyelik buffer
	}, nil
}

// StartHost: (Yayıncı) Bilgisayarın sesini yakalar (Loopback) ve gönderir.
func (m *Manager) StartHost(onData func([]byte)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.running {
		return nil
	}
	m.sendChan = onData

	// Cihazı Ayarla (Loopback - Sistem Sesi)
	deviceConfig := malgo.DefaultDeviceConfig(malgo.Loopback)
	deviceConfig.Capture.Format = malgo.FormatS16 // Signed 16-bit
	deviceConfig.Capture.Channels = channels
	deviceConfig.SampleRate = sampleRate
	deviceConfig.Alsa.NoMMap = 1 // Linux uyumluluğu için (Windows'ta zararı yok)

	// Callback Tanımla (Yeni Malgo API)
	callbacks := malgo.DeviceCallbacks{
		Data: func(pOutput, pInput []byte, frameCount uint32) {
			// pInput: Ham PCM verisi.
			// Opus kullanmadığımız için bunu direkt kopyalayıp gönderiyoruz.
			
			if frameCount == 0 || len(pInput) == 0 {
				return
			}

			// Veriyi kopyala (Data Race olmasın diye)
			data := make([]byte, len(pInput))
			copy(data, pInput)

			if m.sendChan != nil {
				m.sendChan(data)
			}
		},
	}

	// Cihazı Başlat
	device, err := malgo.InitDevice(m.ctx.Context, deviceConfig, callbacks)
	if err != nil {
		return err
	}

	if err := device.Start(); err != nil {
		return err
	}

	m.device = device
	m.running = true
	fmt.Println("🎤 Ses Yakalama (PCM Loopback) Başladı.")
	return nil
}

// StartClient: (İzleyici) Ağdan gelen sesi hoparlörden verir.
func (m *Manager) StartClient() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	// Playback Cihazı Ayarla
	deviceConfig := malgo.DefaultDeviceConfig(malgo.Playback)
	deviceConfig.Playback.Format = malgo.FormatS16
	deviceConfig.Playback.Channels = channels
	deviceConfig.SampleRate = sampleRate

	// Callback: Hoparlör veri istiyor
	callbacks := malgo.DeviceCallbacks{
		Data: func(pOutput, pInput []byte, frameCount uint32) {
			sampleCount := int(frameCount) * channels
			
			for i := 0; i < sampleCount; i++ {
				var val int16
				select {
				case val = <-m.playQueue:
				default:
					val = 0 // Veri yoksa sessizlik
				}
				
				// Int16 -> Byte (Little Endian)
				pOutput[i*2] = byte(val)
				pOutput[i*2+1] = byte(val >> 8)
			}
		},
	}

	// Başlat
	device, err := malgo.InitDevice(m.ctx.Context, deviceConfig, callbacks)
	if err != nil {
		return err
	}
	if err := device.Start(); err != nil {
		return err
	}

	m.device = device
	m.running = true
	fmt.Println("🔊 Ses Oynatma (PCM) Başladı.")
	return nil
}

// PlayPacket: Client tarafında ağdan gelen paketi işler
func (m *Manager) PlayPacket(data []byte) {
	// Raw PCM verisi geliyor, bunu int16'ya çevirip kuyruğa atıyoruz
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			break
		}
		val := int16(binary.LittleEndian.Uint16(data[i : i+2]))
		
		// Kuyruğa at (Doluysa atla - blocking yapma)
		select {
		case m.playQueue <- val:
		default:
			// Buffer dolu, paketi düşür (Latency artmasın)
			return
		}
	}
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.device != nil {
		m.device.Uninit()
	}
	if m.ctx != nil {
		m.ctx.Free()
	}
	m.running = false
}