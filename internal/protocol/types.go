package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// --- TİP TANIMLARI ---
type InputDevice uint8
type InputAction uint8

// Sabitler
const (
	DeviceMouse    InputDevice = 0
	DeviceKeyboard InputDevice = 1
)

const (
	MouseMove  InputAction = 0
	MouseDown  InputAction = 1
	MouseUp    InputAction = 2
	MouseWheel InputAction = 3
	KeyText    InputAction = 4
)

// Input protocol versions / limits
const (
	// Yeni format: [Dev][Act][Flg][Pad][X][Y][Wh][Key][TextLen(uint16)][TextBytes]
	// Header = 14 byte
	inputHeaderV2Size = 14

	// Eski format: 12 byte header + geri kalan "text" (TCP stream'de çakışmaya çok müsait)
	inputHeaderV1Size = 12

	// Güvenlik limiti (tek event için)
	maxTextLen = 256
)

// InputEvent: Ağdan gelen verinin Go yapısı
type InputEvent struct {
	Device InputDevice
	Action InputAction
	Flags  uint8
	X      int16
	Y      int16
	Wheel  int16
	Key    uint16
	Text   string
}

// EncodeInputEvent: Event'i byte dizisine çevirir (V2 format)
func EncodeInputEvent(ev InputEvent) ([]byte, error) {
	buf := new(bytes.Buffer)

	// V2 Header: 14 byte
	// [Dev][Act][Flg][Pad][X][Y][Wh][Key][TextLen]
	_ = binary.Write(buf, binary.LittleEndian, uint8(ev.Device))
	_ = binary.Write(buf, binary.LittleEndian, uint8(ev.Action))
	_ = binary.Write(buf, binary.LittleEndian, ev.Flags)
	_ = binary.Write(buf, binary.LittleEndian, uint8(0)) // Padding

	_ = binary.Write(buf, binary.LittleEndian, ev.X)
	_ = binary.Write(buf, binary.LittleEndian, ev.Y)
	_ = binary.Write(buf, binary.LittleEndian, ev.Wheel)
	_ = binary.Write(buf, binary.LittleEndian, ev.Key)

	textBytes := []byte(ev.Text)
	if len(textBytes) > maxTextLen {
		return nil, errors.New("text çok uzun")
	}

	_ = binary.Write(buf, binary.LittleEndian, uint16(len(textBytes)))
	if len(textBytes) > 0 {
		_, _ = buf.Write(textBytes)
	}

	return buf.Bytes(), nil
}

// DecodeInputEvent: Byte dizisini Event'e çevirir
//
// Bu fonksiyon hem V2 (text length'li) hem de eski V1 formatını destekler.
// NOT: TCP stream'de güvenli kullanım için V2 önerilir.
func DecodeInputEvent(data []byte) (InputEvent, error) {
	if len(data) < inputHeaderV1Size {
		return InputEvent{}, errors.New("paket çok kısa")
	}

	dev := InputDevice(data[0])
	act := InputAction(data[1])
	flg := data[2]

	x := int16(binary.LittleEndian.Uint16(data[4:6]))
	y := int16(binary.LittleEndian.Uint16(data[6:8]))
	wh := int16(binary.LittleEndian.Uint16(data[8:10]))
	key := binary.LittleEndian.Uint16(data[10:12])

	// V2 mi? (en az 14 byte varsa text length okuyabiliriz)
	if len(data) >= inputHeaderV2Size {
		textLen := int(binary.LittleEndian.Uint16(data[12:14]))
		if textLen < 0 || textLen > maxTextLen {
			return InputEvent{}, errors.New("geçersiz text uzunluğu")
		}
		if len(data) < inputHeaderV2Size+textLen {
			return InputEvent{}, errors.New("paket eksik (text)")
		}

		txt := ""
		if textLen > 0 {
			txt = string(data[14 : 14+textLen])
		}

		return InputEvent{
			Device: dev,
			Action: act,
			Flags:  flg,
			X:      x,
			Y:      y,
			Wheel:  wh,
			Key:    key,
			Text:   txt,
		}, nil
	}

	// --- V1 fallback ---
	// Eski formatta 12. byte sonrası text kabul ediliyordu (TCP stream'de birleşme riski var).
	// Bu yüzden V1 fallback'te sadece KeyText action ise text okumaya izin veriyoruz.
	txt := ""
	if act == KeyText && len(data) > inputHeaderV1Size {
		// Güvenlik için maxTextLen ile kırpıyoruz
		raw := data[inputHeaderV1Size:]
		if len(raw) > maxTextLen {
			raw = raw[:maxTextLen]
		}
		txt = string(raw)
	}

	return InputEvent{
		Device: dev,
		Action: act,
		Flags:  flg,
		X:      x,
		Y:      y,
		Wheel:  wh,
		Key:    key,
		Text:   txt,
	}, nil
}

// --- VERİ KANALI PROTOKOLÜ (DATA CHANNEL) ---

// Veri Tipleri
const (
	DataTypeClipboard   = 1 // Pano Metni
	DataTypeFileStart   = 2 // Dosya Transferi Başlat (Ad, Boyut) - JSON
	DataTypeFileData    = 3 // Dosya Parçası (Chunk) - Raw Bytes
	DataTypeChat        = 4 // Sohbet Mesajı
	DataTypeAudio       = 5 // Ses Verisi (Opus/PCM)
	DataTypeAudioCmd    = 6 // Ses Komutu (Start/Stop) - YENİ
	DataTypeConnRequest = 7 // Bağlantı İsteği (Engine -> UI) - YENİ
	DataTypeConnDecide  = 8 // Bağlantı Kararı (UI -> Engine) - YENİ
)

// DataHeader: Veri paketinin başlığı (5 Byte)
type DataHeader struct {
	Type uint8
	Size uint32
}

// Dosya Başlangıç Paketi (Metadata)
type FileStartPacket struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// EncodeFileStart: Dosya bilgisini JSON olarak paketler
func EncodeFileStart(name string, size int64) ([]byte, error) {
	return json.Marshal(FileStartPacket{Name: name, Size: size})
}

// DecodeFileStart: Gelen veriyi struct'a çevirir
func DecodeFileStart(data []byte) (FileStartPacket, error) {
	var p FileStartPacket
	err := json.Unmarshal(data, &p)
	return p, err
}

// WriteDataPacket: Veri paketini ağa yazar
func WriteDataPacket(w io.Writer, dataType uint8, data []byte) error {
	// 1. Başlığı hazırla
	header := make([]byte, 5)
	header[0] = dataType
	binary.LittleEndian.PutUint32(header[1:], uint32(len(data)))

	// 2. Başlığı gönder
	if _, err := w.Write(header); err != nil {
		return err
	}

	// 3. Veriyi gönder
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// ReadDataHeader: Gelen verinin başlığını okur
func ReadDataHeader(r io.Reader) (DataHeader, error) {
	buf := make([]byte, 5)
	if _, err := io.ReadFull(r, buf); err != nil {
		return DataHeader{}, err
	}

	return DataHeader{
		Type: buf[0],
		Size: binary.LittleEndian.Uint32(buf[1:]),
	}, nil
}
