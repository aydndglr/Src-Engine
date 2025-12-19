package network

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"
)

// GenerateTLSConfig: QUIC bağlantısı için gerekli olan
// güvenli sertifikayı (Self-Signed) anlık olarak üretir.
func GenerateTLSConfig() *tls.Config {
	// 1. Kriptografik Anahtar Oluştur (RSA 2048-bit)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // Anahtar üretilemezse çalışmanın anlamı yok
	}

	// 2. Sertifika Şablonunu Hazırla
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), // Basit bir seri no
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365), // 1 yıl geçerli

		// Bu sertifika hem şifreleme hem imzalama yapabilir
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		
		// Sadece yerel kullanım için genişletilmiş izinler
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// 3. Sertifikayı İmzala (Self-Signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	// 4. PEM Formatına Çevir (Go'nun anlayacağı format)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 5. TLS Konfigürasyonunu Oluştur
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// Uygulamamızın konuştuğu özel protokol adı (Versiyon kontrolü için iyi)
		NextProtos: []string{"src-engine-v1"},
		
		// Biz Headscale içindeyiz ve sertifikamız self-signed.
		// O yüzden tarayıcı gibi "Bu sertifika kimin?" diye sormasını engelliyoruz.
		InsecureSkipVerify: true, 
	}
}