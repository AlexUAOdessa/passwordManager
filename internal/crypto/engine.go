package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize = 16
	keyLen   = 32 // AES-256
)

type CryptoSession struct {
	key []byte
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, keyLen)
}

func NewSession(password string, salt []byte) *CryptoSession {
	return &CryptoSession{key: deriveKey(password, salt)}
}

func (s *CryptoSession) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Возвращаем Nonce + Ciphertext. Соль добавим в app.go при сохранении.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(data []byte, password string) ([]byte, error) {
	if len(data) < saltSize+12 {
		return nil, errors.New("данные слишком короткие")
	}

	salt := data[:saltSize]
	payload := data[saltSize:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return nil, errors.New("неверный формат данных")
	}

	nonce, ciphertext := payload[:nonceSize], payload[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}