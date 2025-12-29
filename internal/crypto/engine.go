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

// CryptoSession хранит производный ключ в памяти
type CryptoSession struct {
	key []byte
}

func deriveKey(password string, salt []byte) []byte {
	// Параметры Argon2id для высокой стойкости
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, keyLen)
}

func NewSession(password string, salt []byte) *CryptoSession {
	return &CryptoSession{key: deriveKey(password, salt)}
}

func (s *CryptoSession) Encrypt(plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Пересоздаем сессионный ключ с солью для конкретной записи
	key := deriveKey(string(s.key), salt) // В реальном приложении лучше передать исходный пароль
	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return append(salt, ciphertext...), nil
}

func Decrypt(data []byte, password string) ([]byte, error) {
	if len(data) < saltSize+12 {
		return nil, errors.New("data too short")
	}

	salt := data[:saltSize]
	nonceSize := 12
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}