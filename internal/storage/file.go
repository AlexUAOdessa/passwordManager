package storage

import (
	"os"
)

const DbFileName = "vault.bin"

func Save(data []byte) error {
	return os.WriteFile(DbFileName, data, 0600)
}

func Load() ([]byte, error) {
	return os.ReadFile(DbFileName)
}