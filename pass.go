package pass

import (
	"bufio"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)

// PromptCallback should decrypt the given pgp private keys.
var PromptCallback func(key []openpgp.Key) error

// Store repsents a password-store.
type Store struct {
	path     string
	entities openpgp.EntityList
}

// Open a password store.
func Open(path string, keys openpgp.EntityList) (*Store, error) {
	s := &Store{
		path:     path,
		entities: keys,
	}
	f, err := os.Open(filepath.Join(path, ".gpg-id"))
	if err != nil {
		return s, err
	}
	defer f.Close()
	// read gpg id file
	var names []string
	buf := bufio.NewScanner(f)
	for buf.Scan() {
		names = append(names, buf.Text())
	}
	err = buf.Err()
	return s, err
}
