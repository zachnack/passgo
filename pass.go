package passgo

import (
	"bufio"
	"io"
	"os"
	"path"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
)

var (
	// ErrNotDir file is not dir.
	ErrNotDir = errors.New("file is not directory")
)

// Store repsents a password-store eg ~/.password-store.
type Store struct {
	dir     string
	keyring Entities
	prompt  PromptFunc
}

// Entities represents the components of an OpenPGP key:
// a primary public key (which must be a signing key), one or more identities claimed by that key,
// and zero or more subkeys, which may be encryption keys.
type Entities struct {
	openpgp.EntityList
}

// PromptFunc is a callback function that decrypt pgp private keys.
type PromptFunc func(keys []openpgp.Key) error

// Open a password store.
func Open(dir string, keys Entities, prompt PromptFunc) (*Store, error) {
	s := &Store{
		dir:     dir,
		keyring: keys,
		prompt:  prompt,
	}
	f, err := os.Open(path.Join(dir, ".gpg-id"))
	if err != nil {
		return s, errors.Wrap(err, "Can't open password store")
	}
	defer f.Close()
	var names []string
	// filter keys by reading gpg-id file
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		names = append(names, scanner.Text())
	}
	if scanner.Err() != nil {
		return s, errors.Wrap(err, "Can't filter gpg ids")
	}
	s.keyring = Filter(keys, names...)
	return s, err
}

// Read and decrypt entry from a password store.
func (s *Store) Read(name string) (io.Reader, error) {
	if path.Ext(name) != ".gpg" {
		name = name + ".gpg"
	}
	f, err := os.Open(path.Join(s.dir, name))
	if err != nil {
		return f, err
	}
	p := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		err := s.prompt(keys)
		return nil, err
	}

	md, err := openpgp.ReadMessage(f, s.keyring, p, nil)
	// nesscary err check to prevent null pointer panic
	if err != nil {
		return nil, err
	}
	return md.UnverifiedBody, err
}

// Write and encrypt an entry from a password store.
func (s *Store) Write(name string) (io.WriteCloser, error) {
	if path.Ext(name) != ".gpg" {
		name = name + ".gpg"
	}
	f, err := os.OpenFile(path.Join(s.dir, name), os.O_RDWR|os.O_CREATE, os.FileMode(0666))
	if err != nil {
		return nil, err
	}
	var el openpgp.EntityList
	for _, v := range s.keyring.EntityList.DecryptionKeys() {
		el = append(el, v.Entity)
	}
	plaintext, err := openpgp.Encrypt(f, el, nil, nil, nil)
	return plaintext, err
}

// List all entries in password store.
func (s *Store) List() []string {
	var ls []string
	f, err := os.Open(s.dir)
	if err != nil {
		return ls
	}
	defer f.Close()
	list, err := f.Readdir(0)
	if err != nil {
		return ls
	}
	for _, fi := range list {
		n := fi.Name()
		ext := ".gpg"
		if path.Ext(n) == ext {
			ls = append(ls, n)
		}
	}
	return ls
}

// SubFolders list all subfolders.
func (s *Store) SubFolders() []string {
	var ls []string
	f, err := os.Open(s.dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	d, err := f.Readdir(0)
	if err != nil {
		return nil
	}
	for _, fi := range d {
		if fi.IsDir() {
			ls = append(ls, fi.Name())
		}
	}
	return ls
}

// ReadKeyRing will open a file and read pgp keys.
func ReadKeyRing(filename string) (Entities, error) {
	var keys Entities
	f, err := os.Open(filename)
	if err != nil {
		return keys, errors.Wrap(err, "Can't read keyring")
	}
	defer f.Close()
	k, err := openpgp.ReadKeyRing(f)
	keys = Entities{k}
	if err != nil {
		return keys, errors.Wrap(err, "Can't read keyring")
	}

	return keys, err
}

// Filter openpgp keys by name.
func Filter(keys Entities, names ...string) Entities {
	var ls openpgp.EntityList
	for _, entity := range keys.EntityList {
		for _, name := range names {
			if _, ok := entity.Identities[name]; ok {
				ls = append(ls, entity)
			}
		}
	}
	return Entities{ls}
}
