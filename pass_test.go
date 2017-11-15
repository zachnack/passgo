package passgo_test

import (
	"io/ioutil"
	"path"
	"testing"

	"github.com/nill/passgo"
	"golang.org/x/crypto/openpgp"
)

func testprompt(keys []openpgp.Key) error {
	success := false
	var err error
	pass := []byte("testing")
	for _, k := range keys {
		if k.PrivateKey == nil {
			continue
		}
		// only throw an error if all decryptions failed
		if e := k.PrivateKey.Decrypt(pass); e != nil {
			err = e
		} else {
			success = true
		}
	}
	if success {
		return nil
	}
	return err
}

func setup() (*passgo.Store, error) {
	dir := path.Join("testdata", "store")
	keyring := path.Join("testdata", "private.key")
	keys, err := passgo.ReadKeyRing(keyring)
	if err != nil {
		return nil, err
	}
	pw, err := passgo.Open(dir, keys, testprompt)
	return pw, err
}

func TestOpen(t *testing.T) {
	_, err := setup()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFilter(t *testing.T) {
	keyring := path.Join("testdata", "private.key")
	keys, err := passgo.ReadKeyRing(keyring)
	if err != nil {
		t.Fatal(err)
	}
	keys = passgo.Filter(keys, "testing", "testing1")
	if len(keys.EntityList) != 2 {
		t.Fatal("Failed to filter keyring")
	}
}

func TestReadKeyRing(t *testing.T) {
	keyring := path.Join("testdata", "private.key")
	_, err := passgo.ReadKeyRing(keyring)
	if err != nil {
		t.Fatal(err)
	}
}

func TestList(t *testing.T) {
	pw, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	ls := pw.List()
	if ls == nil {
		t.Fatal("Failed to list")
	}
}

func TestWrite(t *testing.T) {
	pw, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := pw.Write("write.gpg")
	if err != nil {
		t.Fatal(err)
	}
	defer plaintext.Close()
	_, err = plaintext.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRead(t *testing.T) {
	pw, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	r, err := pw.Read("read.gpg")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
}
