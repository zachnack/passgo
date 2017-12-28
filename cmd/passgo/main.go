package main

import (
	"os"
	"path"

	"github.com/zachneal/passgo"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/urfave/cli.v1"
)

func main() {
	app := cli.NewApp()
	app.Name = "passgo"
	app.Usage = "manage your passwords"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "keyring",
			Value:  "./keyring.skr",
			Usage:  "path to pgp keyring",
			EnvVar: "PASSGO_KEYRING",
		},
		cli.StringFlag{
			Name:   "store",
			Value:  "./password-store",
			Usage:  "path to password store folder",
			EnvVar: "PASSGO_STORE",
		},
	}
	app.Run(os.Args)
}

func prompt(key []openpgp.Key) error {
	pw, err := terminal.ReadPassword(0)
	if err != nil {
		return err
	}

	errcheck := func(e error) {
		if err != nil {
			err = e
		}
	}

	for _, k := range key {
		errcheck(k.PrivateKey.Decrypt(pw))
	}
	return err
}
func open(keyring, store string) (*passgo.Store, error) {
	keyring = path.Clean(keyring)
	store = path.Clean(store)
	keys, err := passgo.ReadKeyRing(keyring)
	if err != nil {
		return nil, err
	}
	return passgo.Open(store, keys, prompt)
}

func read(c *cli.Context) error {
	_, err := open(c.String("keyring"), c.String("store"))
	return err
}
