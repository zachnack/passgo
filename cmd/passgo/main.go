package main

import (
	"os"
	"gopkg.in/urfave/cli.v1"
)

func main() {
	app := cli.NewApp()
	app.Name = "passgo"
	app.Usage = "manage your passwords"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "keyring",
			Value: "./keyring.skr",
			Usage: "path to pgp keyring",
			EnvVar: "PASSGO_KEYRING",
		},
		cli.StringFlag {
			Name: "store",
			Value: "./password-store",
			Usage: "path to password store folder",
			EnvVar: "PASSGO_STORE",
		},
	}
	app.Run(os.Args)
}