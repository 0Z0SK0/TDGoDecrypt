package tggodecrypt

import (
	"encoding/json"
	"github.com/0z0sk0/tdgodecrypt/tdata"
	"github.com/0z0sk0/tdgodecrypt/tdata/decrypted"
	"github.com/0z0sk0/tdgodecrypt/tdata/encrypted"
	"log"
	"os"
)

func DecryptSettingsFile(settingsPath string, password string) (out []byte) {
	f, err := os.Open(settingsPath)
	if err != nil {
		log.Fatalf("could not open file '%s': %+v", settingsPath, err)
	}
	defer f.Close()

	rawTDF, err := tdata.ReadRawTDF(f)
	if err != nil {
		log.Fatalf("could not interpret file '%s': %+v", settingsPath, err)
	}

	settings, err := encrypted.ReadESettings(rawTDF)
	if err != nil {
		log.Fatalf("could not interpret settings file: %+v", err)
	}

	settingsKey := settings.GetKey(password)
	plain, err := settings.Decrypt(settingsKey)
	if err != nil {
		log.Fatalf("could not decrypt settings file: %+v", err)
	}

	parsed, err := decrypted.ParseCache(plain, decrypted.ReverseLSK(decrypted.UserSettings{}))
	if err != nil {
		log.Fatalf("could not interpret settings file: %+v", err)
	}

	out, err = json.Marshal(parsed)
	if err != nil {
		log.Fatalf("could not interpret settings file: %+v", err)
	}

	return out
}
