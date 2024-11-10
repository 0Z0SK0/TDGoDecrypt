package tggodecrypt

import (
	"encoding/json"
	"github.com/0z0sk0/tdgodecrypt/tdata"
	"github.com/0z0sk0/tdgodecrypt/tdata/decrypted"
	"github.com/0z0sk0/tdgodecrypt/tdata/encrypted"
	"log"
	"os"
)

func GetMapKey(mapPath string, password string) (out []byte) {
	f, err := os.Open(mapPath)
	if err != nil {
		log.Fatalf("could not open file '%s': %+v", mapPath, err)
	}
	defer f.Close()

	rawTDF, err := tdata.ReadRawTDF(f)
	if err != nil {
		log.Fatalf("could not interpret file '%s': %+v", mapPath, err)
	}

	eMap, err := encrypted.ReadEMap(rawTDF)
	if err != nil {
		log.Fatalf("could not interpret map file: %+v", err)
	}

	out, err = eMap.GetKey(password)
	if err != nil {
		log.Fatalf("could not decrypt map file: %+v", err)
	}

	return out
}

func DecryptMapFile(mapPath string, password string) (out []byte) {
	f, err := os.Open(mapPath)
	if err != nil {
		log.Fatalf("could not open file '%s': %+v", mapPath, err)
	}
	defer f.Close()

	rawTDF, err := tdata.ReadRawTDF(f)
	if err != nil {
		log.Fatalf("could not interpret file '%s': %+v", mapPath, err)
	}

	eMap, err := encrypted.ReadEMap(rawTDF)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	out, err = eMap.Decrypt(password)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	return out
}

func GetSettingsKey(settingsPath string, password string) (out []byte) {
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

	out = settings.GetKey(password)

	return out
}

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
