package tggodecrypt

import (
	"encoding/json"
	"github.com/0z0sk0/tdgodecrypt/tdata"
	"github.com/0z0sk0/tdgodecrypt/tdata/decrypted"
	"github.com/0z0sk0/tdgodecrypt/tdata/encrypted"
	"log"
	"os"
)

type DecryptedMap decrypted.DMap

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

// DecryptMapFile decrypt map-file normally located in tdata/D877F783D5D3EF8C/map0
//
// produces
//
// []byte output, that can be used in ExportDecryptedMap
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

// ExportDecryptedMap converts values obtained from DecryptMapFile to human-readable form
//
// produces
//
// DecryptedMap struct, with strings keys and uint32 values
func ExportDecryptedMap(data []byte) (out decrypted.DMap) {
	var err error

	out, err = decrypted.ReadDMap(data)
	if err != nil {
		log.Fatalf("could not decrypt map data: %+v", err)
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

// DecryptSettingsFile decrypt settings-file normally located in tdata/settingss
//
// produces
//
// []byte output, that can be converted with json.Marshal
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
