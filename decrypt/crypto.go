package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/pbkdf2"

	"github.com/karlmcguire/ige"
)

var (
	LocalEncryptNoPwdIterCount = 4
	LocalEncryptIterCount      = 400
	KStrongIterationsCount     = 100000
)

// CreateLocalLegacyKey creates the key used by DecryptLocal. Legacy must use for settings.
func CreateLocalLegacyKey(pass []byte, salt []byte) []byte {
	iter := LocalEncryptNoPwdIterCount
	if len(pass) > 0 {
		iter = LocalEncryptIterCount
	}

	keyLen := 256
	result := pbkdf2.Key(pass, salt, iter, keyLen, sha1.New)

	return result
}

// CreateLocalKey creates the key used by DecryptLocal. The default password is empty.
func CreateLocalKey(pass []byte, salt []byte) []byte {
	iter := 1
	if len(pass) > 0 {
		iter = KStrongIterationsCount
	}

	hash := sha512.New()
	hash.Write(salt)
	hash.Write(pass)
	hash.Write(salt)

	password := make([]byte, 0)
	password = hash.Sum(password)

	keyLen := 256
	result := pbkdf2.Key(password, salt, iter, keyLen, sha512.New)

	return result
}

// DecryptLocal decrypts a message. localKey should be created at CreateLocalKey.
func DecryptLocal(encryptedMsg []byte, localKey []byte) (decrypted []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			decrypted = nil
			err = fmt.Errorf("error decrypting data: %v", r)
		}
	}()

	if len(encryptedMsg) < 16 {
		return nil, fmt.Errorf("encrypted message too short (%d)", len(encryptedMsg))
	}

	msgKey := encryptedMsg[:16]
	encrypted := encryptedMsg[16:]

	decrypted, err = AESDecryptLocal(encrypted, localKey, msgKey)
	sum := sha1.Sum(decrypted)
	hash := sum[:16]
	if !bytes.Equal(hash, msgKey) {
		return nil, fmt.Errorf("bad decrypt key (incorrect password)")
	}

	return decrypted, nil
}

func AESDecryptLocal(encrypted []byte, localKey []byte, msgKey []byte) (decrypted []byte, err error) {
	decrypted = make([]byte, len(encrypted))
	aesKey, aesIV := PrepareAESoldmtp(localKey, msgKey)
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher: %v", err)
	}

	i := ige.NewIGEDecrypter(cipher, aesIV)
	i.CryptBlocks(decrypted, encrypted)

	return decrypted, nil
}

// PrepareAESoldmtp produces key and iv, using localKey and msgKey. localKey comes from CreateLocalKey, msgKey are the first 16 bytes from encrypted message.
func PrepareAESoldmtp(localKey []byte, msgKey []byte) (key []byte, iv []byte) {
	dataA := []byte{}
	dataA = append(dataA, msgKey...)
	dataA = append(dataA, localKey[8:][:32]...)

	dataB := []byte{}
	dataB = append(dataB, localKey[(8 + 32):][:16]...)
	dataB = append(dataB, msgKey...)
	dataB = append(dataB, localKey[(8 + 32 + 16):][:16]...)

	dataC := []byte{}
	dataC = append(dataC, localKey[(8 + 32 + 16 + 16):][:32]...)
	dataC = append(dataC, msgKey...)

	dataD := []byte{}
	dataD = append(dataD, msgKey...)
	dataD = append(dataD, localKey[(8 + 32 + 16 + 16 + 32):][:32]...)

	sha1A := sha1.Sum(dataA)
	sha1B := sha1.Sum(dataB)
	sha1C := sha1.Sum(dataC)
	sha1D := sha1.Sum(dataD)

	key = []byte{}
	key = append(key, sha1A[:8]...)
	key = append(key, sha1B[8:20]...)
	key = append(key, sha1C[4:16]...)

	iv = []byte{}
	iv = append(iv, sha1A[8:20]...)
	iv = append(iv, sha1B[:8]...)
	iv = append(iv, sha1C[16:20]...)
	iv = append(iv, sha1D[:8]...)

	return key, iv
}
