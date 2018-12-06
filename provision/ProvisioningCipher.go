package provision

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/RadicalApp/libsignal-protocol-go/cipher"

	"github.com/RadicalApp/libsignal-protocol-go/kdf"
	"github.com/RadicalApp/libsignal-protocol-go/keys/root"
	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
)

type ProvisionMessage struct {
	IdentityKeyPublic  []byte `json:"identity_key_public"`
	IdentityKeyPrivate []byte `json:"identity_key_private"`
	UserId             string `json:"user_id"`
	ProvisioningCode   string `json:"provisioning_code"`
	ProfileKey         []byte `json:"profile_key"`
}

type ProvisionEnvelope struct {
	PublicKey []byte `json:"public_key"`
	Body      []byte `json:"body"`
}

func verifyMAC(key, input, mac []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(input)
	return hmac.Equal(m.Sum(nil), mac)
}

func Decrypt(cipherText string, privateKey string) error {
	ourPrivateKey, _ := hex.DecodeString(privateKey)
	envelopeDecode, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return err
	}

	var envelope ProvisionEnvelope
	if err := json.Unmarshal(envelopeDecode, &envelope); err != nil {
		return err
	}
	masterEphemeral := bytehelper.SliceToArray(envelope.PublicKey)
	message := envelope.Body
	if message[0] != 1 {
		return fmt.Errorf("Bad version number on ProvisioningMessage %s", err.Error())
	}
	messages := message[1:]
	versionAndIvAndCiphertext := message[:len(message)-32]
	parts, err := bytehelper.SplitThree(messages, 16, len(messages)-16-32, 32)
	if err != nil {
		fmt.Println(err)
	}
	iv := parts[0]
	ciphertext := parts[1]
	mac := parts[2]
	ivAndCiphertext := append(iv, ciphertext...)

	var keyMaterial []byte
	sharedSecret := kdf.CalculateSharedSecret(masterEphemeral, bytehelper.SliceToArray(ourPrivateKey))
	copy(keyMaterial[:], sharedSecret[:])

	salt := [32]byte{}
	derivedSecretBytes, err := kdf.DeriveSecrets(keyMaterial, salt[:], []byte("Mixin Provisioning Message"), root.DerivedSecretsSize)
	if err != nil {
		fmt.Println(err)
		return err
	}
	aesKey := derivedSecretBytes[:32]
	macKey := derivedSecretBytes[32:]

	if !verifyMAC(macKey, versionAndIvAndCiphertext, mac) {
		return fmt.Errorf("Verify Mac failed")
	}
	plaintext, err := cipher.AesDecrypt(aesKey, ivAndCiphertext)
	// plaintext, err := cipher.Decrypt(iv, key, ciphertext)
	if err != nil {
		fmt.Println(err)
	}
	var provisionMessage ProvisionMessage
	if err := json.Unmarshal(plaintext, &provisionMessage); err != nil {
		return err
	}
	fmt.Println(provisionMessage.UserId)
	return nil
}
