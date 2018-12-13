package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"syscall/js"

	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/keys/identity"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"github.com/RadicalApp/libsignal-protocol-go/util/keyhelper"
)

func generateIdentityKeyPair(this js.Value, args []js.Value) interface{} {
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()

	if err != nil {
		// TODO
		fmt.Println(err.Error())
	}
	publicKey := identityKeyPair.PublicKey().Serialize()
	privateKey := identityKeyPair.PrivateKey().Serialize()
	pub := hex.EncodeToString(publicKey[:])
	priv := hex.EncodeToString(privateKey[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	keyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		// TODO
		fmt.Println(err.Error())
	}
	public := keyPair.PublicKey().Serialize()
	private := keyPair.PrivateKey().Serialize()
	pub := hex.EncodeToString(public[:])
	priv := hex.EncodeToString(private[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func createKeyPair(this js.Value, args []js.Value) interface{} {
	privateKey := args[0].String()
	decoded, _ := base64.StdEncoding.DecodeString(privateKey)
	keyPair := ecc.CreateKeyPair(decoded)

	public := keyPair.PublicKey().Serialize()
	private := keyPair.PrivateKey().Serialize()
	pub := hex.EncodeToString(public[:])
	priv := hex.EncodeToString(private[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func generateRegId(this js.Value, args []js.Value) interface{} {
	return keyhelper.GenerateRegistrationID()
}

func generateSignedPreKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		// TODO
	}
	pub, priv, id := args[0], args[1], args[2]
	public, _ := hex.DecodeString(pub.String())
	private, _ := hex.DecodeString(priv.String())

	privateKey := ecc.NewDjbECPrivateKey(bytehelper.SliceToArray(private))
	publicKey := identity.NewKeyFromBytes(bytehelper.SliceToArray(public), 0)
	identityKeyPair := identity.NewKeyPair(&publicKey, privateKey)
	serializer := serialize.NewProtoBufSerializer()
	signedPeKey, _ := keyhelper.GenerateSignedPreKey(identityKeyPair, uint32(id.Int()), serializer.SignedPreKeyRecord)
	h := hex.EncodeToString(signedPeKey.Serialize())
	return map[string]interface{}{"id": signedPeKey.ID(), "record": h}
}

func generatePreKeys(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		// TODO
	}
	start, end := args[0].Int(), args[1].Int()
	serializer := serialize.NewProtoBufSerializer()
	preKeys, err := keyhelper.GeneratePreKeys(start, end, serializer.PreKeyRecord)
	if err != nil {
		fmt.Println(err.Error())
	}
	var encodePreKeys []string
	for _, preKey := range preKeys {
		encodePreKeys = append(encodePreKeys, hex.EncodeToString(preKey.Serialize()))
	}
	return strings.Join(encodePreKeys, ",")
}

func registerCallbacks() {
	js.Global().Set("generateIdentityKeyPaireFromGo", js.NewCallback(generateIdentityKeyPair))
	js.Global().Set("generateKeyPairFromGo", js.NewCallback(generateKeyPair))
	js.Global().Set("generateSignedPreKeyFromGo", js.NewCallback(generateSignedPreKey))
	js.Global().Set("generatePreKeysFromGo", js.NewCallback(generatePreKeys))
	js.Global().Set("generateRegIdFromGo", js.NewCallback(generateRegId))
	js.Global().Set("createKeyPairFromGo", js.NewCallback(createKeyPair))
}

func main() {
	c := make(chan struct{}, 0)
	registerCallbacks()
	<-c
}
