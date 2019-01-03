package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"syscall/js"

	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/groups"
	"github.com/RadicalApp/libsignal-protocol-go/keys/identity"
	"github.com/RadicalApp/libsignal-protocol-go/keys/prekey"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/session"
	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"github.com/RadicalApp/libsignal-protocol-go/util/keyhelper"
	"github.com/RadicalApp/libsignal-protocol-go/util/optional"
)

func generateIdentityKeyPair(this js.Value, args []js.Value) interface{} {
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()

	if err != nil {
		// TODO
		fmt.Println(err.Error())
	}
	publicKey := identityKeyPair.PublicKey().Serialize()
	privateKey := identityKeyPair.PrivateKey().Serialize()
	pub := base64.StdEncoding.EncodeToString(publicKey)
	priv := base64.StdEncoding.EncodeToString(privateKey[:])
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
	pub := base64.StdEncoding.EncodeToString(public)
	priv := base64.StdEncoding.EncodeToString(private[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func createKeyPair(this js.Value, args []js.Value) interface{} {
	privateKey := args[0].String()
	decoded, _ := base64.StdEncoding.DecodeString(privateKey)
	keyPair := ecc.CreateKeyPair(decoded)

	public := keyPair.PublicKey().Serialize()
	private := keyPair.PrivateKey().Serialize()
	pub := base64.StdEncoding.EncodeToString(public)
	priv := base64.StdEncoding.EncodeToString(private[:])
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
	public, _ := base64.StdEncoding.DecodeString(pub.String())
	private, _ := base64.StdEncoding.DecodeString(priv.String())

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

func containsSession(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
	}
	name, deviceId := args[0].String(), args[1].Int()
	serializer := serialize.NewProtoBufSerializer()
	sessionStore := NewMixinSessionStore(serializer)
	result := sessionStore.ContainsSession(protocol.NewSignalAddress(name, uint32(deviceId)))
	return result
}

type ConsumeSignedPreKey struct {
	KeyId     int    `json:"key_id"`
	PubKey    []byte `json:"pub_key"`
	Signature []byte `json:"signature"`
}

type ConsumeOneTimeKey struct {
	KeyId  int    `json:"key_id"`
	PubKey []byte `json:"pub_key"`
}

type ConsumePreKeyBundle struct {
	UserId         string              `json:"user_id"`
	RegistrationId int                 `json:"registration_id"`
	IdentityKey    []byte              `json:"identity_key"`
	Signed         ConsumeSignedPreKey `json:"signed_pre_key"`
	OnetimeKey     ConsumeOneTimeKey   `json:"one_time_pre_key"`
}

func processSession(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
	}
	name, deviceId, bundle := args[0].String(), args[1].Int(), args[2].String()

	var preKeyBundle ConsumePreKeyBundle
	err := json.Unmarshal([]byte(bundle), &preKeyBundle)
	if err != nil {
		// TODO
	}
	preKeyPublic, err := ecc.DecodePoint(preKeyBundle.OnetimeKey.PubKey, 0)
	signedPreKeyPublic, err := ecc.DecodePoint(preKeyBundle.Signed.PubKey, 0)
	signature := bytehelper.SliceToArray64(preKeyBundle.Signed.Signature)
	identityKey := identity.NewKeyFromBytes(bytehelper.SliceToArray(preKeyBundle.IdentityKey), 0)

	retrievedPreKey := prekey.NewBundle(uint32(preKeyBundle.RegistrationId), uint32(deviceId),
		optional.NewOptionalUint32(uint32(preKeyBundle.OnetimeKey.KeyId)), uint32(preKeyBundle.Signed.KeyId),
		preKeyPublic, signedPreKeyPublic, signature, &identityKey)

	serializer := serialize.NewProtoBufSerializer()
	sessionStore := NewMixinSessionStore(serializer)
	preKeyStore := NewMixinPreKeyStore(serializer)
	signedPreKeyStore := NewMixinSignedPreKeyStore(serializer)
	identityStore := NewMixinIdentityKeyStore()
	address := protocol.NewSignalAddress(name, uint32(deviceId))
	sessionBuilder := session.NewBuilder(
		sessionStore,
		preKeyStore,
		signedPreKeyStore,
		identityStore,
		address,
		serializer,
	)

	err = sessionBuilder.ProcessBundle(retrievedPreKey)
	if err != nil {
		return err
	}
	return nil
}

func test(this js.Value, args []js.Value) interface{} {
	store := NewMixinIdentityKeyStore()
	store.GetIdentityKeyPair()
	id := store.GetLocalRegistrationId()
	fmt.Println(id)
	return nil
}

func encryptSenderKey(this js.Value, args []js.Value) interface{} {
	// encryptSenderKeyFromGo(groupId, recipientId, recipientDeviceId, senderId, senderDeviceId)
	if len(args) != 5 {
		return nil
	}
	groupId := args[0].String()
	recipientId, recipientDeviceId := args[1].String(), args[2].Int()
	senderId, senderDeviceId := args[3].String(), args[4].Int()
	address := protocol.NewSignalAddress(senderId, uint32(senderDeviceId))
	senderKeyName := protocol.NewSenderKeyName(groupId, address)
	serializer := serialize.NewProtoBufSerializer()
	senderKeyStore := NewMixinSenderKeyStore(serializer)
	builder := groups.NewGroupSessionBuilder(senderKeyStore, serializer)
	senderKeyDistributionMessage, err := builder.Create(senderKeyName)
	if err != nil {
		return nil
	}
	remoteAddress := protocol.NewSignalAddress(recipientId, uint32(recipientDeviceId))
	ciphertextMessage, err := encryptSession(senderKeyDistributionMessage.Serialize(), remoteAddress)
	if err != nil {
		return nil
	}
	return encodeMessageData(ciphertextMessage.Type(), ciphertextMessage.Serialize(), "")
}

func encryptSession(plaintext []byte, remoteAddress *protocol.SignalAddress) (protocol.CiphertextMessage, error) {
	serializer := serialize.NewProtoBufSerializer()
	signalProtocolStore := NewMixinSignalProtocolStore(serializer)
	buidler := session.NewBuilderFromSignal(signalProtocolStore, remoteAddress, serializer)
	cipher := session.NewCipher(buidler, remoteAddress)
	ciphertextMessage, err := cipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return ciphertextMessage, nil
}

func encodeMessageData(keyType uint32, cipher []byte, resendMessageId string) string {
	header := []byte{byte(protocol.CurrentVersion), byte(keyType), 0, 0, 0, 0, 0, 0}
	ciphertext := append(header, cipher...)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func registerCallbacks() {
	js.Global().Set("generateIdentityKeyPaireFromGo", js.FuncOf(generateIdentityKeyPair))
	js.Global().Set("generateKeyPairFromGo", js.FuncOf(generateKeyPair))
	js.Global().Set("gbenerateSignedPreKeyFromGo", js.FuncOf(generateSignedPreKey))
	js.Global().Set("generatePreKeysFromGo", js.FuncOf(generatePreKeys))
	js.Global().Set("generateRegIdFromGo", js.FuncOf(generateRegId))
	js.Global().Set("createKeyPairFromGo", js.FuncOf(createKeyPair))

	js.Global().Set("containsSessionFromGo", js.FuncOf(containsSession))
	js.Global().Set("processSessionFromGo", js.FuncOf(processSession))
	js.Global().Set("encryptSenderKeyFromGo", js.FuncOf(encryptSenderKey))

	js.Global().Set("test", js.FuncOf(test))
}

func main() {
	c := make(chan struct{}, 0)
	registerCallbacks()
	<-c
}
