package main

import (
	"encoding/base64"
	"encoding/hex"
	"syscall/js"

	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	groupRecord "github.com/RadicalApp/libsignal-protocol-go/groups/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/keys/identity"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
)

// IdentityKeyStore
func NewMixinIdentityKeyStore() *MixinIdentityKeyStore {
	return &MixinIdentityKeyStore{}
}

type MixinIdentityKeyStore struct {
}

func (i *MixinIdentityKeyStore) GetIdentityKeyPair() *identity.KeyPair {
	result := js.Global().Get("signalDao").Call("getIdentityKeyPair")
	public, _ := base64.StdEncoding.DecodeString(result.Get("public_key").String())
	private, _ := base64.StdEncoding.DecodeString(result.Get("private_key").String())

	privateKey := ecc.NewDjbECPrivateKey(bytehelper.SliceToArray(private))
	publicKey := identity.NewKeyFromBytes(bytehelper.SliceToArray(public), 0)
	identityKeyPair := identity.NewKeyPair(&publicKey, privateKey)
	return identityKeyPair
}

func (i *MixinIdentityKeyStore) GetLocalRegistrationId() uint32 {
	result := js.Global().Get("signalDao").Call("getIdentityKeyPair")
	return uint32(result.Get("registration_id").Int())
}

func (i *MixinIdentityKeyStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	pub := base64.StdEncoding.EncodeToString(identityKey.Serialize())
	js.Global().Get("signalDao").Call("saveIdentityKey", address.Name(), pub)
}

func (i *MixinIdentityKeyStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key) bool {
	result := js.Global().Get("signalDao").Call("getIdentityKey", address.Name())
	if result == js.Undefined() {
		return true
	}
	public, _ := base64.StdEncoding.DecodeString(result.Get("public_key").String())
	if hex.EncodeToString(public) == identityKey.Fingerprint() {
		return true
	}
	return false
}

// PreKeyStore
func NewMixinPreKeyStore(serializer *serialize.Serializer) *MixinPreKeyStore {
	return &MixinPreKeyStore{
		serializer: serializer,
	}
}

type MixinPreKeyStore struct {
	serializer *serialize.Serializer
}

func (i *MixinPreKeyStore) LoadPreKey(preKeyID uint32) *record.PreKey {
	result := js.Global().Get("signalDao").Call("getPreKey", preKeyID)
	if result == js.Undefined() {
		return nil
	}
	recordBytes, _ := hex.DecodeString(result.String())
	preKey, err := record.NewPreKeyFromBytes(recordBytes, i.serializer.PreKeyRecord)
	if err != nil {
		return nil
	}
	return preKey
}

func (i *MixinPreKeyStore) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	record := hex.EncodeToString(preKeyRecord.Serialize())
	js.Global().Get("signalDao").Call("savePreKey", preKeyID, record)
}

func (i *MixinPreKeyStore) ContainsPreKey(preKeyID uint32) bool {
	result := js.Global().Get("signalDao").Call("getPreKey", preKeyID)
	if result == js.Undefined() {
		return false
	}
	return true
}

func (i *MixinPreKeyStore) RemovePreKey(preKeyID uint32) {
	js.Global().Get("signalDao").Call("deletePreKey", preKeyID)
}

// SessionStore
func NewMixinSessionStore(serializer *serialize.Serializer) *MixinSession {
	return &MixinSession{
		serializer: serializer,
	}
}

type MixinSession struct {
	serializer *serialize.Serializer
}

func (i *MixinSession) LoadSession(address *protocol.SignalAddress) *record.Session {
	result := js.Global().Get("signalDao").Call("getSession", address.Name(), address.DeviceID())
	if result == js.Undefined() {
		return nil
	}

	// if i.ContainsSession(address) {
	// 	return i.sessions[address]
	// }
	// sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	// i.sessions[address] = sessionRecord

	// return sessionRecord
	return nil
}

func (i *MixinSession) GetSubDeviceSessions(name string) []uint32 {
	var deviceIDs []uint32

	return deviceIDs
}

func (i *MixinSession) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	rec := hex.EncodeToString(record.Serialize())
	js.Global().Get("signalDao").Call("saveSession", remoteAddress.Name(), remoteAddress.DeviceID(), rec)
}

func (i *MixinSession) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	result := js.Global().Get("signalDao").Call("getSession", remoteAddress.Name(), remoteAddress.DeviceID())
	if result == js.Undefined() {
		return false
	}
	return true
}

func (i *MixinSession) DeleteSession(remoteAddress *protocol.SignalAddress) {
	js.Global().Get("signalDao").Call("deleteSession", remoteAddress.Name(), remoteAddress.DeviceID())
}

func (i *MixinSession) DeleteAllSessions() {
	// i.sessions = make(map[*protocol.SignalAddress]*record.Session)
}

// SignedPreKeyStore
func NewMixinSignedPreKeyStore(serializer *serialize.Serializer) *MixinSignedPreKey {
	return &MixinSignedPreKey{
		serializer: serializer,
	}
}

type MixinSignedPreKey struct {
	serializer *serialize.Serializer
}

func (i *MixinSignedPreKey) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	result := js.Global().Get("signalDao").Call("getSignedPreKey", signedPreKeyID)
	if result == js.Undefined() {
		return nil
	}
	recordBytes, _ := hex.DecodeString(result.String())
	signedPreKey, err := record.NewSignedPreKeyFromBytes(recordBytes, i.serializer.SignedPreKeyRecord)
	if err != nil {
		return nil
	}
	return signedPreKey
}

func (i *MixinSignedPreKey) LoadSignedPreKeys() []*record.SignedPreKey {
	result := js.Global().Get("signalDao").Call("getAllSignedPreKeys")
	if result == js.Undefined() {
		return nil
	}

	var preKeys []*record.SignedPreKey

	// for _, record := range i.store {
	// 	preKeys = append(preKeys, record)
	// }

	return preKeys
}

func (i *MixinSignedPreKey) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	recordStr := hex.EncodeToString(record.Serialize())
	js.Global().Get("signalDao").Call("saveSignedPreKey", signedPreKeyID, recordStr)
}

func (i *MixinSignedPreKey) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	result := js.Global().Get("signalDao").Call("getSignedPreKey", signedPreKeyID)
	if result == js.Undefined() {
		return false
	}
	return true
}

func (i *MixinSignedPreKey) RemoveSignedPreKey(signedPreKeyID uint32) {
	js.Global().Get("signalDao").Call("deleteSignedPreKey", signedPreKeyID)
}

func NewMixinSenderKeyStore(serializer *serialize.Serializer) *MixinSenderKey {
	return &MixinSenderKey{
		serializer:      serializer.SenderKeyRecord,
		stateSerializer: serializer.SenderKeyState,
	}
}

type MixinSenderKey struct {
	serializer      groupRecord.SenderKeySerializer
	stateSerializer groupRecord.SenderKeyStateSerializer
}

func (i *MixinSenderKey) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) {
	recordStr := hex.EncodeToString(keyRecord.Serialize())
	js.Global().Get("signalDao").Call("saveSenderKey", senderKeyName.GroupID(), senderKeyName.Sender().String(), recordStr)
}

func (i *MixinSenderKey) LoadSenderKey(senderKeyName *protocol.SenderKeyName) *groupRecord.SenderKey {
	result := js.Global().Get("signalDao").Call("getSenderKey", senderKeyName.GroupID(), senderKeyName.Sender())
	if result == js.Undefined() {
		return nil
	}
	recordBytes, _ := hex.DecodeString(result.String())
	senderKey, err := groupRecord.NewSenderKeyFromBytes(recordBytes, i.serializer, i.stateSerializer)
	if err != nil {
		return nil
	}
	return senderKey
}
