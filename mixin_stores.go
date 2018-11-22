package main

import (
	"encoding/hex"
	"strings"
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
	result := js.Global().Call("getIdentityKeyFromStore", "-1").String()
	keys := strings.Split(result, ",")
	if len(keys) != 2 {
		//TODO
	}

	public, _ := hex.DecodeString(keys[0])
	private, _ := hex.DecodeString(keys[1])

	privateKey := ecc.NewDjbECPrivateKey(bytehelper.SliceToArray(private))
	publicKey := identity.NewKeyFromBytes(bytehelper.SliceToArray(public), 0)
	identityKeyPair := identity.NewKeyPair(&publicKey, privateKey)
	return identityKeyPair
}

func (i *MixinIdentityKeyStore) GetLocalRegistrationId() uint32 {
	return 0
}

func (i *MixinIdentityKeyStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	js.Global().Call("saveIdentityKeyToStore", address.String(), identityKey.Fingerprint())
}

func (i *MixinIdentityKeyStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key) bool {
	trusted := js.Global().Call("getIdentityKeyFromStore", address.String()).String()
	return trusted == "" || trusted == identityKey.Fingerprint()
}

// PreKeyStore
func NewMixinPreKeyStore() *MixinPreKeyStore {
	return &MixinPreKeyStore{}
}

type MixinPreKeyStore struct {
}

func (i *MixinPreKeyStore) LoadPreKey(preKeyID uint32) *record.PreKey {
	// return i.store[preKeyID]
	return nil
}

func (i *MixinPreKeyStore) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	// i.store[preKeyID] = preKeyRecord
}

func (i *MixinPreKeyStore) ContainsPreKey(preKeyID uint32) bool {
	// _, ok := i.store[preKeyID]
	return true
}

func (i *MixinPreKeyStore) RemovePreKey(preKeyID uint32) {
	// delete(i.store, preKeyID)
}

// SessionStore
func NewMixinSessionStore(serializer *serialize.Serializer) *MixinSession {
	return &MixinSession{
		sessions:   make(map[*protocol.SignalAddress]*record.Session),
		serializer: serializer,
	}
}

type MixinSession struct {
	sessions   map[*protocol.SignalAddress]*record.Session
	serializer *serialize.Serializer
}

func (i *MixinSession) LoadSession(address *protocol.SignalAddress) *record.Session {
	if i.ContainsSession(address) {
		return i.sessions[address]
	}
	sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	i.sessions[address] = sessionRecord

	return sessionRecord
}

func (i *MixinSession) GetSubDeviceSessions(name string) []uint32 {
	var deviceIDs []uint32

	for key := range i.sessions {
		if key.Name() == name && key.DeviceID() != 1 {
			deviceIDs = append(deviceIDs, key.DeviceID())
		}
	}

	return deviceIDs
}

func (i *MixinSession) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	i.sessions[remoteAddress] = record
}

func (i *MixinSession) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	_, ok := i.sessions[remoteAddress]
	return ok
}

func (i *MixinSession) DeleteSession(remoteAddress *protocol.SignalAddress) {
	delete(i.sessions, remoteAddress)
}

func (i *MixinSession) DeleteAllSessions() {
	i.sessions = make(map[*protocol.SignalAddress]*record.Session)
}

// SignedPreKeyStore
func NewMixinSignedPreKeyStore() *MixinSignedPreKey {
	return &MixinSignedPreKey{
		store: make(map[uint32]*record.SignedPreKey),
	}
}

type MixinSignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func (i *MixinSignedPreKey) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	return i.store[signedPreKeyID]
}

func (i *MixinSignedPreKey) LoadSignedPreKeys() []*record.SignedPreKey {
	var preKeys []*record.SignedPreKey

	for _, record := range i.store {
		preKeys = append(preKeys, record)
	}

	return preKeys
}

func (i *MixinSignedPreKey) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	i.store[signedPreKeyID] = record
}

func (i *MixinSignedPreKey) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	_, ok := i.store[signedPreKeyID]
	return ok
}

func (i *MixinSignedPreKey) RemoveSignedPreKey(signedPreKeyID uint32) {
	delete(i.store, signedPreKeyID)
}

func NewMixinSenderKeyStore() *MixinSenderKey {
	return &MixinSenderKey{
		store: make(map[*protocol.SenderKeyName]*groupRecord.SenderKey),
	}
}

type MixinSenderKey struct {
	store map[*protocol.SenderKeyName]*groupRecord.SenderKey
}

func (i *MixinSenderKey) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) {
	i.store[senderKeyName] = keyRecord
}

func (i *MixinSenderKey) LoadSenderKey(senderKeyName *protocol.SenderKeyName) *groupRecord.SenderKey {
	return i.store[senderKeyName]
}
