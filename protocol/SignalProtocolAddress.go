package protocol

import (
	"fmt"
)

const ADDRESS_SEPARATOR = ":"

// NewSignalAddress returns a new signal address.
func NewSignalAddress(name string, deviceID uint32, suffix string) *SignalAddress {
	addr := SignalAddress{
		name:     name,
		deviceID: deviceID,
		suffix:   suffix,
	}

	return &addr
}

// SignalAddress is a combination of a name and a device ID.
type SignalAddress struct {
	name     string
	deviceID uint32
	suffix   string
}

// String returns a string of both the address name and device id.
func (s *SignalAddress) String() string {
	return fmt.Sprintf("%s%s%d%s", s.name, ADDRESS_SEPARATOR, s.deviceID, s.suffix)
}
