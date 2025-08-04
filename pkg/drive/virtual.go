// Copyright (c) 2021 by library authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package drive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/open-source-firmware/go-tcg-storage/pkg/core/feature"
	"strconv"
	"strings"
)

const (
	virtVersion = "1.2.3"
	virtVendor  = "9elements"
	virtComID   = 0x7FFE
)

var (
	ErrNotImplemented = fmt.Errorf("not implemented")
)

type virtDrive struct {
	sn string // serial number
}

// NOTE: This structure should probably go somewhere else to allow to be used for parsing

type TCGStorageLevel0Hdr struct {
	Length uint32
	Major  uint16
	Minor  uint16
	_      [8]byte
	Vendor [32]byte
}

type TCGStorageFeatureDesc struct {
	Code    uint16
	Version uint8 // Version is encoded in the upper 4 bit. The lower 4 bits are reserved.
	Length  uint8
}

type TCGStorageTPerFeature struct {
	TCGStorageFeatureDesc
	Features uint8 // Features Bitmask indicating TPer features
	_        [11]byte
}

type TCGStorageLockingFeature struct {
	TCGStorageFeatureDesc
	Features uint8 //Features Bitmask indicating Locking features
	_        [11]byte
}

type TCGStoragePyriteSSCFeature struct {
	TCGStorageFeatureDesc
	BaseComID       uint16
	NumComIDs       uint16
	_               [5]byte
	SidPinIndicator uint8
	SidPinBehavior  uint8
	_               [5]byte
}

type TCGStorageDataRemovalFeature struct {
	TCGStorageFeatureDesc
	_                     uint8
	DataRemovalProcessing uint8 // DataRemovalProcessing is the least significant bit. Rest of bits is reserved.
	SupportedDataRemoval  uint8
	DataRemovalTimeFmt    uint8 // DataRemovalTimeFmt bitmask indicating data removal time format. Bit 0-5 are defined.
	DataRemovalTimeBit    [6]uint16
	_                     [16]byte
}

// VERIFY_COMID_VALID - TCG Storage Architecture Core Specification V2.01 chapter 3.3.4.7.4
type TCGStorageVerifyComIDValid struct {
	ExtendedComID uint32
	RequestCode   [4]byte
	_             [2]byte
	Lenght        uint16
	State         [4]byte
	AbsAllocTime  [10]byte
	AbsExpireTime [10]byte
	LastResetTime [10]byte
}

func (d *virtDrive) IFRecv(proto SecurityProtocol, sps uint16, data *[]byte) error {
	switch proto {
	case SecurityProtocolInformation:
		switch sps {
		// Protocol Information
		case uint16(0x0000):
			// TODO: Introduce proper type
			secProt := []uint8{
				0, 0, 0, 0, 0, 0, // Reserved or unknown fields
				0, 3, // Size of payload (3 protocols)
				uint8(SecurityProtocolInformation),
				uint8(SecurityProtocolTCGManagement),
				uint8(SecurityProtocolTCGTPer)}

			*data = secProt

			return nil
		// X.509 Certificate
		case uint16(0x0001):
			return nil
		default:
			return fmt.Errorf("IFRecv: SecurityProtocolInformation: invalid command ID")
		}
	case SecurityProtocolTCGManagement:
		switch sps {
		// ComIDDiscoveryL0
		case uint16(0x0001):
			err := virtDriveDiscovery(data)
			return err
		default:
			return fmt.Errorf("IFRecv: SecurityProtocolTCGManagement: invalid command ID")
		}
	case SecurityProtocolTCGTPer:
		switch sps {
		// GET_COMID - TCG Storage Architecture Core Specification V2.01 chapter 3.3.4.3.1
		case uint16(0x0000):
			binary.BigEndian.PutUint32(*data, uint32(virtComID<<16))
			return nil
		case uint16(virtComID):
			// TODO: no state machine yet, we handle the return for the comIDRequest
			comIdValid := TCGStorageVerifyComIDValid{
				ExtendedComID: uint32(virtComID << 16),
				RequestCode:   [4]byte{0x00, 0x00, 0x00, 0x01}, // Request ComID
				Lenght:        0x22,
				State:         [4]byte{0x00, 0x00, 0x00, 0x02}, // State: Issued
				AbsAllocTime:  [10]byte{},
				AbsExpireTime: [10]byte{},
				LastResetTime: [10]byte{},
			}

			d0buf := bytes.NewBuffer(nil)
			if err := binary.Write(d0buf, binary.BigEndian, &comIdValid); err != nil {
				return err
			}
			*data = d0buf.Bytes()

			return nil
		default:
			return fmt.Errorf("IFRecv: SecurityProtocolTCGTPer: invalid command ID")
		}
		return fmt.Errorf("IFRecv: SecurityProtocolTCGTPer: %v", ErrNotImplemented)
	default:
		return fmt.Errorf("IFRecv: Unsupported security protocol: %v", proto)
	}
}

func (d *virtDrive) IFSend(proto SecurityProtocol, sps uint16, data []byte) error {
	switch proto {
	case SecurityProtocolInformation:
		return fmt.Errorf("IFSend: SecurityProtocolInformation: %v", ErrNotImplemented)
	case SecurityProtocolTCGManagement:
		return fmt.Errorf("IFSend: SecurityProtocolTCGManagement: %v", ErrNotImplemented)
	case SecurityProtocolTCGTPer:
		switch sps {
		case uint16(virtComID):
			comId := binary.BigEndian.Uint16(data[0:2])
			if comId != uint16(virtComID) {
				return fmt.Errorf("unsupported ComID")
			}

			requestCode := data[4:8]

			//ComIDRequestVerifyComIDValid
			comIDRequest := [4]byte{0x00, 0x00, 0x00, 0x01}
			if bytes.Equal(comIDRequest[:], requestCode) {
				// TODO: no statemachine yet, we would expect a following IF_RECV and
				//       return the data to the comIDRequest
				return nil
			} else {
				return fmt.Errorf("invalid request code")
			}

			return nil
		default:
			return fmt.Errorf("IFSend: SecurityProtocolTCGTPer: invalid command ID")
		}
	default:
		return fmt.Errorf(":IFSend: Unsupported security protocol: %v", proto)
	}
}

func (d *virtDrive) Identify() (*Identity, error) {
	return &Identity{
		Protocol:     "Virtual",
		SerialNumber: d.sn,
		Model:        "Virtual Drive",
		Firmware:     virtVersion,
	}, nil
}

func (d *virtDrive) SerialNumber() ([]byte, error) {
	return []byte(d.sn), nil
}

func (d *virtDrive) Close() error {
	// Nothing to do
	return nil
}

// virtDriveDiscovery return data emulating a Level0Discrovery for Pyrite SSC V2 device
func virtDriveDiscovery(data *[]byte) error {
	d0resp := struct {
		Discovery0Hdr      TCGStorageLevel0Hdr
		TPerFeature        TCGStorageTPerFeature
		LockingFeature     TCGStorageLockingFeature
		PyriteSSCFeature   TCGStoragePyriteSSCFeature
		DataRemovalFeature TCGStorageDataRemovalFeature
	}{}

	d0resp.Discovery0Hdr.Length = uint32(binary.Size(d0resp) - binary.Size(d0resp.Discovery0Hdr))

	parts := strings.Split(virtVersion, ".")
	if len(parts) >= 2 {
		major, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			major = 0
		}
		minor, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			minor = 0
		}

		d0resp.Discovery0Hdr.Major = uint16(major)
		d0resp.Discovery0Hdr.Minor = uint16(minor)
	}

	copy(d0resp.Discovery0Hdr.Vendor[:], virtVendor)

	d0resp.TPerFeature.Code = uint16(feature.CodeTPer)
	d0resp.TPerFeature.Version = (0x01 << 4) & 0xF0
	d0resp.TPerFeature.Length = uint8(binary.Size(d0resp.TPerFeature) - 4)
	// TPer Features: SyncSupported
	d0resp.TPerFeature.Features = 0x01

	d0resp.LockingFeature.Code = uint16(feature.CodeLocking)
	d0resp.LockingFeature.Version = (0x02 << 4) & 0xF0
	d0resp.LockingFeature.Length = uint8(binary.Size(d0resp.LockingFeature) - 4)
	// Locking Feature: LockingSupported, "MBR Shadowing Not Supported"
	d0resp.LockingFeature.Features = 0x01 | 0x40

	d0resp.PyriteSSCFeature.Code = uint16(feature.CodePyriteV2)
	d0resp.PyriteSSCFeature.Version = (0x01 << 4) & 0xF0
	d0resp.PyriteSSCFeature.Length = uint8(binary.Size(d0resp.PyriteSSCFeature) - 4)
	d0resp.PyriteSSCFeature.BaseComID = virtComID
	d0resp.PyriteSSCFeature.NumComIDs = 1
	d0resp.PyriteSSCFeature.SidPinIndicator = 0x00
	d0resp.PyriteSSCFeature.SidPinBehavior = 0x00

	// Data removal has to be set but is not supported by our code. Fake it as much as is needed.
	d0resp.DataRemovalFeature.Code = uint16(feature.CodeDataRemoval)
	d0resp.DataRemovalFeature.Version = (0x01 << 4) & 0xF0
	d0resp.DataRemovalFeature.Length = uint8(binary.Size(d0resp.DataRemovalFeature) - 4)
	// other values will be automatically 0

	d0buf := bytes.NewBuffer(nil)
	if err := binary.Write(d0buf, binary.BigEndian, &d0resp); err != nil {
		return err
	}

	*data = d0buf.Bytes()
	return nil
}

func virtualDrive() *virtDrive {
	return &virtDrive{
		sn: "12345678",
	}
}
