/*******************************************************************************
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

package ledger_filecoin_go

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	userMessageChunkSize = 250
	publicKeyLength      = 65
	
	// Signature-related constants
	signatureLength         = 65
	signatureROffset        = 0
	signatureRLength        = 32
	signatureSOffset        = 32
	signatureSLength        = 32
	signatureVOffset        = 64
	signatureMinLength      = 66 // R(32) + S(32) + V(1) + DER(1+)
	signatureDEROffset      = 65
	
	// Version check constants
	minVersionMajor = 0
	minVersionMinor = 0
	minVersionPatch = 3
	minVersionMode  = 0
	
	// Response length constants
	minVersionResponseLength = 4
	minAddressResponseLength = 39
	
	// Message construction constants
	messageLengthPrefixSize = 4
	lengthByteSize          = 1
	
	// BIP44 path constants
	bip44PathElements = 5
	bip44BytesLength  = 20
	bip44BytesPerElement = 4
	hardenBit         = 0x80000000
	
	// APDU message constants
	apduP1Default      = 0
	apduP2Default      = 0
	apduDataLenOffset  = 4
	apduP1Confirm      = 1
)

func (c VersionInfo) String() string {
	return fmt.Sprintf("%d.%d.%d", c.Major, c.Minor, c.Patch)
}

func (e VersionRequiredError) Error() string {
	return fmt.Sprintf("App Version required %s - Version found: %s", e.Required, e.Found)
}

func NewVersionRequiredError(req VersionInfo, ver VersionInfo) error {
	return &VersionRequiredError{
		Found:    ver,
		Required: req,
	}
}

// CheckVersion compares the current version with the required version
func CheckVersion(ver VersionInfo, req VersionInfo) error {
	if ver.Major != req.Major {
		if ver.Major > req.Major {
			return nil
		}
		return NewVersionRequiredError(req, ver)
	}

	if ver.Minor != req.Minor {
		if ver.Minor > req.Minor {
			return nil
		}
		return NewVersionRequiredError(req, ver)
	}

	if ver.Patch >= req.Patch {
		return nil
	}
	return NewVersionRequiredError(req, ver)
}

func GetBip44bytes(bip44Path []uint32, hardenCount int) ([]byte, error) {
	message := make([]byte, bip44BytesLength)
	if len(bip44Path) != bip44PathElements {
		return nil, fmt.Errorf("path should contain %d elements", bip44PathElements)
	}
	for index, element := range bip44Path {
		pos := index * bip44BytesPerElement
		value := element
		if index < hardenCount {
			value = hardenBit | element
		}
		binary.LittleEndian.PutUint32(message[pos:], value)
	}
	return message, nil
}

func prepareChunks(bip44PathBytes []byte, transaction []byte) ([][]byte, error) {
	var packetIndex = 0
	// first chunk + number of chunk needed for transaction
	var packetCount = 1 + int(math.Ceil(float64(len(transaction))/float64(userMessageChunkSize)))

	chunks := make([][]byte, packetCount)

	// First chunk is path
	chunks[0] = bip44PathBytes
	packetIndex++

	for packetIndex < packetCount {
		var start = (packetIndex - 1) * userMessageChunkSize
		var end = packetIndex * userMessageChunkSize

		if end >= len(transaction) {
			chunks[packetIndex] = transaction[start:]
		} else {
			chunks[packetIndex] = transaction[start:end]
		}
		packetIndex++
	}

	return chunks, nil
}
