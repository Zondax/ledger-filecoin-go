/*******************************************************************************
*   (c) 2019 ZondaX GmbH
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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_FindLedger(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	assert.NotNil(t, app)
	defer app.Close()
}

func Test_UserGetVersion(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	version, err := app.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x0), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x8), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x0), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, err := app.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(pubKey),
		"Public key has wrong length: %x, expected length: %x\n", pubKey, 33)
	fmt.Printf("PUBLIC KEY: %x\n", pubKey)

	assert.Equal(t,
		"02d3ffcbd4ef64589c142d5642ee93264347c74944230587605bd7cc159a2be1c4",
		hex.EncodeToString(pubKey),
		"Unexpected pubkey")
}

func Test_GetAddressPubKeySECP256K1_Zero(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 0, 0, 0}

	pubKey, addr, err := app.GetAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	// TODO : Format address ?
	fmt.Printf("BYTES ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 33)

	assert.Equal(t, "031e10b3a453db1e7324cd37e78820d7d150c13ba3bf784be204c91afe495816a1", hex.EncodeToString(pubKey), "Unexpected pubkey")

	// TODO : fix me get actual address
	assert.Equal(t, "0120e301418e88da44ae76d45980b9e7ee27eb724e", addr, "Unexpected addr")
}

func Test_GetAddressPubKeySECP256K1(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, addr, err := app.GetAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 33)


	// TODO: Fix me (get proper pubkey)
	assert.Equal(t, "02d3ffcbd4ef64589c142d5642ee93264347c74944230587605bd7cc159a2be1c4", hex.EncodeToString(pubKey), "Unexpected pubkey")

	// TODO : fix me get actual address
	assert.Equal(t, "0132bfcde1eb22d6832af220c06b7c4622eaf26246", addr, "Unexpected addr")
}

func Test_ShowAddressPubKeySECP256K1(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, addr, err := app.ShowAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 33)

	// TODO: Fix me (get proper pubkey and address)
	assert.Equal(t, "02d3ffcbd4ef64589c142d5642ee93264347c74944230587605bd7cc159a2be1c4", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "0132bfcde1eb22d6832af220c06b7c4622eaf26246", addr, "Unexpected addr")
}

func Test_UserPK_HDPaths(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 0, 0, 0}

	// TODO: Fix me
	expected := []string{
		"031e10b3a453db1e7324cd37e78820d7d150c13ba3bf784be204c91afe495816a1",
		"03b481eeff158ba0044fa075b2a53cb34de11193699e0fd0ee8abb10fa2acd9bc3",
		"032259104b7273ef2536ed502339ce9af0d86e0da7d7ada5e74fc4c889f6635df2",
		"0231baabf58c017bd9fead1bf35678995dcd6008932e3be70e869e8531a305283a",
		"03a9e6cbf4ce5a36c8b453ef7b20f5d9d06b71b4ac7546e5a273ccb5a49d2696cf",
		"02f4e7c0c1f25c7f2dabc1a86c10d62d67e9bc26be75c630f4853a8e8ae2d1db42",
		"03376ffe9d230cd4f937b7ed33e82d6240ad9e1326dc61d79a12096342b820405c",
		"035e28f7574fec025c27ebd8cea256f15a98b832926735fb945689af77f8b081ce",
		"027070981da387c2a91c9c73bccd11bd23514ee00fcdd7bc4e036a776d8fb59c5d",
		"033364f9288fbc6bfdc10e5ba30c6c63b7f60bffc7152bef63e922da72eee22c4c",
	}

	for i := uint32(0); i < 10; i++ {
		path[4] = i

		pubKey, err := app.GetPublicKeySECP256K1(path)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}

		assert.Equal(
			t,
			33,
			len(pubKey),
			"Public key has wrong length: %x, expected length: %x\n", pubKey, 33)

		assert.Equal(
			t,
			expected[i],
			hex.EncodeToString(pubKey),
			"Public key 44'/461'/0'/0/%d does not match\n", i)
	}
}

func getDummyTx() []byte {
	base64tx := "ODg1NTAxZDE1MDA1MDRlNGQxYWMzZTg5YWM4OTFhNDUwMjU4NmZhYmQ5YjQxNzU1MDFiODgyNjE5" +
		"ZDQ2NTU4ZjNkOWUzMTZkMTFiNDhkY2YyMTEzMjcwMjZhMDE0MTAwNDMwMDA5YzQ0MzAwNjFhODAwNDAK"
	tx, _ := base64.StdEncoding.DecodeString(base64tx)
	return tx
}

func Test_Sign(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 0, 0, 5}

	message := getDummyTx()
	signature, err := app.SignSECP256K1(path, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey[:], btcec.S256())
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := btcec.ParseDERSignature(signature[:], btcec.S256())
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	// REVIEW: we are doing a hash256, not a blake2b hash ?
	hash := sha256.Sum256(message)

	verified := sig2.Verify(hash[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature")
		return
	}
}

func Test_Sign_Fails(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 0, 0, 5}

	message := getDummyTx()
	garbage := []byte{65}
	message = append(garbage, message...)

	_, err = app.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage := err.Error()
	assert.Equal(t, errMessage, "Unexpected data type")

	message = getDummyTx()
	garbage = []byte{65}
	message = append(message, garbage...)

	_, err = app.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage = err.Error()
	assert.Equal(t, errMessage, "Unexpected data at end")

}
