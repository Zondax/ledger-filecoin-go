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
		"02e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa",
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

	pubKey, addrByte, addrString, err := app.GetAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BYTE ADDR: %x\n", addrByte)
	fmt.Printf("STRING ADDR: %s\n", addrString)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 33)

	assert.Equal(t, "0235e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795", hex.EncodeToString(pubKey), "Unexpected pubkey")

	assert.Equal(t, "010f323f4709e8e4db0c1d4cd374f9f35201d26fb2", hex.EncodeToString(addrByte), "Unexpected addr")
	assert.Equal(t, "f1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka", addrString, "Unexpected addr")
}

func Test_GetAddressPubKeySECP256K1(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, addrByte, addrString, err := app.GetAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BYTE ADDR: %x\n", addrByte)
	fmt.Printf("STRING ADDR: %s\n", addrString)


	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 33)


	assert.Equal(t, "02e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa", hex.EncodeToString(pubKey), "Unexpected pubkey")

	assert.Equal(t, "01302a5c3302178cfd57cdea06e3ecadfe00d4237c", hex.EncodeToString(addrByte), "Unexpected addr")
	assert.Equal(t, "f1gavfymycc6gp2v6n5idoh3fn7yanii34vgsqwpy", addrString, "Unexpected addr")
}

func Test_ShowAddressPubKeySECP256K1(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, addrByte, addrString, err := app.ShowAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BYTE ADDR: %x\n", addrByte)
	fmt.Printf("STRING ADDR: %s\n", addrString)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 33)

	assert.Equal(t, "02e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "01302a5c3302178cfd57cdea06e3ecadfe00d4237c", hex.EncodeToString(addrByte), "Unexpected addr")
	assert.Equal(t, "f1gavfymycc6gp2v6n5idoh3fn7yanii34vgsqwpy", addrString, "Unexpected addr")

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
		"0235e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795",
		"02fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de18",
		"03b9b4026fd1bf1182f6063362e8329efa83d9ed8224efa65d1624a482b0d3bb41",
		"0276476b80a1c4d0637df0ffcc2b21b17a319589d3afefc934e5ce9c8449892522",
		"020103b0e5a8fbba7879db8b050769a4f15ca9b10876e23b86bb32bba42e81032a",
		"0320316dba4ab1c0eb296467d69c32c6395af0cbc304e46f33e6929e9e6870bc3b",
		"028c9af1429d01bb868d7fe34934f9e593ebe48b76f233752d02fb5292f144aa0f",
		"02472a3365e5ff78d4dd17f8dd126bffb6ab76da933aeb037f5e7cd19c35f9ea1f",
		"0361dcb79a58bd04d55c686794d5bf048faff71935abed829e758ba4077d9f91a4",
		"02f94f7ea0c279104457124103dc5ea03e55466ff92faa1f3a1fef2f02aab2b16f",
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

func Test_Sign(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	app.api.Logging = true

	path := []uint32{44, 461, 0, 0, 5}

	message, _ := hex.DecodeString("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040")
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

	message, _ := hex.DecodeString("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040")
	garbage := []byte{65}
	message = append(garbage, message...)

	_, err = app.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage := err.Error()
	assert.Equal(t, errMessage, "Unexpected data type")

	message, _ = hex.DecodeString("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040")
	garbage = []byte{65}
	message = append(message, garbage...)

	_, err = app.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage = err.Error()
	assert.Equal(t, errMessage, "Unexpected CBOR EOF")

}
