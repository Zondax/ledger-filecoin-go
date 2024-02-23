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
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ipsn/go-secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
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

	version, err := app.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x0), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x12), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x03), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, err := app.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, len(pubKey), publicKeyLength,
		"Public key has wrong length: %x, expected length: %x\n", pubKey, publicKeyLength)
	fmt.Printf("PUBLIC KEY: %x\n", pubKey)

	assert.Equal(t,
		"04e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa64ec9551c73adf8ca216b36c1720d9d700da991c899c129c3715406f060f1bd4",
		hex.EncodeToString(pubKey),
		"Unexpected pubkey")
}

func Test_GetAddressPubKeySECP256K1_Zero(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 0, 0, 0}

	pubKey, addrByte, addrString, err := app.GetAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BYTE ADDR: %x\n", addrByte)
	fmt.Printf("STRING ADDR: %s\n", addrString)

	assert.Equal(t, len(pubKey), publicKeyLength, "Public key has wrong length: %x, expected length: %x\n", pubKey, publicKeyLength)

	assert.Equal(t, "0435e752dc6b4113f78edcf2cf7b8082e442021de5f00818f555397a6f181af795ace98f0f7d065793eaffa1b06bf52e572c97030c53a2396dfab40ba0e976b108", hex.EncodeToString(pubKey), "Unexpected pubkey")

	assert.Equal(t, "011eaf1c8a4bbfeeb0870b1745b1f57503470b7116", hex.EncodeToString(addrByte), "Unexpected addr")
	assert.Equal(t, "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba", addrString, "Unexpected addr")
}

func Test_GetAddressPubKeySECP256K1(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, addrByte, addrString, err := app.GetAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BYTE ADDR: %x\n", addrByte)
	fmt.Printf("STRING ADDR: %s\n", addrString)

	assert.Equal(t, len(pubKey), publicKeyLength, "Public key has wrong length: %x, expected length: %x\n", pubKey, publicKeyLength)

	assert.Equal(t, "04e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa64ec9551c73adf8ca216b36c1720d9d700da991c899c129c3715406f060f1bd4", hex.EncodeToString(pubKey), "Unexpected pubkey")

	assert.Equal(t, "0144603d82382885567f729c11f26de75be60522b1", hex.EncodeToString(addrByte), "Unexpected addr")
	assert.Equal(t, "f1irqd3aryfccvm73stqi7e3phlptakivru5mirnq", addrString, "Unexpected addr")
}

func Test_ShowAddressPubKeySECP256K1(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, addrByte, addrString, err := app.ShowAddressPubKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BYTE ADDR: %x\n", addrByte)
	fmt.Printf("STRING ADDR: %s\n", addrString)

	assert.Equal(t, len(pubKey), publicKeyLength, "Public key has wrong length: %x, expected length: %x\n", pubKey, publicKeyLength)

	assert.Equal(t, "04e6a262c96c7d7fd015273ec469492c2626eb2e29d73e7f65c64d695670343aaa64ec9551c73adf8ca216b36c1720d9d700da991c899c129c3715406f060f1bd4", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "0144603d82382885567f729c11f26de75be60522b1", hex.EncodeToString(addrByte), "Unexpected addr")
	assert.Equal(t, "f1irqd3aryfccvm73stqi7e3phlptakivru5mirnq", addrString, "Unexpected addr")

}

func Test_UserPK_HDPaths(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 1, 0, 0, 0}

	// TODO: Fix me
	expected := []string{
		"0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a",
		"04ed4fd587fbedc2f29070d20672772b57d0fcc6dac219bbf69b770ecfc72d97c1679009e44edb98939a50bffc68cc70e923484dff8a406417dd2642b743ac85d5",
		"046f5084038d51d7f24faea04d078151394c1c16e0dded13c822ccd50d581f4df6fe1443c19094b812144ebfd6f79b1fa2942d70913f82e8e1d7dbd320dfc0423a",
		"04e0d52a1ae07284cfe2ad37b5d1c3ffd9df28ca3526f2694fd0a8559776125ae0d3ca0ebaec1a96d2b85a77b98bab82a7441e7b618c5c26bf46bbaa1e4ff5911e",
		"04325e554383b7c7438ebd1eadcceaa528cdbb958ac6ba8a013e764ccaf87f8686760458092cfbc1ed5955ac4ae9710a79aa454ccd1c254b4a5da14278cbb92cdc",
		"043fc5ccea9872313b75fec78704b27420de29dd3db298a562559f90f332059465ca0d26f9e4d06985bdad927d37fcd98c789e1cfb7517ad4b364dd16ea1c8e4c7",
		"048dd992702c0f69538d5fd233a907c92fac1233b4c02f833384a3de20a8b66a158206a3c61d0b3bd93746403f8ccd06875a1878ea26ac3aa4f1716509ee25d235",
		"0404493e498a87fc97a23307a9231bfe5f6b978e3c856b575dc2644c267ec5af5a1ce9bf57a9dcffd1dc49750564e391ad584bff96e7a522f3031ba5079abb8c94",
		"046886bd689c36ad3c236eb178dcddb428a39656502fa358a8a4d549a569a4f11914a33144023bfc0abb6fad7a861b1c7e297262331f0c0f636a4e51805ebcef4b",
		"0497f59bb7a9a272ee9b1105233b3191a87994419d19d0212619b289c53952e209526dd84fd4361c9c994e6a1b5c343afa267cf40d56e1893c92d44549b1a71aec",
	}

	for i := uint32(0); i < 10; i++ {
		path[4] = i

		pubKey, err := app.GetPublicKeySECP256K1(path)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}

		assert.Equal(
			t,
			len(pubKey), publicKeyLength,
			"Public key has wrong length: %x, expected length: %x\n", pubKey, publicKeyLength)

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

	path := []uint32{44, 461, 0, 0, 0}

	message, _ := hex.DecodeString("8a0058310396a1a3e4ea7a14d49985e661b22401d44fed402d1d0925b243c923589c0fbc7e32cd04e29ed78d15d37d3aaa3fe6da3358310386b454258c589475f7d16f5aac018a79f6c1169d20fc33921dd8b5ce1cac6c348f90a3603624f6aeb91b64518c2e80950144000186a01961a8430009c44200000040")

	signature, err := app.SignSECP256K1(path, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey, btcec.S256())
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := btcec.ParseDERSignature(signature.derSignature, btcec.S256())
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	// double blake2b hashing
	hash := blake2b.Sum256(message)
	hash_cid_sum := blake2b.Sum256(append([]byte{0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20}, hash[:]...))

	verified := sig2.Verify(hash_cid_sum[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature")
		return
	}

	assert.Equal(t, len(pubKey), publicKeyLength, "Unexpected pubkey size")
}

func Test_Sign2(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 1, 0, 0, 0}

	message, _ := hex.DecodeString("8a0055019f4c34943e4b92f4542bed08af54be955629fc6f5501ef8fd1e48a1e0f1a49310ec675bc677a3954147400430003e81903e84200014200010040")

	signature, err := app.SignSECP256K1(path, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey, btcec.S256())
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := btcec.ParseDERSignature(signature.derSignature, btcec.S256())
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	// double blake2b hashing
	hash := blake2b.Sum256(message)
	hash_cid_sum := blake2b.Sum256(append([]byte{0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20}, hash[:]...))

	verified := sig2.Verify(hash_cid_sum[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature")
		return
	}

	assert.Equal(t, "0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, len(pubKey), publicKeyLength, "Unexpected pubkey size")

}

func Test_Sign3(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 1, 0, 0, 0}

	message, _ := hex.DecodeString("8a0055019f4c34943e4b92f4542bed08af54be955629fc6f5501ef8fd1e48a1e0f1a49310ec675bc677a3954147400430003e81903e84200014200010040")

	signature, err := app.SignSECP256K1(path, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey, btcec.S256())
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := btcec.ParseDERSignature(signature.derSignature, btcec.S256())
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	// double blake2b hashing
	hash := blake2b.Sum256(message)
	hash_cid_sum := blake2b.Sum256(append([]byte{0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20}, hash[:]...))

	verified := sig2.Verify(hash_cid_sum[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature")
		return
	}

	assert.Equal(t, "0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, len(pubKey), publicKeyLength, "Unexpected pubkey size")

}

func Test_Sign_RecoveryID(t *testing.T) {
	message, _ := hex.DecodeString("5a51287d2e5401b75014da0f050c8db96fe0bacdad75fce964520ca063b697e1")
	signature, _ := hex.DecodeString("20316dba4ab1c0eb296467d69c32c6395af0cbc304e46f33e6929e9e6870bc3b5390c901570334b7303ec18c499e3ee3670ea2a35c2090d59bf5bad71d1f1cd700")
	assert.NotNil(t, message)
	assert.NotNil(t, signature)
	signature[64] = signature[64] & 0x3
	pubkey, err := secp256k1.RecoverPubkey(message, signature)

	assert.Equal(t, "0420316dba4ab1c0eb296467d69c32c6395af0cbc304e46f33e6929e9e6870bc3b63377b3322c9955cc0ed81715f4abeb04cd2274daf5ea9201a4f88f4e83b9eb7", hex.EncodeToString(pubkey), "Unexpected pubkey")

	assert.NoError(t, err)
	assert.NotNil(t, pubkey)
}

func Test_Sign_Fails(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	message_cbor_hex := "8a0055019f4c34943e4b92f4542bed08af54be955629fc6f5501ef8fd1e48a1e0f1a49310ec675bc677a3954147400430003e81903e84200014200010040"

	path := []uint32{44, 461, 0, 0, 0}

	message, _ := hex.DecodeString(message_cbor_hex)
	garbage := []byte{65}
	message = append(garbage, message...)

	_, err = app.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage := err.Error()
	assert.Equal(t, errMessage, "Unexpected data type")

	message, _ = hex.DecodeString(message_cbor_hex)
	garbage = []byte{65}
	message = append(message, garbage...)

	_, err = app.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage = err.Error()
	assert.Equal(t, errMessage, "Unexpected CBOR EOF")

}
