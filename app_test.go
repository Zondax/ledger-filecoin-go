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
	"github.com/btcsuite/btcd/btcec/v2"
	ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
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
	if version.Major == 0 && version.Minor == 0 && version.Patch == 0 {
		t.Fatalf("All version numbers are zero: Major, Minor, Patch")
	}
}

func Test_UserGetPublicKey(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 5, 0, 21}

	pubKey, err := app.GetPublicKey(path, SECP256K1)
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

	pubKey, addrByte, addrString, err := app.GetAddressPubKey(path, SECP256K1)
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

	pubKey, addrByte, addrString, err := app.GetAddressPubKey(path, SECP256K1)
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

	pubKey, addrByte, addrString, err := app.ShowAddressPubKey(path, SECP256K1)
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

		pubKey, err := app.GetPublicKey(path, SECP256K1)
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

	signature, err := app.Sign(path, message, SECP256K1)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKey(path, SECP256K1)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := ecdsa.ParseDERSignature(signature.derSignature)
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

	signature, err := app.Sign(path, message, SECP256K1)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKey(path, SECP256K1)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := ecdsa.ParseDERSignature(signature.derSignature)
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

	signature, err := app.Sign(path, message, SECP256K1)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := app.GetPublicKey(path, SECP256K1)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	pub2, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := ecdsa.ParseDERSignature(signature.derSignature)
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

	_, err = app.Sign(path, message, SECP256K1)
	assert.Error(t, err)
	errMessage := err.Error()
	assert.Equal(t, errMessage, "Unexpected data type")

	message, _ = hex.DecodeString(message_cbor_hex)
	garbage = []byte{65}
	message = append(message, garbage...)

	_, err = app.Sign(path, message, SECP256K1)
	assert.Error(t, err)
	errMessage = err.Error()
	assert.Equal(t, errMessage, "Unexpected CBOR EOF")

}

func Test_SignPersonalMessageFVM(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 0, 0, 0}

	// Test personal message
	personalMessage := []byte("Hello World!")

	signature, err := app.SignPersonalMessageFVM(path, personalMessage)
	if err != nil {
		t.Fatalf("[SignPersonalMessageFVM] Error: %s\n", err.Error())
	}

	// Verify that we got a signature
	assert.NotNil(t, signature)
	assert.NotNil(t, signature.r)
	assert.NotNil(t, signature.s)
	assert.NotNil(t, signature.derSignature)

	// Check signature lengths
	assert.Equal(t, 32, len(signature.r), "R component should be 32 bytes")
	assert.Equal(t, 32, len(signature.s), "S component should be 32 bytes")
	assert.True(t, len(signature.derSignature) > 0, "DER signature should not be empty")

	// Verify signature format (v should be 0, 1, 2, or 3)
	assert.True(t, signature.v <= 3, "V value should be <= 3")

	// Get public key for verification
	pubKey, err := app.GetPublicKey(path, SECP256K1)
	if err != nil {
		t.Fatalf("Failed to get public key: %s\n", err.Error())
	}

	// Parse public key
	pub2, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	// Parse DER signature
	sig2, err := ecdsa.ParseDERSignature(signature.derSignature)
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	// For FVM personal messages, we need to construct the EIP-191 message format
	// EIP191_FVM_PREFIX = "\x19Filecoin Signed Message:\n"
	eip191FVMPrefix := []byte("\x19Filecoin Signed Message:\n")

	// Create message length as UTF-8 string (not 4-byte big endian)
	messageLengthString := fmt.Sprintf("%d", len(personalMessage))
	messageLengthBuffer := []byte(messageLengthString)

	// Construct EIP-191 message: prefix + length (as string) + message
	eip191Message := make([]byte, 0, len(eip191FVMPrefix)+len(messageLengthBuffer)+len(personalMessage))
	eip191Message = append(eip191Message, eip191FVMPrefix...)
	eip191Message = append(eip191Message, messageLengthBuffer...)
	eip191Message = append(eip191Message, personalMessage...)

	// Hash the EIP-191 message with Blake2b
	messageHash := blake2b.Sum256(eip191Message)

	// Verify signature
	verified := sig2.Verify(messageHash[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature")
		return
	}

	fmt.Printf("PersonalMessage Signature R: %x\n", signature.r)
	fmt.Printf("PersonalMessage Signature S: %x\n", signature.s)
	fmt.Printf("PersonalMessage Signature V: %d\n", signature.v)
	fmt.Printf("PersonalMessage DER Signature: %x\n", signature.derSignature)
	fmt.Printf("Signature verification: PASSED\n")
}

func Test_SignPersonalMessageFVM_LongMessage(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	path := []uint32{44, 461, 0, 0, 0}

	// Test with a longer message that will require chunking
	longMessage := make([]byte, 300)
	for i := range longMessage {
		longMessage[i] = byte(i % 256)
	}

	signature, err := app.SignPersonalMessageFVM(path, longMessage)
	if err != nil {
		t.Fatalf("[SignPersonalMessageFVM] Error with long message: %s\n", err.Error())
	}

	// Verify that we got a signature
	assert.NotNil(t, signature)
	assert.NotNil(t, signature.r)
	assert.NotNil(t, signature.s)
	assert.NotNil(t, signature.derSignature)

	// Check signature lengths
	assert.Equal(t, 32, len(signature.r), "R component should be 32 bytes")
	assert.Equal(t, 32, len(signature.s), "S component should be 32 bytes")
	assert.True(t, len(signature.derSignature) > 0, "DER signature should not be empty")

	// Get public key for verification
	pubKey, err := app.GetPublicKey(path, SECP256K1)
	if err != nil {
		t.Fatalf("Failed to get public key: %s\n", err.Error())
	}

	// Parse public key
	pub2, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	// Parse DER signature
	sig2, err := ecdsa.ParseDERSignature(signature.derSignature)
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	// For FVM personal messages, we need to construct the EIP-191 message format
	// EIP191_FVM_PREFIX = "\x19Filecoin Signed Message:\n"
	eip191FVMPrefix := []byte("\x19Filecoin Signed Message:\n")

	// Create message length as UTF-8 string (not 4-byte big endian)
	messageLengthString := fmt.Sprintf("%d", len(longMessage))
	messageLengthBuffer := []byte(messageLengthString)

	// Construct EIP-191 message: prefix + length (as string) + message
	eip191Message := make([]byte, 0, len(eip191FVMPrefix)+len(messageLengthBuffer)+len(longMessage))
	eip191Message = append(eip191Message, eip191FVMPrefix...)
	eip191Message = append(eip191Message, messageLengthBuffer...)
	eip191Message = append(eip191Message, longMessage...)

	// Hash the EIP-191 message with Blake2b
	messageHash := blake2b.Sum256(eip191Message)

	// Verify signature
	verified := sig2.Verify(messageHash[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying long message signature")
		return
	}

	fmt.Printf("PersonalMessage Signature R: %x\n", signature.r)
	fmt.Printf("PersonalMessage Signature S: %x\n", signature.s)
	fmt.Printf("PersonalMessage Signature V: %d\n", signature.v)
	fmt.Printf("PersonalMessage DER Signature: %x\n", signature.derSignature)
	fmt.Printf("Signature verification: PASSED\n")
}

func Test_SignRawBytes(t *testing.T) {
	app, err := FindLedgerFilecoinApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer app.Close()

	// Derivation path used across the existing tests.
	path := []uint32{44, 461, 0, 0, 0}

	// 1 KB payload taken from the reference JavaScript test.
	rawBytesHex := "ab11c412ff5f6fafc466e856f67eb20ad85ef754ad1b7c5d4120ffe95dcd94bd1079f1a89a575d284422825f1aaeb099439bc60e6537e3c939a3a5f0e108d372be73d388da351c11bfc5a20a316051fcd52b4a6d003cd1eef171ba197cfbf8d245f705d65ee0c82fa74e4d3ee1f918a496a0244fb342b7ea0a836e522ba3519001866edde3207af56ad45177433ceb0290e0b55e0584b4c799a7646805d50e885e95e89209d5b223d82001be1c85c881ec6c5bd21bcfceb286c12fdc1f28feaaaa13853655c24f6ef5c640c222ba8ed161718d535786867481fb96bc1720be4b63438d72ba559cb0c72485d1fb6543bc6c684d358aa7cfc1877031600c6efb0f90e5224951205e276cbbd3876953e92a522e26d22a75b0417b2971866a839c03825df7e06de380e00ba7599c59a01165a0ac95d636cc63d09f095df058a273aa4067e9dbeeb7d28ba62519c34c485c9389a485d90f6c47698260fc43b5d2fb88794c34f129fd2861a310c74238f12cd7c84b4f8df19faf05a0756e8b5261b48ee45929f9cfc33c8cedb69029af312a544b216ea8fc33a10cd7188d58591c8a22b2ee3ab6816fe45e080c4f1733ea2a71627cbc90133cecd8eae635e0d522731ee1992a09f411a424bc48ae54cfebcdb442d34ef8e42b1cd9212fdda322baed3569437e1106b67a25d064b0d96a1150a4ea866e4849eb646574a5e3c0d4d6efca09eef7feaf540a6eda9c886d92018b2afbf64d9c077c83f23f45529f826a51b575432c6fa0c7849799c3e9ba5a0f4d71b93a12b72a9d06238c686561cd952a2a50e2c516f3fc1b60e94365dbc883a8a47a0214a6df74390c9963836e6d1099bc16da0a6caf07f0962b945ef225930bd6131fe344ff7fcac9f0181a0a24940146b03b79a3de67b92fe592183258e939685d47089e6f9228b169952aabb45f3ad369b1d557099ce97b6092f2e0bd6122c2479fed1a2427c8fd763a93587795f38a391782b0dadf857a3a8d896940c94cef4183d3ff52f26af4957736955db70d668f524285d091313ffc9b807e0502edc6fbc3f1d6e76350a0c3d78fc6cdc6ae36bd2b9dccb3b4e7734c8d91a2c883390953429fd9dd185a81bfa3ac147d86342ac3b227eff6ac0c2904596076b845a3267b1b472e8bbb429575fb280ec82718734ceb2b07e8c998b42cad224c98cc56aa5ca3a9159e8bf3604f4f56b2350befc00cca8e1a1aecb3dbb64c9536ec557204dfd3ee68ee16b641c41e75c4f97266ed4c5f78b5f8fd7ff11eb8c5db201f85b3904f13931bbead263a00e85d1086340bb4a2fb6fd139b793d4a7540b3dbf2495f7d08f8821759bde65817aa08fa1424101639fbfb6c4f91961da1372bccb127afc627d352f9d9d2faa5a9176be55274b53dc04b94174b6b7aa52955939cf14970d31e03ea60cb2cdc99e422f232a4052"
	rawBytes, _ := hex.DecodeString(rawBytesHex)

	// The Ledger stacks expect the "Filecoin Sign Bytes:\n" prefix (EIP-191 style)
	prefix := []byte("Filecoin Sign Bytes:\n")
	txBlob := append(prefix, rawBytes...)

	// Sign the blob
	signature, err := app.SignRawBytes(path, txBlob)
	if err != nil {
		t.Fatalf("[SignRawBytes] Error: %s\n", err.Error())
	}

	// Basic sanity checks on the returned signature
	assert.NotNil(t, signature)
	assert.Equal(t, 32, len(signature.r), "R component should be 32 bytes")
	assert.Equal(t, 32, len(signature.s), "S component should be 32 bytes")
	assert.True(t, len(signature.derSignature) > 0, "DER-encoded signature should not be empty")

	// Retrieve the associated public key to perform verification
	pubKey, err := app.GetPublicKey(path, SECP256K1)
	if err != nil {
		t.Fatalf("[GetPublicKey] Error: %s\n", err.Error())
	}

	parsedPK, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("[ParsePubKey] Error: %s\n", err.Error())
	}

	parsedSig, err := ecdsa.ParseDERSignature(signature.derSignature)
	if err != nil {
		t.Fatalf("[ParseDERSignature] Error: %s\n", err.Error())
	}

	// Digest = Blake2b-256( CID_PREFIX || Blake2b-256(txBlob) )
	cidPrefix := []byte{0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20}
	innerHash := blake2b.Sum256(txBlob)
	cid := append(cidPrefix, innerHash[:]...)
	digest := blake2b.Sum256(cid)

	verified := parsedSig.Verify(digest[:], parsedPK)
	assert.True(t, verified, "Signature verification failed")

	fmt.Printf("RawBytes Signature R: %x\n", signature.r)
	fmt.Printf("RawBytes Signature S: %x\n", signature.s)
	fmt.Printf("RawBytes Signature V: %d\n", signature.v)
	fmt.Printf("RawBytes DER Signature: %x\n", signature.derSignature)
}
