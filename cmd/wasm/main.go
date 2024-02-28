package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	ecdsa_schnorr "github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

type ModNScalar = btcec.ModNScalar
type PrivateKey = secp256k1.PrivateKey
type PublicKey = secp256k1.PublicKey
type PrivateRand = secp256k1.ModNScalar
type PublicRand = secp256k1.FieldVal

// BEP-340 Schnorr signatures.
type Signature = ModNScalar

type ErrorKind = ecdsa_schnorr.ErrorKind
type Error = ecdsa_schnorr.Error

func signatureError(kind ErrorKind, desc string) Error {
	return Error{Err: kind, Description: desc}
}

func main() {
	done := make(chan struct{}, 0)

	js.Global().Set("jsKeyGen", jsKeyGen())
	js.Global().Set("jsPubGen", jsPubGen())
	js.Global().Set("jsRandGen", jsRandGen())
	js.Global().Set("jsGenerateKeys", jsGenerateKeys())
	js.Global().Set("jsGenerateSignatures", jsGenerateSignatures())
	js.Global().Set("jsGenerateTx", jsGenerateTx())
	js.Global().Set("jsDecodeWif", jsDecodeWif())

	<-done

}

func jsDecodeWif() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		result := make([]interface{}, 0)
		wif_bytes_string := args[0].String()
		wif, err := btcutil.DecodeWIF(wif_bytes_string)
		if err != nil {
			return "unable to wif"
		}
		result = append(result, wif.PrivKey.Key.String())
		return result

	})
	return helperFunc

}
func jsGenerateSignatures() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		result := make([]interface{}, 0)
		sk_bytes_string := args[0].String()
		private_rand_string := args[1].String()
		private_rand_uint32, _ := strconv.ParseUint(private_rand_string, 16, 32)
		private_rand := new(secp256k1.ModNScalar).SetInt(uint32(private_rand_uint32))
		message1 := args[2].String()
		message2 := args[3].String()

		sk_bytes, err := hex.DecodeString(sk_bytes_string)
		if err != nil {
			return "unable to key"
		}
		sk := secp256k1.PrivKeyFromBytes(sk_bytes)

		h1 := chainhash.HashB([]byte(message1))
		s1, _ := Sign(sk, private_rand, h1)

		h2 := chainhash.HashB([]byte(message2))
		s2, _ := Sign(sk, private_rand, h2)

		result = append(result, js.ValueOf(hex.EncodeToString(h1)))
		result = append(result, js.ValueOf(s1.String()))

		result = append(result, js.ValueOf(hex.EncodeToString(h2)))

		result = append(result, js.ValueOf(s2.String()))

		return js.ValueOf(result)

	})
	return helperFunc

}

func jsGenerateTx() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		result := make([]interface{}, 0)

		sender_sk_string := args[0].String()
		amount_string := args[1].String()
		fees_string := args[2].String()
		recv_address_string := args[3].String()
		unspent_tx_id_string := args[4].String()
		out_index_string := args[5].String()

		sk_bytes, err := hex.DecodeString(sender_sk_string)
		if err != nil {
			return "unable to key"
		}
		sender_sk := secp256k1.PrivKeyFromBytes(sk_bytes)

		amount, _ := strconv.ParseUint(amount_string, 16, 32)
		fees, _ := strconv.ParseUint(fees_string, 16, 32)
		out_index, _ := strconv.ParseUint(out_index_string, 16, 32)
		unspent_tx_id, _ := chainhash.NewHashFromStr(unspent_tx_id_string)
		recv_address, err := btcutil.DecodeAddress(recv_address_string, &chaincfg.TestNet3Params)

		recTx := wire.NewMsgTx(wire.TxVersion)

		outPoint := wire.NewOutPoint(unspent_tx_id, uint32(out_index))
		txIn := wire.NewTxIn(outPoint, nil, nil)
		recTx.AddTxIn(txIn)

		rcvScript2, err := txscript.PayToAddrScript(recv_address)
		if err != nil {
			return "err gen tx"
		}
		outCoin := int64(amount - fees)
		txOut := wire.NewTxOut(outCoin, rcvScript2)
		recTx.AddTxOut(txOut)

		senderAddress, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(sender_sk.PubKey().SerializeCompressed()), &chaincfg.TestNet3Params)
		rcvScript, err := txscript.PayToAddrScript(senderAddress)
		if err != nil {
			return "err gen tx"
		}

		scriptSig, err := txscript.SignatureScript(
			recTx,
			0,
			rcvScript,
			txscript.SigHashAll,
			sender_sk,
			true)
		if err != nil {
			return "err gen tx"
		}
		recTx.TxIn[0].SignatureScript = scriptSig

		buf := bytes.NewBuffer(make([]byte, 0, recTx.SerializeSize()))
		recTx.Serialize(buf)

		// verify transaction
		vm, err := txscript.NewEngine(rcvScript, recTx, 0, txscript.StandardVerifyFlags, nil, nil, int64(amount), nil)
		if err != nil {
			return "err gen tx"
		}
		if err := vm.Execute(); err != nil {
			return "err gen tx"
		}

		hash := recTx.TxHash()
		result = append(result, js.ValueOf(hash.String()))
		result = append(result, js.ValueOf(hex.EncodeToString(buf.Bytes())))
		return result

	})
	return helperFunc
}

func jsGenerateKeys() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		result := make([]interface{}, 0)

		secretKey, err := KeyGen(rand.Reader)
		if err != nil {
			panic(err)
		}

		publicKey := PubGen(secretKey)

		privateRand, publicRand, err := RandGen(rand.Reader)
		if err != nil {
			js.Global().Get("console").Call("log", "error")
			return "randgen err"

		}
		wif, err := btcutil.NewWIF(secretKey, &chaincfg.TestNet3Params, true)
		if err != nil {
			panic(err)
		}

		address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(publicKey.SerializeCompressed()), &chaincfg.TestNet3Params)
		if err != nil {
			panic(err)
		}

		js.Global().Get("console").Call("log", "address: ", js.ValueOf(address.String()))
		result = append(result, js.ValueOf(secretKey.Key.String()))
		result = append(result, js.ValueOf(hex.EncodeToString(publicKey.SerializeCompressed())))

		result = append(result, js.ValueOf(privateRand.String()))

		result = append(result, js.ValueOf(publicRand.String()))

		result = append(result, js.ValueOf(wif.String()))
		result = append(result, js.ValueOf(address.String()))

		return js.ValueOf(result)
	})
	return helperFunc

}

func jsKeyGen() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
		if err != nil {
			return "unable to keygen"
		}
		return pk.Key.String()
	})
	return helperFunc
}

func KeyGen(randSource io.Reader) (*PrivateKey, error) {
	return secp256k1.GeneratePrivateKeyFromRand(randSource)
}

func jsPubGen() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pk_bytes_string := args[0].String()
		pk_bytes, err := hex.DecodeString(pk_bytes_string)
		if err != nil {
			return "unable to key"
		}
		pk := secp256k1.PrivKeyFromBytes(pk_bytes)
		return hex.EncodeToString(pk.PubKey().SerializeCompressed())
	})
	return helperFunc
}

func PubGen(k *PrivateKey) *PublicKey {
	return k.PubKey()
}

// RandGen returns the value to be used as random value when signing, and the associated public value.
func jsRandGen() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		result := make([]interface{}, 0)

		pk, err := KeyGen(rand.Reader)

		if err != nil {
			result = append(result, "unable to rand")
			return result
		}
		var j secp256k1.JacobianPoint
		pk.PubKey().AsJacobian(&j)
		result = append(result, pk.Key.String())
		result = append(result, j.X.String())
		return js.ValueOf(result)

	})
	return helperFunc
}

// RandGen returns the value to be used as random value when signing, and the associated public value.
func RandGen(randSource io.Reader) (*PrivateRand, *PublicRand, error) {
	pk, err := KeyGen(randSource)
	if err != nil {
		return nil, nil, err
	}
	var j secp256k1.JacobianPoint
	pk.PubKey().AsJacobian(&j)
	return &pk.Key, &j.X, nil
}

func jsHash() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid params"
		}
		return "hi"
	})
	return helperFunc
}

// hash function is used for hashing the message input for all functions of the library.
// Wrapper around sha256 in order to change only one function if the input hashing function is changed.
func hash(message []byte) [32]byte {
	return sha256.Sum256(message)
}

// Sign returns an extractable Schnorr signature for a message, signed with a private key and private randomness value.
// Note that the Signature is only the second (S) part of the typical bitcoin signature, the first (R) can be deduced from
// the public randomness value and the message.
func Sign(sk *PrivateKey, privateRand *PrivateRand, message []byte) (*Signature, error) {
	h := hash(message)
	return signHash(sk, privateRand, h)
}

// signHash returns an extractable Schnorr signature for a hashed message.
// The caller MUST ensure that hash is the output of a cryptographically secure hash function.
// Based on unexported schnorrSign of btcd.
func signHash(sk *PrivateKey, privateRand *PrivateRand, hash [32]byte) (*Signature, error) {
	if sk.Key.IsZero() {
		str := "private key is zero"
		return nil, signatureError(ecdsa_schnorr.ErrPrivateKeyIsZero, str)
	}

	// d' = int(d)
	var privKeyScalar ModNScalar
	privKeyScalar.Set(&sk.Key)

	pubKey := PubGen(sk)

	// Negate d if P.y is odd.
	pubKeyBytes := pubKey.SerializeCompressed()
	if pubKeyBytes[0] == secp256k1.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	k := new(ModNScalar).Set(privateRand)

	// R = kG
	var R btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(k, &R)

	// Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
	}

	// e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m) mod n
	var rBytes [32]byte
	r := &R.X
	r.PutBytesUnchecked(rBytes[:])
	pBytes := pubKey.SerializeCompressed()[1:]

	commitment := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, rBytes[:], pBytes, hash[:])

	var e ModNScalar
	if overflow := e.SetBytes((*[32]byte)(commitment)); overflow != 0 {
		k.Zero()
		str := "hash of (r || P || m) too big"
		return nil, signatureError(ecdsa_schnorr.ErrSchnorrHashValue, str)
	}

	// s = k + e*d mod n
	sig := new(ModNScalar).Mul2(&e, &privKeyScalar).Add(k)

	// If Verify(bytes(P), m, sig) fails, abort.
	// optional

	// Return s
	return sig, nil
}

// Verify verifies that the signature is valid for this message, public key and random value.
func Verify(pubKey *PublicKey, r *PublicRand, message []byte, sig *Signature) error {
	h := hash(message)
	return verifyHash(pubKey, r, h, sig)
}

// Verify verifies that the signature is valid for this hashed message, public key and random value.
// Based on unexported schnorrVerify of btcd.
func verifyHash(pubKey *PublicKey, r *PublicRand, hash [32]byte, sig *Signature) error {
	// Fail if P is not a point on the curve
	if !pubKey.IsOnCurve() {
		str := "pubkey point is not on curve"
		return signatureError(ecdsa_schnorr.ErrPubKeyNotOnCurve, str)
	}

	// Fail if r >= p is already handled by the fact r is a field element.
	// Fail if s >= n is already handled by the fact s is a mod n scalar.

	// e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	var rBytes [32]byte
	r.PutBytesUnchecked(rBytes[:])
	pBytes := pubKey.SerializeCompressed()[1:]

	commitment := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, rBytes[:], pBytes, hash[:])

	var e ModNScalar
	if overflow := e.SetBytes((*[32]byte)(commitment)); overflow != 0 {
		str := "hash of (r || P || m) too big"
		return signatureError(ecdsa_schnorr.ErrSchnorrHashValue, str)
	}

	// Negate e here so we can use AddNonConst below to subtract the s*G
	// point from e*P.
	e.Negate()

	// R = s*G - e*P
	var P, R, sG, eP btcec.JacobianPoint
	pubKey.AsJacobian(&P)
	btcec.ScalarBaseMultNonConst(sig, &sG)
	btcec.ScalarMultNonConst(&e, &P, &eP)
	btcec.AddNonConst(&sG, &eP, &R)

	// Fail if R is the point at infinity
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		str := "calculated R point is the point at infinity"
		return signatureError(ecdsa_schnorr.ErrSigRNotOnCurve, str)
	}

	// Fail if R.y is odd
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()
	if R.Y.IsOdd() {
		str := "calculated R y-value is odd"
		return signatureError(ecdsa_schnorr.ErrSigRYIsOdd, str)
	}

	// verify signed with the right k random value
	if !r.Equals(&R.X) {
		str := "calculated R point was not given R"
		return signatureError(ecdsa_schnorr.ErrUnequalRValues, str)
	}

	return nil
}

// Extract extracts the private key from a public key and signatures for two distinct hashes messages.
func Extract(pubKey *PublicKey, r *PublicRand, message1 []byte, sig1 *Signature, message2 []byte, sig2 *Signature) (*PrivateKey, error) {
	h1 := hash(message1)
	h2 := hash(message2)
	return extractFromHashes(pubKey, r, h1, sig1, h2, sig2)
}

// extractFromHashes extracts the private key from hashes, instead of the non-hashed message directly as Extract does.
func extractFromHashes(pubKey *PublicKey, r *PublicRand, hash1 [32]byte, sig1 *Signature, hash2 [32]byte, sig2 *Signature) (*PrivateKey, error) {
	var rBytes [32]byte
	r.PutBytesUnchecked(rBytes[:])
	pBytes := pubKey.SerializeCompressed()[1:]

	if sig1.Equals(sig2) {
		return nil, errors.New("The two signatures need to be different in order to extract")
	}

	commitment1 := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, rBytes[:], pBytes, hash1[:])
	var e1 ModNScalar
	if overflow := e1.SetBytes((*[32]byte)(commitment1)); overflow != 0 {
		str := "hash of (r || P || m1) too big"
		return nil, signatureError(ecdsa_schnorr.ErrSchnorrHashValue, str)
	}

	commitment2 := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, rBytes[:], pBytes, hash2[:])
	var e2 ModNScalar
	if overflow := e2.SetBytes((*[32]byte)(commitment2)); overflow != 0 {
		str := "hash of (r || P || m2) too big"
		return nil, signatureError(ecdsa_schnorr.ErrSchnorrHashValue, str)
	}

	// x = (s1 - s2) / (e1 - e2)
	var x, denom ModNScalar
	denom.Add2(&e1, e2.Negate())
	x.Add2(sig1, sig2.Negate()).Mul(denom.InverseNonConst())

	pubKeyBytes := pubKey.SerializeCompressed()
	if pubKeyBytes[0] == secp256k1.PubKeyFormatCompressedOdd {
		x.Negate()
	}

	privKey := secp256k1.NewPrivateKey(&x)
	if privKey.PubKey().IsEqual(pubKey) {
		return privKey, nil
	} else {
		return privKey, errors.New("Extracted private key does not match public key")
	}
}
