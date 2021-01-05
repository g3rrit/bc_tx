package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ripemd160"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/shengdoushi/base58"
)

const seederHostname = "seed.bitcoinabc.org"

func lookupNodes() []net.IP {

	ips, err := net.LookupIP(seederHostname)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to resolve hostname (%s): %v\n", seederHostname, err)
		os.Exit(0)
	}

	return ips
}

func b58CheckEncode(v byte, pl []byte) string {
	s := append([]byte{v}, pl...)
	s1 := sha256.Sum256(pl)
	s2 := sha256.Sum256(s1[:])
	cs := s2[:4]
	r := append(s, cs...)
	return base58.Encode(r, base58.BitcoinAlphabet)
}

func privKeyToWif(k []byte) string {
	return b58CheckEncode(0x80, k)
}

type key struct {
	priv    *ecdsa.PrivateKey
	privWif string
	pub     []byte
	add     string
}

func newKey() key {
	// This is just for testing purposes. I have not looked into how this lib generates keys.
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to generate secp256k1 private key")
		os.Exit(1)
	}

	return newKeyFromPriv(priv)
}

func newKeyFromBytes(key [32]byte) key {

	priv := secp256k1.PrivKeyFromBytes(key[:])

	return newKeyFromPriv(priv)
}

func newKeyFromPriv(priv *secp256k1.PrivateKey) key {

	privSer := priv.Serialize()
	pubSer := priv.PubKey().SerializeCompressed() // or uncompressed

	privFull := append([]byte{0x80}, privSer...)
	privShaA := sha256.Sum256(privFull)
	privShaB := sha256.Sum256(privShaA[:])
	privWif := base58.Encode(append(privFull, privShaB[:8]...), base58.BitcoinAlphabet)

	pubFull := append([]byte{0x04}, pubSer...)
	pubShaA := sha256.Sum256(pubFull)
	pubHash160 := ripemd160.New().Sum(pubShaA[:])[32:]
	pubAddA := append([]byte{0x00}, pubHash160...)
	pubShaB := sha256.Sum256(pubAddA)
	pubShaC := sha256.Sum256(pubShaB[:])
	pubAdd := base58.Encode(append(pubAddA, pubShaC[:4]...), base58.BitcoinAlphabet)

	return key{
		priv:    priv.ToECDSA(),
		privWif: privWif,
		pub:     pubFull,
		add:     pubAdd,
	}
}

func main() {

	ips := lookupNodes()

	for _, ip := range ips {
		fmt.Printf("Found IP: %s\n", ip.String())
	}

	key := newKey()
	fmt.Printf("priv_key: %s\npub_key: %s\nadd_len: %d\n", key.privWif, key.add, len(key.add))
}
