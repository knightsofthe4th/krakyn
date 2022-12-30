package krakyn

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

/*===============================================
 *            AUTHENTICATION STRUCT
 *===============================================
 */

type Authenticator struct {
	Name       string
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

/*===============================================
 *              RSA AUTHENTICATION
 *===============================================
 */

func RSAEncrypt(pub *rsa.PublicKey, data []byte) []byte {
	label := []byte("KRAKYN RSA")
	ci, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, label)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	secret := make([]byte, base64.StdEncoding.EncodedLen(len(ci)))
	base64.StdEncoding.Encode(secret, ci)

	return secret
}

func RSADecrypt(priv *rsa.PrivateKey, data []byte) []byte {
	secret := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	count, err := base64.StdEncoding.Decode(secret, data)
	label := []byte("KRAKYN RSA")

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, secret[:count], label)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return plain
}

func RSASign(priv *rsa.PrivateKey, data []byte) []byte {
	hash := SHA256Hash(data)

	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hash, nil)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return sig
}

func RSAVerify(pub *rsa.PublicKey, data []byte, sig []byte) bool {
	hash := SHA256Hash(data)

	err := rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, nil)
	return err == nil
}

func RSAGenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println(err.Error())
		return nil, nil
	}

	return privateKey, &privateKey.PublicKey
}

func RSAPrivKeyToBytes(key *rsa.PrivateKey) []byte {
	priv := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	return priv
}

func RSAPubKeyToBytes(key *rsa.PublicKey) []byte {
	pub := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(key),
		},
	)

	return pub
}

func RSABytesToPrivKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	bytes := block.Bytes

	priv, err := x509.ParsePKCS1PrivateKey(bytes)

	if err != nil {
		return nil, err
	}

	return priv, nil
}

func RSABytesToPubKey(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	bytes := block.Bytes

	pub, err := x509.ParsePKCS1PublicKey(bytes)

	if err != nil {
		return nil, err
	}

	return pub, nil
}

/*===============================================
 *              AES AUTHENTICATION
 *===============================================
 */

func AESDeriveKey(pass []byte, salt []byte) []byte {
	return pbkdf2.Key(pass, salt, 80000, 32, sha256.New)
}

func AESEncrypt(key []byte, data []byte) []byte {
	ci, err := aes.NewCipher(key)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	gcm, err := cipher.NewGCM(ci)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return gcm.Seal(nonce, nonce, data, nil)
}

func AESDecrypt(key []byte, data []byte) []byte {
	ci, err := aes.NewCipher(key)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	gcm, err := cipher.NewGCM(ci)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	ns := gcm.NonceSize()

	if len(data) < ns {
		fmt.Println(err.Error())
		return nil
	}

	nonce, data := data[:ns], data[ns:]

	plain, err := gcm.Open(nil, nonce, data, nil)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return plain
}

/*===============================================
 *           CRYPTO UTILITY FUNCTIONS
 *===============================================
 */

func SHA256Hash(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)

	return hasher.Sum(nil)
}

func GenerateValue32() []byte {
	value := make([]byte, 24)

	mrand.Seed(time.Now().UnixNano())
	mrand.Read(value)

	time.Sleep(50 * time.Millisecond)
	return []byte(base64.StdEncoding.EncodeToString(value))
}

/*===============================================
 *      PROFILE GENERATION/AUTHENTICATION
 *===============================================
 */

func GenerateProfile(user, pass, path string) error {
	priv, pub := RSAGenerateKeys()
	salt := GenerateValue32()

	buffer := make([]byte, 0)

	buffer = append(buffer, []byte(MAGIC_VAL)...)
	buffer = append(buffer, salt...)
	buffer = append(buffer, []byte(SEP_VAL)...)

	key := AESDeriveKey(append([]byte(user), []byte(pass)...), salt)

	keypair := RSAPrivKeyToBytes(priv)
	keypair = append(keypair, []byte(SEP_VAL)...)
	keypair = append(keypair, RSAPubKeyToBytes(pub)...)

	rsabytes := AESEncrypt(key, keypair)
	buffer = append(buffer, rsabytes...)

	err := os.WriteFile(path, buffer, 0644)

	if err != nil {
		return err
	} else {
		return nil
	}
}

func LoadProfile(user, pass, path string) (*Authenticator, error) {
	file, err := os.ReadFile(path)

	if err != nil {
		return nil, err
	}

	if string(file[:len(MAGIC_VAL)]) != MAGIC_VAL {
		return nil, fmt.Errorf("file does not appear to be a valid format")
	}

	file = file[len(MAGIC_VAL):]

	buffer := bytes.Split(file, []byte(SEP_VAL))
	salt, keycipher := buffer[0], buffer[1]

	masterkey := AESDeriveKey(append([]byte(user), []byte(pass)...), salt)
	plainkeys := bytes.Split(AESDecrypt(masterkey, keycipher), []byte(SEP_VAL))

	if len(plainkeys) < 2 {
		return nil, fmt.Errorf("failed to retrieve key pair data")
	}

	priv, err := RSABytesToPrivKey(plainkeys[0])

	if err != nil {
		return nil, err
	}

	pub, err := RSABytesToPubKey(plainkeys[1])

	if err != nil {
		return nil, err
	}

	return &Authenticator{
		Name:       user,
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}
