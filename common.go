package common

import (

	//"bufio"

	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strconv"
	"sync"

	"github.com/aead/ecdh"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"golang.org/x/crypto/sha3"
)

//encryptPDF experimental function to store bytes buffer to local pdf file encrypt file, then returns a byte buffer at the encryped file
func encryptPDF(buf bytes.Buffer, userPass, ownPass string) (*bytes.Buffer, error) {
	//create temporary local file with provided fileName
	fileName := "temp.pdf"
	out, err := os.Create(fileName)
	if err != nil {
		log.Println("local file creation error", err)
		return nil, err
	}
	defer out.Close()
	// Write the bytes buffer to file
	_, err = buf.WriteTo(out)
	if err != nil {
		log.Println("file write error", err)
		return nil, err
	}
	//encrypt the file with user and owner password
	conf := pdfcpu.NewAESConfiguration(userPass, ownPass, 256)
	err = api.EncryptFile(fileName, "", conf)
	//open file again
	file, err := os.OpenFile(fileName, os.O_RDWR, 0644)
	if err != nil {
		log.Println("open file ", fileName, err)
		return nil, err
	}
	defer file.Close()
	//create new reader on file bytes
	pdfBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("file read error", err)
		return nil, err
	}
	byteReader := bytes.NewReader(pdfBytes)
	var bb bytes.Buffer
	byteReader.WriteTo(&bb)
	return &bb, err
}

//prependArray looks for the value in the array if it find the value it is prepended to the array and returned, otherwise the same array is returned
func prependArray(arr []interface{}, val interface{}) []interface{} {
	if len(arr) == 0 {
		log.Println("zero length array")
		return arr
	}
	if reflect.TypeOf(arr[0]) != reflect.TypeOf(val) {
		log.Println("array and value mismatch", reflect.TypeOf(arr[0]).String(), reflect.TypeOf(val).String())
		return arr
	}
	var newSlice []interface{}
	exist := false
	for i, j := range arr {

		if j == val {
			newSlice = append(newSlice, j)
			newSlice = append(newSlice, arr[:i]...)
			newSlice = append(newSlice, arr[(i+1):]...)
			exist = true
		}
	}
	if exist == true {
		return newSlice
	}
	return arr
}

//decryptPDF decodes the pdf with the user and owner password and returns the decrypted pdf using bytes buffer
func decryptPDF(buf bytes.Buffer, userPass, ownPass string) (*bytes.Buffer, error) {
	//create temporary local file with provided fileName
	fileName := "temp.pdf"
	out, err := os.Create(fileName)
	if err != nil {
		log.Println("local file creation error", err)
		return nil, err
	}
	defer out.Close()
	// Write the bytes buffer to file
	_, err = buf.WriteTo(out)
	if err != nil {
		log.Println("file write error", err)
		return nil, err
	}
	//encrypt the file with user and owner password
	conf := pdfcpu.NewAESConfiguration(userPass, ownPass, 256)
	err = api.DecryptFile(fileName, "", conf)
	//open file again
	file, err := os.OpenFile(fileName, os.O_RDWR, 0644)
	if err != nil {
		log.Println("open file ", fileName, err)
		return nil, err
	}
	defer file.Close()
	//create new reader on file bytes
	pdfBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("file read error", err)
		return nil, err
	}
	byteReader := bytes.NewReader(pdfBytes)
	var bb bytes.Buffer
	byteReader.WriteTo(&bb)
	return &bb, err
}

//mergePDFs merges an array of pdf bytes converted to string
func mergePDFs(pdfBytes []string) ([]byte, error) {
	var readseekers []io.ReadSeeker

	for _, j := range pdfBytes {
		//decode usign standard decoding decodes with padding
		pdfb, err := base64.StdEncoding.DecodeString(j)
		//create new readseaker on reader to pdf bytes
		rs := io.ReadSeeker(bytes.NewReader(pdfb))
		readseekers = append(readseekers, rs)
		if err != nil {
			log.Println("base 64 decode error", err)
			return nil, err
		}
	}
	//create bytes buffer to write merge pdf
	var buf bytes.Buffer
	//write merged pdf to bytes buffer
	err := api.Merge(readseekers, &buf, nil)
	if err != nil {
		log.Println("pdf merge error", err)
		return nil, err
	}
	//write buff bytes to byte array
	mpdfb := buf.Bytes()
	return mpdfb, err
}

type ecdhKey struct {
	PrivateK crypto.PrivateKey
	PublicK  crypto.PublicKey
}

// Inc increments the counter for the given key.

type publicKeyring struct {
	m   map[int][]byte
	v   map[int]crypto.PublicKey
	mux sync.Mutex
	wg  sync.WaitGroup
}

//encrypt byte encrypts byte input using cipher block
func encryptByte(block cipher.Block, value []byte) []byte {
	// Generate an initialization vector (IV) suitable for encryption.
	// http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Initialization_vector_.28IV.29
	iv := make([]byte, block.BlockSize())
	rand.Read(iv)
	// Encrypt it.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(value, value)
	// Return iv + ciphertext.
	return append(iv, value...)
}

//decryptByte decrypts a byte using cipher block
func decryptByte(block cipher.Block, value []byte) []byte {
	if len(value) > block.BlockSize() {
		// Extract iv.
		iv := value[:block.BlockSize()]
		// Extract ciphertext.
		value = value[block.BlockSize():]
		// Decrypt it.
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(value, value)
		return value
	}
	return nil
}

//genECDH acts as a method on the public key ring, receiving channels as inputs
func (pkr *publicKeyring) genECDH(pchan chan bool, mchan chan []byte, n int) {

	c25519 := ecdh.X25519()

	privatek, publick, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private/public key pair: %s\n", err)
	}

	pkr.mux.Lock()
	pkr.v[n] = publick
	pkr.mux.Unlock()
	pkr.wg.Done()

	var k []byte

	chk := <-pchan
	if chk {
		k = c25519.ComputeSecret(privatek, pkr.v[(n+1)%2])
	}
	buf := []byte("this is a message for authentication. the message is hashed to verify message contents.  the recieved message is hashed again using the same key to make sure that the hash matches")
	// A MAC with 32 bytes of output has 256-bit security strength -- if you use at least a 32-byte-long key.
	hash := make([]byte, 64)
	d := sha3.NewShake256()
	// Write the key into the hash.
	d.Write(k)
	// Now write the data.
	d.Write(buf)
	// Read 32 bytes of output from the hash into h.
	d.Read(hash)
	mchan <- hash

	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	pkr.mux.Lock()
	pkr.m[n] = encryptByte(block, []byte("decrypted message from entity"+strconv.Itoa(n)))
	pkr.mux.Unlock()
	pchan <- true

	_ = <-mchan

	msg := decryptByte(block, pkr.m[(n+1)%2])

	log.Println("i am entity", strconv.Itoa(n), string(msg))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func chkHMAC(key, message string) string {

	sig := hmac.New(sha256.New, []byte(key))
	sig.Write([]byte(message))

	return hex.EncodeToString(sig.Sum(nil))

}
