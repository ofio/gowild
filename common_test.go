package common

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/aead/ecdh"
	"github.com/jeremywohl/flatten"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"golang.org/x/crypto/sha3"
)

func TestStringCommands(t *testing.T) {
	is := "data.team.user.email.trevjmoore@gmail.com"
	tm := map[string]interface{}{
		"start": true,
		"params": map[string]interface{}{
			"trigger_fields": []string{
				"data.owner", "data.email",
			},
			"trigger_table_name":         "board_item",
			"trigger_govaluate":          "",
			"trigger_field_condition":    []string{"updated", "assigned"},
			"test_struct":                map[string]interface{}{"int_array": []int{0, 4, 6, 2, 3, 9, 8}, "email": "trevor@infor500.com", "string_array": map[string]interface{}{"key1": "value1", "email": "trevor@raindrop.com", "key3": "value3", "bool_array": []bool{false, true, true, true}}},
			"trigger_type":               "workflow_event",
			"trigger_operation":          "update",
			"trigger_parent_object_type": "contract",
			"trigger_parent_id":          3,
		},
		"id":    1,
		"type":  "trigger",
		"label": "Contract Approval Request",
	}
	om, err := flatten.Flatten(tm, "", flatten.DotStyle)
	if err != nil {
		log.Println("flatten error")
	}
	log.Println(om)
	check := strings.Contains(is, "email")
	log.Println(check)
	op := strings.Fields(is)
	log.Println(op)
	f := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}
	op = strings.FieldsFunc(is, f)
	log.Println(op)

	//t
	log.Println(is[strings.Index(is, ".email.")+7:])
	var emArr []string
	for u, v := range om {
		if strings.Contains(u, "email") {

			if strings.Index(u, ".email") == len(u)-6 {
				if reflect.TypeOf(v).String() == "string" {
					emArr = append(emArr, v.(string))
				}
			}
		}
	}
	log.Println("emails", emArr)
}

func TestPDFWatermark(t *testing.T) {
	onTop := true
	wm, _ := pdfcpu.ParseTextWatermarkDetails("Demo", "", onTop)
	//pdfcpu.ParseImageWatermarkDetails()
	api.AddWatermarksFile("in.pdf", "", nil, wm, nil)

	// Update stamp for correction:
	wm, _ = pdfcpu.ParseTextWatermarkDetails("Confidential", "", onTop)
	wm.Update = true
	api.AddWatermarksFile("in.pdf", "", nil, wm, nil)

	// Add another watermark on top of page 1
	wm, _ = pdfcpu.ParseTextWatermarkDetails("Footer stamp", "c:.5 1 1, pos:bc", onTop)
	api.AddWatermarksFile("in.pdf", "", nil, wm, nil)

	// Remove watermark on page 1
	api.RemoveWatermarksFile("in.pdf", "", []string{"1"}, nil)

	// Remove all watermarks
	api.RemoveWatermarksFile("in.pdf", "", nil, nil)

	imgW, err := api.ImageWatermark("raindrop.jpeg", "yes", true, true)
	if err != nil {
		log.Println(err)
	}
	api.AddWatermarksFile("example.pdf", "", nil, imgW, nil)
}

func TestPrepend(t *testing.T) {
	arr := []interface{}{"a", "b", "c", "d", "e", "f"}
	newSlice := prependArray(arr, "d")
	log.Println(newSlice)
}

func TestPDFEncrypt(t *testing.T) {

	file, err := os.OpenFile("IMG_1815.pdf", os.O_RDWR, 0644)
	if err != nil {
		log.Println(err)
	}
	pdfBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println(err)
	}
	pdfr := bytes.NewReader(pdfBytes)
	var buf bytes.Buffer
	pdfr.WriteTo(&buf)
	userPass := "user"
	ownerPass := "owner"
	rdr, err := encryptPDF(buf, userPass, ownerPass)
	if err != nil {
		log.Println(err)
	}
	drdr, err := decryptPDF(*rdr, userPass, ownerPass)
	if err != nil {
		log.Println(err)
	}
	out, err := os.Create("example.pdf")
	if err != nil {
		log.Println(err)
	}
	defer out.Close()
	// Write the body to file
	_, err = drdr.WriteTo(out)
	if err != nil {
		log.Println(err)
	}

}

func TestHmac(t *testing.T) {
	key := []byte("5ebe2294ecd0e0f08eab7690d2a6ee69")
	message := "secret message to compute hash"

	sig := hmac.New(sha256.New, key)
	sig.Write([]byte(message))

	fmt.Println(hex.EncodeToString(sig.Sum(nil)))
}

func TestHash(t *testing.T) {
	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf := []byte("and this is some data to authenticate")
	// A MAC with 32 bytes of output has 256-bit security strength -- if you use at least a 32-byte-long key.
	h := make([]byte, 32)
	d := sha3.NewShake256()
	// Write the key into the hash.
	d.Write(k)
	// Now write the data.
	d.Write(buf)
	// Read 32 bytes of output from the hash into h.
	d.Read(h)
	fmt.Printf("%x\n", h)

	buf2 := []byte("some data to hash")
	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	hash := make([]byte, 64)
	// Compute a 64-byte hash of buf and put it in h.
	sha3.ShakeSum256(hash, buf2)
	fmt.Printf("%x\n", hash)
}
func TestEncryption(t *testing.T) {
	fmt.Println("Starting the application...")
	ciphertext := encrypt([]byte("Hello World"), "password")
	fmt.Printf("Encrypted: %x\n", ciphertext)
	plaintext := decrypt(ciphertext, "password")
	fmt.Printf("Decrypted: %s\n", plaintext)
	encryptFile("sample.txt", []byte("Hello World"), "password1")
	fmt.Println(string(decryptFile("sample.txt", "password1")))
}

const BUFFER_SIZE int = 4096
const IV_SIZE int = 16

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
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

func TestStringSplit(t *testing.T) {
	pathname := "data.owner.name"
	resultArr := strings.Split(pathname, ".")
	log.Println(resultArr)
}

func TestSha3(t *testing.T) {
	buf := []byte("some data to hash")
	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	h := make([]byte, 64)
	// Compute a 64-byte hash of buf and put it in h.
	sha3.ShakeSum256(h, buf)

	fmt.Printf("%x\n", h)

	k := []byte("this is a secret key; you should generate a strong random key that's at least 32 bytes long")
	buf = []byte("and this is some data to authenticate")
	// A MAC with 32 bytes of output has 256-bit security strength -- if you use at least a 32-byte-long key.
	hash := make([]byte, 32)
	d := sha3.NewShake256()
	// Write the key into the hash.
	d.Write(k)
	// Now write the data.
	d.Write(buf)
	// Read 32 bytes of output from the hash into h.
	d.Read(hash)
	fmt.Printf("%x\n", h)
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

func TestAsyncECDH(t *testing.T) {
	pkr := publicKeyring{v: make(map[int]crypto.PublicKey), m: make(map[int][]byte)}
	//need a waitgroup to wait until both entities exchange their public keys
	pkr.wg.Add(2)
	pchan := make(chan (bool))
	mchan := make(chan ([]byte), 2)
	for i := 0; i < 2; i++ {
		go func(i int, mchan chan []byte, pkr *publicKeyring) {
			pkr.genECDH(pchan, mchan, i)
		}(i, mchan, &pkr)
	}
	pkr.wg.Wait()
	pchan <- true
	pchan <- true
	h1 := <-mchan
	h2 := <-mchan
	//check that message hash is the same
	log.Println(bytes.Equal(h1, h2))
	_ = <-pchan
	_ = <-pchan
	//check that encrypted messages exist
	mchan <- pkr.m[0]
	log.Println("encrypted message 0", string(pkr.m[0]))
	mchan <- pkr.m[1]
	log.Println("encrypted message 1", string(pkr.m[1]))
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

func TestAES(t *testing.T) {
	aes.NewCipher([]byte(`asdgsadg`))
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

func TestEncryptCTR(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		panic(err)
	}

	value := "foobarbaz asdfgasg df adf faffdf dfadsg thsi a a test of streaming encryption using a block cipher"
	encrypted := encryptByte(block, []byte(value))
	decrypted := decryptByte(block, encrypted)
	fmt.Printf("--- %s ---", string(decrypted))
}
