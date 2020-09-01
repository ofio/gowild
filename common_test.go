package common

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode"

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

func TestEncryptCTR(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		log.Println(err)
	}

	value := "foobarbaz asdfgasg df adf faffdf dfadsg thsi a a test of streaming encryption using a block cipher"
	encrypted := encryptByte(block, []byte(value))
	decrypted := decryptByte(block, encrypted)
	fmt.Printf("--- %s ---", string(decrypted))
}
