package common

import (

	//"bufio"

	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
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
