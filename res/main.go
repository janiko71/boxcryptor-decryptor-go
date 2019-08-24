package res

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/gookit/color.v1"
)

/* ==================================================================

	   Some useful functions

   ================================================================== */

func Credentials() string {

	//
	// Function for reading a password through the standard console (in)
	//

	fmt.Print("Enter Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	password := string(bytePassword)

	return strings.TrimSpace(password)
}

func FileExists(filename string) bool {

	//
	// Function to check if the file (in param) exists or not
	//

	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func PrintParameter(txt, param string) {

	//
	// Function pretty-print some text
	//

	color.FgDefault.Printf("%-50s", txt)
	color.Green.Print(param)
	color.FgDefault.Println()
}

func PrintBytes(txt string, b []byte) {

	//
	// Function pretty-print some text (bytes are converted into hex)
	//

	color.FgDefault.Printf("%-50s", txt)
	color.FgGreen.Print(hex.EncodeToString(b))
	/*for i := 0; i < len(b); i++ {
		color.FgGreen.Printf("%v ", b[i])
	}*/
	color.FgDefault.Println()
}

func PKCS5Trimming(encrypt []byte) []byte {
	// http://www.herongyang.com/Cryptography/DES-JDK-What-Is-PKCS5Padding.html
	/*padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]*/
	l := len(encrypt)
	m := int(encrypt[l-1])
	return encrypt[:l-m]
}

func CheckErr(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

func Line() {
	fmt.Println("------------------------------------------------------------------------")
}

func ComputeBlockIV(initVector []byte, seed int, key []byte) []byte {

	/*
		This function computes the initialization vector for every
		encrypted block in the data file. Every block has its own
		init vector, to prevent cryptoanalyzing.
		The init vector is the first part of a HMAC calculated from
		the data file init vector, a seed (which is simply the block
		number, and the file's AES key)
	*/

	tmpData := make([]byte, 16)
	result := make([]byte, 16)
	copy(tmpData, initVector)
	bseed := byte(seed)
	//fmt.Println(hex.EncodeToString(initVector))
	//fmt.Println("...........")

	for i := 0; i < 8; i++ {
		b := bseed & 255
		tmpData = append(tmpData, b)
		bseed = bseed >> 8
		//fmt.Println(hex.EncodeToString(tmpData))

		hmacHelper := hmac.New(sha256.New, key)
		hmacHelper.Write(tmpData)
		calculatedHMAC := hmacHelper.Sum(nil)
		copy(result, calculatedHMAC[:len(initVector)])
	}

	return result
}
