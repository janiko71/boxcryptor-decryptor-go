package exportkey

import (
	"boxcryptor/res"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

type File struct {
	KdfIterations            int
	SaltBytes                []byte
	EncryptedPrivateKeyBytes []byte
	PublicKeyBytes           []byte
	WrappingKeyBytes         []byte
	AESKeyBytes              []byte
	Username                 string
	FirstName                string
	LastName                 string
}

// ===========================================================================
//
//   This package
//
// ===========================================================================

func Read(bcFileName string, debug bool) *File {

	// First of all: read the .bckey file, containing all needed crypto information
	result := File{}

	// Open our jsonFile
	jsonFile, err := os.Open(bcFileName)

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully opened file", bcFileName)

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	bckeyRaw, _ := ioutil.ReadAll(jsonFile)
	var bckeyJSON map[string]interface{}
	json.Unmarshal([]byte(bckeyRaw), &bckeyJSON)

	// Exit if the file looks bad
	if bckeyJSON["artifact"] != "keyfile" {
		fmt.Println("Not a well-formatted key file")
		os.Exit(1)
	}

	// We assume that we're not in an organization, so there's only one user
	users := bckeyJSON["users"].([]interface{})
	theUser := users[0].(map[string]interface{})
	result.Username = theUser["username"].(string)
	result.FirstName = theUser["firstname"].(string)
	result.LastName = theUser["lastname"].(string)

	// Key derivation information
	result.KdfIterations = int(theUser["kdfIterations"].(float64))
	result.SaltBytes, _ = base64.StdEncoding.DecodeString(theUser["salt"].(string))
	if debug {
		res.PrintParameter("Key derivation # of iterations", strconv.Itoa(result.KdfIterations))
		res.PrintBytes("Salt (bytes)", result.SaltBytes)
	}

	// Base64 encoded datas (mainly crypto keys)
	result.EncryptedPrivateKeyBytes, _ = base64.StdEncoding.DecodeString(theUser["privateKey"].(string))
	result.PublicKeyBytes, _ = base64.StdEncoding.DecodeString(theUser["publicKey"].(string))
	result.WrappingKeyBytes, _ = base64.StdEncoding.DecodeString(theUser["wrappingKey"].(string))
	result.AESKeyBytes, _ = base64.StdEncoding.DecodeString(theUser["aesKey"].(string))
	if debug {
		res.PrintBytes("Encrypted Private Key (first bytes)", result.EncryptedPrivateKeyBytes[:30])
		res.PrintBytes("Public Key (first bytes)", result.PublicKeyBytes[:30])
		res.PrintBytes("Wrapping Key (first bytes)", result.WrappingKeyBytes[:30])
		res.PrintBytes("AES Key (first bytes)", result.AESKeyBytes[:30])
	}

	return &result
}

// ---------------------------------
//   Fonctions annexes
// ---------------------------------
