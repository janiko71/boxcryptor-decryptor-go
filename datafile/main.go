package datafile

import (
	"boxcryptor/res"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/gookit/color.v1"
)

// =======================================================================================================================
//
//   Class for the encrypted file (your file, containing your datas)
//
// =======================================================================================================================

//
// The data file also contains crypto information we need to gather. The file structure depends on the cipher blocksize,
// which is one of the information within the file.
//
// In the file structure, the first block is reserved for the boxcryptor header. This block size is calculated as
// 'offset', and it's padded with NUL (\x00)
//
// +-------------+-------------+-----------+----------------+----------------+-------...------------+
// | boxcryptor  | Json with   | Padding   | Encrypted      | Encrypted      |       ...            |
// | header      | crypto info | with \x00 | data block #1  | data block #2  |       ...            |
// | (48 bytes)  |             |           |                |                |       ...            |
// +-------------+-------------+-----------+----------------+----------------+-------...------------+
// |                                       |                |                |                      |
// |<------------------------------------->|<-------------->|<-------------->|                      |
// |                                       |   blocksize    |   blocksize    |                      |
// 0                                    offset                                                 filesize
//

type File struct {
	Version             string
	HeaderCoreLength    int
	HeaderPaddingLength int
	CipherPaddingLength int
	HashCtrl            []byte
	CryptoJSON          []byte
	CipherAlgo          string
	CipherMode          string
	CipherPaddingMode   string
	CipherKeysize       int
	CipherBlocksize     int
	CipherInitVector    []byte
	FileType            string
	FileID              string
	FileSize            int
	EncryptedKey        []byte
	EncryptedContent    []byte
	OsFileMode          os.FileMode
}

func Read(dataFilename string, debug bool) *File {

	// First of all: read the .bckey file, containing all needed crypto information
	result := File{}

	// Open our jsonFile
	f, err := os.Open(dataFilename)
	res.CheckErr(err)

	// We close the file at the end
	defer f.Close()

	// Parsing
	b4 := make([]byte, 4)
	b32 := make([]byte, 32)
	f.Read(b4)
	result.Version = string(b4)
	f.Read(b4)
	result.HeaderCoreLength = int(binary.LittleEndian.Uint32(b4))
	f.Read(b4)
	result.HeaderPaddingLength = int(binary.LittleEndian.Uint32(b4))
	f.Read(b4)
	result.CipherPaddingLength = int(binary.LittleEndian.Uint32(b4))
	f.Read(b32)
	result.HashCtrl = b32

	// Cryptographic information (JSON Format)
	buff := make([]byte, result.HeaderCoreLength)
	f.Read(buff)

	// read our opened xmlFile as a byte array.
	var cryptoInfoJSON map[string]interface{}
	json.Unmarshal([]byte(buff), &cryptoInfoJSON)
	if debug {
		fmt.Println(cryptoInfoJSON)
	}

	// Exit if the file looks bad
	if cryptoInfoJSON["artifact"] != "header" {
		color.FgRed.Printf("Datafile not a well-formatted. Found artifact '%v' instead of 'header'\n", cryptoInfoJSON["artifact"])
		os.Exit(1)
	}

	cp := cryptoInfoJSON["cipher"].(map[string]interface{})
	result.CipherAlgo = cp["algorithm"].(string)
	result.CipherMode = cp["mode"].(string)
	result.CipherPaddingMode = cp["padding"].(string)
	result.CipherKeysize = int(cp["keySize"].(float64))
	result.CipherBlocksize = int(cp["blockSize"].(float64))
	result.CipherInitVector, _ = base64.StdEncoding.DecodeString(cp["iv"].(string))

	// EFK
	efk := cryptoInfoJSON["encryptedFileKeys"].([]interface{})[0].(map[string]interface{})
	result.FileID = efk["id"].(string)
	result.FileType = efk["type"].(string)
	fs, _ := f.Stat()
	result.FileSize = int(fs.Size())
	result.OsFileMode = fs.Mode()

	// Encrypted Key
	result.EncryptedKey, _ = base64.StdEncoding.DecodeString(efk["value"].(string))

	return &result
}
