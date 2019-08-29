package main

import (
	"boxcryptor/datafile"
	"boxcryptor/exportkey"
	"boxcryptor/res"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/gookit/color.v1"
)

var Debug = false

const DEFAULT_BCKEY_FILEPATH = "export.bckey"
const ALT_BCKEY_FILEPATH_CONFIGFILE = "bckey.txt"

var green = color.FgGreen.Render
var gray = color.FgWhite.Render
var white = color.FgLightWhite.Render

func main() {

	// ---------------------------------
	// OS Args
	// ---------------------------------

	// Options (command line)
	var argKeyFileName = flag.String("bckey", "", "\nFilepath of the exported keys file (ending with .bckey)\n"+
		"If no filepath provided, we'll use the one configured the 'bcdecryptor.py' file (BCKEY_FILEPATH constant)\n")
	var argPassword = flag.String("pwd", "", "\nBoxcryptor's user password. If not provided, it will be asked through console input")
	var debugMode = flag.Bool("d", Debug, "\nDisplay more information (verbose mode)\n")

	// Help message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, white("USAGE\n"))
		fmt.Fprintf(os.Stderr, gray("\n\tboxcryptor [options] [file]\n\n"))
		fmt.Fprintf(os.Stderr, white("DESCRIPTION\n"))
		fmt.Fprintf(os.Stderr, gray("\n"))
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, gray("\n"))
	}

	// Parsing arguments

	flag.Parse()

	// Debug or not Debug

	if *debugMode {
		Debug = true
	}

	// If no data file name to decrypt => we stop here

	if len(flag.Args()) == 0 {
		// we need at least a data file name to decrypt
		fmt.Println("We need at least a data file name to decrypt :(")
		os.Exit(1)
	}

	// Filenames (exported keys, datafile)

	var dataFileName = flag.Arg(0)
	var bcFileName = DEFAULT_BCKEY_FILEPATH
	if *argKeyFileName != "" {
		bcFileName = *argKeyFileName
	}

	//
	// Let's rock'n'roll
	//

	color.FgRed.Println("\nBoxcryptor decryptor")
	res.Line()
	res.PrintParameter("File to decrypt", dataFileName)

	// ---------------------------------
	//  Does the file to decrypt exists in the FS?
	// ---------------------------------

	fmt.Print("File ", dataFileName)
	extension := path.Ext(dataFileName)
	var decryptedFileName string

	if res.FileExists(dataFileName) {
		fmt.Print(" is present")
		if extension == ".bc" {
			fmt.Println(" with a good extension (.bc).")
			decryptedFileName = dataFileName[:len(dataFileName)-3]
			res.PrintParameter("File to write", decryptedFileName)
		} else {
			fmt.Printf(" but with inappropriate file extension (%s).\n", extension)
			os.Exit(1)
		}
	} else {
		fmt.Println(" is NOT present (error in filename?).")
		os.Exit(1)
	}
	res.Line()

	// ---------------------------------
	// First of all: read the .bckey file, containing all needed crypto information
	// ---------------------------------

	res.PrintParameter("Export key file used", bcFileName)
	var bc *exportkey.File
	bc = exportkey.Read(bcFileName, Debug)

	// ---------------------------------
	// Get the password. Reminder: Boxcryptor is a zero-knowledge solution so we need
	// the password to get all the cryptographic information
	//
	// Not needed if provided in the command line (--pwd)
	// ---------------------------------

	username := bc.Username + " (" + bc.FirstName + " " + bc.LastName + ")"
	password := *argPassword

	if *argPassword == "" {
		password = res.Credentials()
	}

	if Debug {
		fmt.Printf("Username is %s, password: %s\n", username, password)
	}

	// ---------------------------------
	//
	//  Constructing crypto elements
	//
	// ---------------------------------

	//
	// Public key (in fact not used for decryption)
	// ===============
	//
	// RSA-4096 key is in DER format
	// 738 base64 (6-bits) = 123 bytes
	//
	_, errPK := x509.ParsePKIXPublicKey(bc.PublicKeyBytes)
	// Should be: publicKey, errPK := x509.ParsePKIXPublicKey(bc.PublicKeyBytes)
	if errPK != nil {
		fmt.Println("Bad Public Key in the export key file.")
	} else {
		res.PrintParameter("Public Key importation", "OK")
		if Debug {
			res.PrintParameter("Public Key", base64.StdEncoding.EncodeToString(bc.PublicKeyBytes))
		}
	}

	//
	// Password key
	// =================
	//
	// --> Password key: A "double" AES encryption key derived from your password. The key is created using the key stretching and
	//     strengthening function PBKDF2 with HMACSHA512, 10.000 iterations and a 24 byte salt.
	//
	//     The password key is used to encrypt the user's private key.
	//
	//     The salt is base64-encode
	//     The password should be unicode (UTF8) encoded
	//

	//
	// Derivation of the user's password
	//
	passwordKey := pbkdf2.Key([]byte(password), bc.SaltBytes, bc.KdfIterations, 64, sha512.New)
	res.PrintParameter("Password key creation", "OK")
	if Debug {
		res.PrintParameter("Password Key", base64.StdEncoding.EncodeToString(passwordKey))
	}

	/*
	   The result of the derivation function is 64 bytes long.

	       - The first 32 bytes (256 buts) is used as an AES key
	       - The second part is used as a hmac key
	*/
	cryptoKey := passwordKey[0:32]
	hmacKey := passwordKey[32:]
	if Debug {
		res.PrintParameter("CryptoKey", base64.StdEncoding.EncodeToString(cryptoKey))
		res.PrintParameter("HMAC Key", base64.StdEncoding.EncodeToString(hmacKey))
	}

	//
	// Private key
	// ===========
	//
	// --> Private RSA key (encrypted with the user's password)
	//     The user’s private key is already encrypted with the user’s password on the client (user device).
	//     The encrypted private key is then encrypted again with the database encryption key.
	//
	//     The encrypted private key is base64-encoded, and includes:
	//
	//       . bytes 0->15   : Initialization Vector
	//       . bytes 16->47  : Hmac Hash
	//       . from byte 48  : Private encrypted key itself
	//

	givenHmacHash := bc.EncryptedPrivateKeyBytes[16:48]
	encryptedPrivateKeyBytes := bc.EncryptedPrivateKeyBytes[48:]

	//
	// HMAC verification. The given HMAC should be the HMAC of the private key
	//

	hmacHelper := hmac.New(sha256.New, hmacKey)
	hmacHelper.Write(encryptedPrivateKeyBytes)
	calculatedHMAC := hmacHelper.Sum(nil)

	if hmac.Equal(calculatedHMAC, givenHmacHash) {

		res.PrintParameter("HMAC verification", "OK")

	} else {

		res.PrintBytes("Expected HMAC", givenHmacHash)
		res.PrintBytes("Calculated HMAC", calculatedHMAC)
		color.FgRed.Println("Error in HMAC validation (for Private Key)")
		os.Exit(1)

	}

	//
	// Get the init vector
	//

	initVector := bc.EncryptedPrivateKeyBytes[0:16]
	res.PrintBytes("Init vector", initVector)

	//
	// Now we have everything we need to decrypt the private key (which is in encryptedPrivateKeyBytes)
	//

	c, err := aes.NewCipher(cryptoKey)
	if err != nil {
		fmt.Println(err)
	}

	res.PrintParameter("Private Key length : ", strconv.Itoa(len(encryptedPrivateKeyBytes)))

	ecb := cipher.NewCBCDecrypter(c, initVector)
	decrypted := make([]byte, len(encryptedPrivateKeyBytes))
	ecb.CryptBlocks(decrypted, encryptedPrivateKeyBytes)
	privateKey := res.PKCS5Trimming(decrypted)
	// ---------------> res.PrintBytes("PKPKPKPKPKPKPKPK", privateKey)
	res.PrintParameter("Private Key decryption ", "OK")

	//
	// Read the data file (encrypted, with header) and display some datas
	//

	f := datafile.Read(dataFileName, Debug)
	res.Line()
	res.PrintParameter("Datafile ID", f.FileID)
	res.PrintParameter("Datafile Type", f.FileType)
	res.PrintParameter("Datafile Size", strconv.Itoa(f.FileSize))
	res.Line()
	res.PrintParameter("Datafile Header Version", f.Version)
	res.PrintParameter("Datafile Header Core Length", strconv.Itoa(f.HeaderCoreLength))
	res.PrintParameter("Datafile Header Padding Length", strconv.Itoa(f.HeaderPaddingLength))
	res.PrintParameter("Datafile Cipher Padding Length", strconv.Itoa(f.CipherPaddingLength))
	res.PrintBytes("Datafile Encrypted Content Hash", f.HashCtrl)
	res.Line()
	res.PrintParameter("Datafile Cipher Algo", f.CipherAlgo)
	res.PrintParameter("Datafile Cipher Mode", f.CipherMode)
	res.PrintParameter("Datafile Padding Mode", f.CipherPaddingMode)
	res.PrintParameter("Datafile Cipher Mode", f.CipherMode)
	res.PrintParameter("Datafile Key Size", strconv.Itoa(f.CipherKeysize))
	res.PrintParameter("Datafile Block Size", strconv.Itoa(f.CipherBlocksize))
	res.PrintBytes("Datafile Init Vector", f.CipherInitVector)
	res.Line()

	offset := 48 + f.HeaderCoreLength + f.HeaderPaddingLength
	encryptedDataLength := f.FileSize - offset - f.CipherPaddingLength
	nbBlocks := encryptedDataLength / f.CipherBlocksize
	if (encryptedDataLength % f.CipherBlocksize) != 0 {
		nbBlocks += 1
	}
	res.PrintParameter("Encrypted data length", strconv.Itoa(encryptedDataLength))
	res.PrintParameter("Offset", strconv.Itoa(offset))
	res.PrintParameter("Number of blocks to decrypt", strconv.Itoa(nbBlocks))
	res.Line()

	//
	// --> File key: AES encryption key used to encrypt or decrypt a file. Every file has its own unique and random file key.
	//
	// file_aes_key_encrypted is the AES key encrypted with the user's public key
	//

	rng := rand.Reader
	d, _ := base64.StdEncoding.DecodeString(string(privateKey))
	rsaPrivateKey, err2 := x509.ParsePKCS1PrivateKey([]byte(d))
	if err2 != nil {
		color.FgRed.Println("(2)===> ", err2)
		os.Exit(1)
	}
	AESKeyData, _ := rsa.DecryptOAEP(sha1.New(), rng, rsaPrivateKey, f.EncryptedKey, nil)
	AESCryptoKey := AESKeyData[32:64]

	// -----------------------------------------------------------------
	//
	//  Data file decryption
	//
	// -----------------------------------------------------------------

	//
	// Decrypt the encrypted file key using the user’s private key. Decrypt the encrypted data using the file key.
	//
	//      - Algo AES with a key length of 256 bits,
	//      - Mode CBC (Cipher Block Chaining)
	//      - Padding PKCS7
	//

	fmt.Println("Start decrypting...")

	// Execution time, for information
	t0 := time.Now()

	// Do it now

	// File in (read, encrypted)
	fileIn, errIn := os.Open(dataFileName)
	res.CheckErr(errIn)
	r := bufio.NewReader(fileIn)

	// File out (write, unencrypted)
	fileOut, errOut := os.OpenFile(decryptedFileName, os.O_CREATE, f.OsFileMode)
	res.CheckErr(errOut)
	w := bufio.NewWriter(fileOut)

	// At end end, we close the files
	defer fileIn.Close()
	defer fileOut.Close()

	// Read the 1st block (header), not used here
	buffileIn := make([]byte, offset)
	r.Read(buffileIn)

	// Now read the blocks
	blockIV := make([]byte, len(f.CipherInitVector))
	block, errC := aes.NewCipher(AESCryptoKey)

	if errC == nil {

		for i := 1; i < nbBlocks+1; i++ {

			// Prepare bytes blocks
			buffileIn := make([]byte, f.CipherBlocksize)
			buffileOut := make([]byte, f.CipherBlocksize)
			r.Read(buffileIn)

			// Compute block IV, derived from IV
			blockIV = res.ComputeBlockIV(f.CipherInitVector, i-1, AESCryptoKey)
			mode := cipher.NewCBCDecrypter(block, blockIV)
			mode.CryptBlocks(buffileOut, buffileIn)

			if i == nbBlocks {

				// Exception: the last block may have smaller size
				lastBlockLength := encryptedDataLength - (nbBlocks-1)*f.CipherBlocksize
				fmt.Println("Last block size is", lastBlockLength)
				lastBlockBuff := make([]byte, lastBlockLength)
				copy(lastBlockBuff, buffileOut[:lastBlockLength])
				w.Write(lastBlockBuff)

			} else {

				// Normal block (block size = cipher block size)
				w.Write(buffileOut)

			}

			// Progression
			if i%5000 == 0 {
				fmt.Println(i, "/", nbBlocks)
			}
		}
		w.Flush()

	} else {

		fmt.Println("Error during file decrypting: unable to instantiate deciphering engine.")
		fmt.Println(errC)
		os.Exit(1)

	}

	// End of decryption
	t1 := time.Now()
	elapsed := t1.Sub(t0)
	fmt.Println("End of processing")
	fmt.Printf("%v blocks decrypted in %v\n", nbBlocks, elapsed.String())

}
