package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"strings"
	"time"
)

// Print() and panic() the message and the error if the error is not nil
func PanicIfErrorMsg(err error, msg string) {
	if err != nil {
		log.Println(msg)
		log.Panic(err)
	}
}

func processArgs() {
	if len(os.Args) == 1 {
		showKeys()
	} else if os.Args[1] == "addKey" {
		addKey()
	} else if os.Args[1] == "changePassword" {
		changePassword()
	} else {
		showHelp()
	}
}

func showHelp() {
	log.Println(" normal usage:")
	log.Println("   ./2fa-wallet")
	log.Println(" it will display each generated pin with its label and the name of file storing your key")
	log.Println(" example : 666666 google 15431.key")
	log.Println("")
	log.Println(" adding a key:")
	log.Println("   ./2fa-wallet addKey szsdfo5157zefd1f5sd4857fgsdf84s4 google")
	log.Println(" it will create an encrypted .key file inside './keys/' with a random name")
	log.Println(" The encryption is based on the password you will enter")
	log.Println("")
	log.Println(" changing the password for every files:")
	log.Println("   ./2fa-wallet changePassword")
	log.Println(" It will ask for your old password, and a new password to decrypt then re-encrypt every files with your new password")
	log.Println("")
	log.Println(" As you can not actually trust any code that try to be secured")
	log.Println(" You can go see the code here: https://github.com/antonin-lebrard/twoAuthConsoleNode")
}

type KeyFileContent struct {
	Filename string
	Salt     []byte
	Salt2    []byte
	Content  []byte
}

func getFiles() []KeyFileContent {
	var keyFiles []KeyFileContent
	files, err := ioutil.ReadDir("./keys")
	PanicIfErrorMsg(err, "cannot read ./keys directory")
	for _, file := range files {
		if !file.IsDir() {
			fileContent, err := ioutil.ReadFile("./keys/" + file.Name())
			PanicIfErrorMsg(err, "cannot read ./keys/"+file.Name()+" file")
			splits := bytes.Split(fileContent, []byte("\n"))
			salt := splits[0]
			salt2 := splits[1]
			keyFiles = append(keyFiles, KeyFileContent{
				Filename: file.Name(),
				Salt:     salt,
				Salt2:    salt2,
				Content:  fileContent[len(salt)+len(salt2)+(len("\n")*2):],
			})
		}
	}
	return keyFiles
}

func getPassword() []byte {
	previousState, err := term.MakeRaw(int(os.Stdin.Fd()))
	PanicIfErrorMsg(err, "cannot configure terminal to not echo characters")
	t := term.NewTerminal(os.Stdin, "")
	password, err := t.ReadPassword("password: ")
	if err != nil {
		log.Println("cannot read password")
		PanicIfErrorMsg(term.Restore(int(os.Stdin.Fd()), previousState), "cannot restore terminal to non-raw mode")
		panic(err)
	}
	PanicIfErrorMsg(term.Restore(int(os.Stdin.Fd()), previousState), "cannot restore terminal to non-raw mode")
	if strings.HasSuffix(password, "\n") {
		password = password[:len(password)-1]
	}
	return []byte(password)
}

func decipherKeys(pass []byte, keyFiles []KeyFileContent, onDecipheredKey func(string, string)) {
	threadDone := make(chan bool, len(keyFiles))
	for _, file := range keyFiles {
		go func(file KeyFileContent) {
			key := pbkdf2.Key(pass, file.Salt, 1000000, 32, crypto.SHA512.New)
			iv := pbkdf2.Key(pass, file.Salt2, 100000, 16, crypto.SHA512.New)

			enc, err := hex.DecodeString(string(file.Content))
			PanicIfErrorMsg(err, "could not decode hex string from file content, is the file content in hex format ?")
			unenc := make([]byte, len(enc))

			aes256Block, err := aes.NewCipher(key)
			PanicIfErrorMsg(err, "could not use crypto lib")

			aes256CTRStream := cipher.NewCTR(aes256Block, iv)
			aes256CTRStream.XORKeyStream(unenc, enc)

			unencString := string(unenc)
			onDecipheredKey(file.Filename, unencString)
			threadDone <- true
		}(file)
	}
	nbThreadDone := 0
	for range threadDone {
		nbThreadDone++
		if nbThreadDone == len(keyFiles) {
			break
		}
	}
}

func getOtpObj(from string) (generatingKey string, label string) {
	return strings.Split(from, " ")[0], from[strings.IndexRune(from, ' ')+1:]
}

func showKeys() {
	filesContent := getFiles()
	pass := getPassword()
	fmt.Println("")
	decipherKeys(pass, filesContent, func(filename, unenc string) {
		fromKey, label := getOtpObj(unenc)
		pin, err := totp.GenerateCode(fromKey, time.Now())
		if err != nil {
			if err.Error() != "Decoding of secret as base32 failed." {
				log.Panic(err)
			}
			tmp := label
			if len(label) > 7 {
				tmp = label[:5] + "..."
			}
			log.Println(filename, tmp, "certainly wrong password, cannot display pin")
		} else {
			log.Println(filename, label, pin)
		}
	})
}

func getGeneratingKey() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("generating key: ")
	key, err := reader.ReadString('\n')
	PanicIfErrorMsg(err, "cannot read stdin")
	return key
}

func getLabel() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("label: ")
	key, err := reader.ReadString('\n')
	PanicIfErrorMsg(err, "cannot read stdin")
	return key
}

func nextUIntRand() uint32 {
	r, err := rand.Int(rand.Reader, big.NewInt(200000))
	PanicIfErrorMsg(err, "cannot generate random filename")
	return uint32(r.Int64())
}
func fileNotExists(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return true
	}
	return false
}
func getNextFileName() string {
	r := nextUIntRand()
	for !fileNotExists(path.Join("keys", string(r)+".key")) {
		r = nextUIntRand()
	}
	return path.Join("keys", string(r)+".key")
}

func cipherIntoFile(pass []byte, generatingKey, label string) string {
	if _, err := totp.GenerateCode(generatingKey, time.Now()); err != nil {
		if err.Error() != "Decoding of secret as base32 failed." {
			log.Panic(err)
		}
		log.Println(`does not support this generating key, you certainly have done a mistake writing it`)
		return ""
	}
	saltRaw := make([]byte, 256)
	salt2Raw := make([]byte, 256)
	_, err := rand.Read(saltRaw)
	PanicIfErrorMsg(err, "error while using crypto lib")
	_, err = rand.Read(salt2Raw)
	PanicIfErrorMsg(err, "error while using crypto lib")
	salt := base64.StdEncoding.EncodeToString(saltRaw)
	salt2 := base64.StdEncoding.EncodeToString(salt2Raw)

	key := pbkdf2.Key(pass, []byte(salt), 1000000, 32, crypto.SHA512.New)
	iv := pbkdf2.Key(pass, []byte(salt2), 100000, 16, crypto.SHA512.New)

	aes256Block, err := aes.NewCipher(key)
	PanicIfErrorMsg(err, "could not use crypto lib")
	aes256CTRStream := cipher.NewCTR(aes256Block, iv)
	toEncrypt := []byte(generatingKey + " " + label)
	encrypted := make([]byte, len(toEncrypt))
	aes256CTRStream.XORKeyStream(encrypted, toEncrypt)
	encryptedHex := hex.EncodeToString(encrypted)

	contentToWrite := []byte(salt + "\n" + salt2 + "\n" + encryptedHex)

	filename := getNextFileName()
	err = ioutil.WriteFile(filename, contentToWrite, os.FileMode(0644))
	PanicIfErrorMsg(err, "cannot write to file")
	return filename
}

func addKey() {
	key := getGeneratingKey()
	label := getLabel()
	pass := getPassword()
	cipherIntoFile(pass, key, label)
}

func changePassword() {
	log.Println("asking for your current password")
	oldPass := getPassword()
	log.Println("\nnow your new password")
	newPass := getPassword()
	filesContent := getFiles()
	log.Println("might take a while to decipher, and re-cipher")
	decipherKeys(oldPass, filesContent, func(filename, unenc string) {
		generatingKey, label := getOtpObj(unenc)
		cipherIntoFile(newPass, generatingKey, label)
	})
	log.Println("\nNow every key has been recreated wth your new password")
	log.Println("The old ones have not been deleted")
	log.Println("so that if anything wrong has happened you can retry the operation")
	log.Println("without having lost every key")
}

func main() {
	processArgs()
}
