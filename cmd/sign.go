package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Digitally sign a file with your private key",
	Long:  "Digitally sign a file with your private key",
	Run:   runSign,
}

func init() {
	signCmd.PersistentFlags().StringP("privatekey", "k", "", "path to PEM formatted private key file")
	signCmd.PersistentFlags().StringP("dest", "f", "./signature", "path to where the digital signature is to be stored. Defaults to: ./signature")
	viper.BindPFlag("privatekey", signCmd.PersistentFlags().Lookup("privatekey"))
	viper.BindPFlag("dest", signCmd.PersistentFlags().Lookup("dest"))
	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) {
	if len(args) < 1 || viper.GetString("privatekey") == "" {
		fmt.Printf("Usage: gosign sign <file> -k <path/to/privateKey> -f <path/to/signature/dest>")
		os.Exit(1)
	}

	dataFilepath := args[0]
	privKeyFilepath := viper.GetString("privatekey")
	destFilePath := viper.GetString("dest")

	signedData, err := sign(dataFilepath, privKeyFilepath)
	if err != nil {
		fmt.Println("error in generating digital signature:", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(destFilePath, signedData, 0600)
	if err != nil {
		fmt.Println("error in writing digital signature to file:", err)
		os.Exit(1)
	}

}

func sign(dataFilepath, privKeyFilepath string) ([]byte, error) {
	msg := []byte("")

	// Read the private key from the file
	file, err := os.Open(privKeyFilepath)
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	// Analysis
	block, _ := pem.Decode(buf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return msg, err
	}

	// Read the dataFile
	b, err := ioutil.ReadFile(dataFilepath)
	if err != nil {
		return msg, err
	}
	//Hash encryption
	myHash := sha256.New()
	myHash.Write(b)
	h := myHash.Sum(nil)

	// Sign the hash result
	res, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h)
	if err != nil {
		return msg, err
	}

	defer file.Close()
	return res, nil
}
