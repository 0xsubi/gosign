package cmd

import (
	"crypto"
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

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Digitally sign a file with your private key",
	Long:  "Digitally sign a file with your private key",
	Run:   runVerify,
}

func init() {
	verifyCmd.PersistentFlags().StringP("publickey", "k", "", "path to PEM formatted public key file of sender")
	verifyCmd.PersistentFlags().StringP("signature", "s", "", "path to file containing signature")
	viper.BindPFlag("publickey", verifyCmd.PersistentFlags().Lookup("publickey"))
	viper.BindPFlag("signature", verifyCmd.PersistentFlags().Lookup("signature"))
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) {
	publicKeyFilepath := viper.GetString("publickey")
	signatureFilePath := viper.GetString("signature")
	if len(args) != 1 || publicKeyFilepath == "" || signatureFilePath == "" {
		fmt.Printf("Usage: gosign verify <data file> -s <path/to/signature/file> -k <path/to/publicKey>")
		os.Exit(1)
	}

	dataFilepath := args[0]

	if err := verify(dataFilepath, signatureFilePath, publicKeyFilepath); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Verification Successful")
}

func verify(dataFilepath, signatureFilePath, publicKeyFilepath string) error {
	file, err := os.Open(publicKeyFilepath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem decryption
	block, _ := pem.Decode(buf)
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey := publicInterface.(*rsa.PublicKey)

	signedData, _ := ioutil.ReadFile(signatureFilePath)

	// Read the dataFile
	b, err := ioutil.ReadFile(dataFilepath)
	if err != nil {
		return err
	}

	// metadata hash encryption
	mySha := sha256.New()
	mySha.Write(b)
	h := mySha.Sum(nil)

	//Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h, signedData)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil

}
