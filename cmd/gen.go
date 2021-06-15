package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	genCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a public private keypair",
		Long:  "Generate a public private keypair",
		Run:   runGen,
	}
)

func init() {
	genCmd.PersistentFlags().StringP("filepath", "f", "./", "path where keypairs will be stored")
	genCmd.PersistentFlags().IntP("bitsize", "b", 2048, "Bit Size of the generated keys")
	viper.BindPFlag("filepath", genCmd.PersistentFlags().Lookup("filepath"))
	viper.BindPFlag("bitsize", genCmd.PersistentFlags().Lookup("bitsize"))
	rootCmd.AddCommand(genCmd)
}

func runGen(cmd *cobra.Command, args []string) {
	bitSize := viper.GetInt("bitsize")
	filePath := viper.GetString("filepath")

	if err := generateRsaKey(filePath, bitSize); err != nil {
		fmt.Println("error while generating keypair:", err)
		os.Exit(1)
	}

}

func generateRsaKey(filePath string, bit int) error {

	if !strings.HasSuffix(filePath, "/") {
		filePath += "/"
	}

	private, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return err
	}
	//x509 private key serialization
	privateStream := x509.MarshalPKCS1PrivateKey(private)
	// Set the private key to the pem structure
	block := pem.Block{
		Type:  "Rsa Private Key",
		Bytes: privateStream,
	}
	//Save the disk
	file, err := os.Create(fmt.Sprintf("%s%s", filePath, "privateKey.pem"))
	if err != nil {
		return err
	}
	//pem encoding
	err = pem.Encode(file, &block)
	if err != nil {
		return err
	}
	//=========public=========
	public := private.PublicKey
	//509 serialization
	publicStream, err := x509.MarshalPKIXPublicKey(&public)
	if err != nil {
		return err
	}
	// public key assignment pem structure
	pubblock := pem.Block{Type: "Rsa Public Key", Bytes: publicStream}
	//Save the disk
	pubfile, err := os.Create(fmt.Sprintf("%s%s", filePath, "publicKey.pem"))
	if err != nil {
		return err
	}
	//pem encoding
	err = pem.Encode(pubfile, &pubblock)
	if err != nil {
		return err
	}
	return nil

}
