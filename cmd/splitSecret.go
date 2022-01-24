package cmd

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/google/uuid"
	"github.com/proveniencenft/primesecrets/poly"
	"github.com/spf13/cobra"
)

// splitSecretCmd
var splitSecretCmd = &cobra.Command{
	Use:   "splitSecret --fileptrn filename_pattern -n shares -t theshold -s secret",
	Short: "Split a secret t/n (shamir's scheme)",
	Long:  `Generates n keyfiles storing shares to the secret provided`,
	Run:   splitSecret,
}

func splitSecret(cmd *cobra.Command, args []string) {
	if len(secret) == 0 {
		fmt.Println("No secret to split")
		return
	}

	if len(secret) > 32 {
		fmt.Printf("Too much of a secret (%v bytes), truncating...\n", len(secret))
	}

	_, err := split([]byte(secret), nshares, threshold)
	if err != nil {
		fmt.Println(err)
		return
	}
	uuidbase, err := uuid.NewUUID()
	if err != nil {
		fmt.Println(err)
		return
	}

	ubytes, err := uuidbase.MarshalBinary()
	fmt.Println(err, ubytes)
	uids := make([]uuid.UUID, 4)

	for i := 0; i < 4; i++ {
		uuidbase[0] = byte(i)
		uids[i], _ = uuid.FromBytes(uuidbase[:])
	}
	fmt.Println(uids)

}

func split(secret []byte, n, t int) ([]poly.Share, error) {
	f := &poly.Field{secp256k1.S256().P}
	s := new(big.Int)
	s.SetBytes(secret) // truncate!
	p, _ := f.NewPoly(t, s)
	return p.SplitSecret(n)
}

func recoverSecret(sh []poly.Share) ([]byte, error) {
	i, e := poly.Lagrange(sh)
	if i != nil {
		return i.Bytes(), e
	}
	return nil, e

}

var secret, filenamePat string
var nshares, threshold int

func init() {
	rootCmd.AddCommand(splitSecretCmd)

	splitSecretCmd.Flags().StringVar(&encalg, "encalg", "aes-128-ctr", "--encalg symm-encryption-algo")
	splitSecretCmd.Flags().StringVar(&kdf, "kdf", "scrypt", "--kdf preferredKDF")
	splitSecretCmd.Flags().StringVarP(&filenamePat, "fileptrn", "f", "", "--fileptrn filename_Pattern")
	splitSecretCmd.Flags().StringVarP(&secret, "secret", "s", "", "--secret your_secret")
	splitSecretCmd.Flags().IntVarP(&nshares, "nshares", "n", 2, "--nshares number_of_shares")
	splitSecretCmd.Flags().IntVarP(&threshold, "threshold", "t", 2, "--theshold no_of_shares_needed")
}
