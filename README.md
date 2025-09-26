# kmsclitool
off-line cli tool for digital key management

Manipulatnig in amny ways [Web3 Secret Storage](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage) objects.
This fork is aimed at compatibility with v3 of the standard.
But...
It supports Argon.id kdf, because the clock is ticking.

```
Yet another tool to manage Ethereum keyfiles, this one written in Go...
...because the only other tools I have been able to find are JS/Python (so interpreted).

Functionality:
  Generating, writing and reading standard Ethereum keyfiles, as used by, e.g. , Metamask
  Generating vanity addresses
  Genrating split (Shamir Secret Sharing) keys across multiple files
  Reassembling SSS shares into a public/private key


Usage:
  kmsclitool [command]

Available Commands:
  adrFromPriv       derive address from a given private key
  calculateAddress  Calculate CREATE contract address.
  calculateAddress2 Calculate CREATE2 contract address.
  changePassword    Changes password of a keyfile
  completion        Generate the autocompletion script for the specified shell
  generateKeyFile   Generate a new keyfile (supports vanity address requests)
  help              Help about any command
  readKeyFile       Read an Ethereum key file
  recoverEthKey     Recovers an Eth key from t/n files (shamir's scheme)
  recoverFile       Recovers a secret form t out of n shares  (shamir's scheme)
  recoverKeyFile    Recovers a keyfile form t out of n shares  (shamir's scheme)
  recoverString     Recovers a secret form t out of n shares  (shamir's scheme)
  splitEthKey       Split an Eth key t/n (shamir's scheme)
  splitFile         Split a file t/n (shamir's scheme)
  splitKeyFile      Split a secret t/n (shamir's scheme)
  splitString       Split a secret t/n (shamir's scheme)

Flags:
  -h, --help   help for kmsclitool

Use "kmsclitool [command] --help" for more information about a command.
```
