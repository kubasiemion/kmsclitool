# kmsclitool
off-line cli tool for digital key management
```
Yet another tool to manage Ethereum keyfiles, this one written in Go...
...because the only other tools I have been able to find are JS/Python (so interpreted).

Usage:
  kmsclitool [command]

Available Commands:
  adrFromPriv     derive address from a given private key
  changePassword  Changes password of a keyfile
  completion      Generate the autocompletion script for the specified shell
  generateKeyFile Generate a new keyfile
  help            Help about any command
  readKeyFile     Read an Ethereum key file
  recombineSecret Recovers a secret from t/n files (shamir's scheme)
  splitSecret     Split a secret t/n (shamir's scheme)

Flags:
  -h, --help   help for kmsclitool

Use "kmsclitool [command] --help" for more information about a command.
  ```
