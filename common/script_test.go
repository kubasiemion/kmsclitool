package common

import "testing"

const scripttestfile = `{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "83dbcc02d8ccb40e466191a123791e0e"
    },
    "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "r": 1,
      "p": 8,
      "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
    },
    "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
  },
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "version": 3
}`

const scripttestfile2 = `{
    "address" : "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
    "ICAP" : "XE542A5PZHH8PYIZUBEJEO0MFWRAPPIL67",
    "UUID" : "3198bc9c-6672-5ab3-d9954942343ae5b6",
    "passphrase" : "testpassword",
    "secret" : "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
    "derivedKey" : "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd",
    "MAC_Body" : "bb5cc24229e20d8766fd298291bba6bdd172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
    "MAC" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097",
    "Cipher_key" : "fac192ceb5fd772906bea3e118a69e8b",
    "crypto" : {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {
            "iv" : "83dbcc02d8ccb40e466191a123791e0e"
        },
        "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
        "kdf" : "scrypt",
        "kdfparams" : {
            "dklen" : 32,
            "n" : 262144,
            "r" : 1,
            "p" : 8,
            "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
        },
        "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
    },
    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version" : 3
}`

const scriptvector3 = `{"version":3,"id":"14e396d1-85e3-47f4-950b-e31416a36190","crypto":{"ciphertext":"e3278db0d08696d546289f3bfb2e31620870c59332914e2c29b8bb4d756e08c0","cipherparams":{"iv":"90dad49d9c250588e3970ca77895c70a"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"44f8d07605c129539a50073889ed898d","n":1048576,"r":8,"p":1},"mac":"300567f62522195fc93239899d547ee27e0bcfae1d9e664014bec1daa1b62cb6"}}`

func TestScript(t *testing.T) {
	kf := new(Keyfile)
	err := kf.UnmarshalJSON([]byte(scriptvector3))
	if err != nil {
		t.Error(err)
	}
	err = kf.Decrypt([]byte("testpassword"))
	if err != nil {
		t.Error(err)
	}
}
