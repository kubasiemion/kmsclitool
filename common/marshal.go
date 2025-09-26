package common

import (
	"encoding/json"
	"fmt"
)

type AuxInner struct {
	Kdf       string          `json:"kdf"`
	Kdfparams json.RawMessage `json:"kdfparams"`
}
type Aux struct {
	Crypto AuxInner `json:"crypto"`
}

type Wrap Keyfile

func (kf *Keyfile) UnmarshalJSON(data []byte) error {
	var aux Aux
	kf.Version = 99
	wrap := new(Wrap)
	err := json.Unmarshal(data, &aux)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, wrap)
	if err != nil {
		return err
	}
	switch aux.Crypto.Kdf {
	case KdfScrypt:
		scryptparams := new(ScryptParams)
		err := json.Unmarshal(aux.Crypto.Kdfparams, scryptparams)
		if err != nil {
			return err
		}
		wrap.Crypto.Kdfparams = *scryptparams
	case KdfPbkdf2:
		params := new(Pbkdf2Params)
		err := json.Unmarshal(aux.Crypto.Kdfparams, params)
		if err != nil {
			return err
		}
		wrap.Crypto.Kdfparams = *params
	case KdfArgon:
		params := new(ArgonParams)
		err := json.Unmarshal(aux.Crypto.Kdfparams, params)
		if err != nil {
			return err
		}
		wrap.Crypto.Kdfparams = *params
	default:
		return fmt.Errorf("Unsupported kdf scheme: %s", aux.Crypto.Kdf)
	}
	*kf = Keyfile(*wrap)
	return nil

}
