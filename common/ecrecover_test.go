package common

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const shash = `0xe68b51f2571f3ae0133122e004bdce9b11c0f6e710eee78b62ea9a862cdf8c89`
const ssign = `0x775c104f68ae8a11c773557be13718cb8f8e3c1db15141a7799907958c9605f01a4a070d76fee4df207b80b302f498d1ee71e4672a0df54784e1eb672d9aa3d01c`

func TestEcrecover(t *testing.T) {
	//Try to recover the address from the signature
	ghash := common.HexToHash(shash)
	gsign, _ := hex.DecodeString(ssign[2:])
	gsign[64] = 1 //&= byte(0x03)
	pub, err := crypto.SigToPub(ghash.Bytes(), gsign)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	addr := crypto.PubkeyToAddress(*pub)
	fmt.Println("Address:", addr.String())
}

const jsn = `[{\"chain-id\":79285688985,\"parent-chain-id\":421614,\"parent-chain-is-arbitrum\":true,\"chain-name\":\"Research L3 Anytrust Chain\",\"chain-config\":{\"homesteadBlock\":0,\"daoForkBlock\":null,\"daoForkSupport\":true,\"eip150Block\":0,\"eip150Hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"eip155Block\":0,\"eip158Block\":0,\"byzantiumBlock\":0,\"constantinopleBlock\":0,\"petersburgBlock\":0,\"istanbulBlock\":0,\"muirGlacierBlock\":0,\"berlinBlock\":0,\"londonBlock\":0,\"clique\":{\"period\":0,\"epoch\":0},\"arbitrum\":{\"EnableArbOS\":true,\"AllowDebugPrecompiles\":false,\"DataAvailabilityCommittee\":true,\"InitialArbOSVersion\":11,\"GenesisBlockNum\":0,\"MaxCodeSize\":24576,\"MaxInitCodeSize\":49152,\"InitialChainOwner\":\"0xa4b000035B4F0C61B9958AE62d69EBE57E217A12\"},\"chainId\":79285688985},\"rollup\":{\"bridge\":\"0xCFb06df63C30deaf73505E73a95bde011ED9c1C8\",\"inbox\":\"0xAC3F23e62961Ff32a9a345D468e28d00BC32FaF2\",\"sequencer-inbox\":\"0xa64b3e37FD1643104f0e74a4D11eb6E4Df60A516\",\"rollup\":\"0xAf95996aB54D66D9FA97D0778f74dB80aD48192E\",\"validator-utils\":\"0xB11EB62DD2B352886A4530A9106fE427844D515f\",\"validator-wallet-creator\":\"0xEb9885B6c0e117D339F47585cC06a2765AaE2E0b\",\"deployed-at\":27085331}}]`

const jsn2 = `"[{\"chain-id\":74088920538,\"parent-chain-id\":421614,\"parent-chain-is-arbitrum\":true,\"chain-name\":\"Research L3 Chain 2.0\",\"chain-config\":{\"homesteadBlock\":0,\"daoForkBlock\":null,\"daoForkSupport\":true,\"eip150Block\":0,\"eip150Hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"eip155Block\":0,\"eip158Block\":0,\"byzantiumBlock\":0,\"constantinopleBlock\":0,\"petersburgBlock\":0,\"istanbulBlock\":0,\"muirGlacierBlock\":0,\"berlinBlock\":0,\"londonBlock\":0,\"clique\":{\"period\":0,\"epoch\":0},\"arbitrum\":{\"EnableArbOS\":true,\"AllowDebugPrecompiles\":false,\"DataAvailabilityCommittee\":false,\"InitialArbOSVersion\":11,\"GenesisBlockNum\":0,\"MaxCodeSize\":24576,\"MaxInitCodeSize\":49152,\"InitialChainOwner\":\"0xa4b000035B4F0C61B9958AE62d69EBE57E217A12\"},\"chainId\":74088920538},\"rollup\":{\"bridge\":\"0x9D3dDaae8D86137a3BF367C089cbEA7054812AE2\",\"inbox\":\"0xD853A49D8532688E4C1dC1Fe6377a1958ef0B3A3\",\"sequencer-inbox\":\"0xBED290563b5a9145dDC0A49083d03101e326B31c\",\"rollup\":\"0x8033d14D15E1F657a738aBe12bF59860F0311488\",\"validator-utils\":\"0xB11EB62DD2B352886A4530A9106fE427844D515f\",\"validator-wallet-creator\":\"0xEb9885B6c0e117D339F47585cC06a2765AaE2E0b\",\"deployed-at\":22018974}}]"`
const jsn3 = `[{\"chain-id\":79285688985,\"parent-chain-id\":421614,\"parent-chain-is-arbitrum\":true,\"chain-name\":\"Research L3 Anytrust Chain\",\"chain-config\":{\"homesteadBlock\":0,\"daoForkBlock\":null,\"daoForkSupport\":true,\"eip150Block\":0,\"eip150Hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"eip155Block\":0,\"eip158Block\":0,\"byzantiumBlock\":0,\"constantinopleBlock\":0,\"petersburgBlock\":0,\"istanbulBlock\":0,\"muirGlacierBlock\":0,\"berlinBlock\":0,\"londonBlock\":0,\"clique\":{\"period\":0,\"epoch\":0},\"arbitrum\":{\"EnableArbOS\":true,\"AllowDebugPrecompiles\":false,\"DataAvailabilityCommittee\":true,\"InitialArbOSVersion\":11,\"GenesisBlockNum\":0,\"MaxCodeSize\":24576,\"MaxInitCodeSize\":49152,\"InitialChainOwner\":\"0xa4b000035B4F0C61B9958AE62d69EBE57E217A12\"},\"chainId\":79285688985},\"rollup\":{\"bridge\":\"0xCFb06df63C30deaf73505E73a95bde011ED9c1C8\",\"inbox\":\"0xAC3F23e62961Ff32a9a345D468e28d00BC32FaF2\",\"sequencer-inbox\":\"0xa64b3e37FD1643104f0e74a4D11eb6E4Df60A516\",\"rollup\":\"0xAf95996aB54D66D9FA97D0778f74dB80aD48192E\",\"validator-wallet-creator\":\"0xEb9885B6c0e117D339F47585cC06a2765AaE2E0b\",\"deployed-at\":27085331}}]`

func TestJN(t *testing.T) {
	unesc := strings.Replace(jsn, "\\", "", -1)
	fmt.Println(unesc)
	mym := map[string]interface{}{}
	err := json.Unmarshal([]byte(unesc), &mym)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
}
