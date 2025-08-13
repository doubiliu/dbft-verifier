package verifier

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	parent := new(block.Header)
	err := parent.UnmarshalJSON([]byte(
		`{
			"hash": "0x580ede92e9c41f6e0edd491d66bfac11cb38749744f725117636b0f600ac0bda",
			"size": 696,
			"version": 0,
			"previousblockhash": "0x92661b2985f7649edad5465f0a3fb19d4289051f43bd242f60660cb49594f19d",
			"merkleroot": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"time": 1628062127819,
			"nonce": "EB9DB8F0012A3C1E",
			"index": 9999,
			"primary": 3,
			"nextconsensus": "NVg7LjGcUSrgxgjX3zEgqaksfMaiS8Z6e1",
			"witnesses": [
				{
					"invocation": "DEDCjfeKUw2coerAOvs12ffgbaXZf0LK3zl9XdBlFWfsqxajuVK41g3hjiZCp2THdrvPD0VWmbz8wSZbNMO+vGP5DECR2m0A8VPtPNEhqg+ozlcnO5+SRDpDuzvZdJuVp4W+we37U9rjaR21GRYOua4gLIyfNhqKxEOI22zquu6rjPDPDEArOI2hfb2CmzK2HhTm4Yt2UBUb0wv6vTB88y+p/famfLq+czL2Y7k97zEPZM7or7bv59/Yx3XDSiB7+PqCBiPTDEDP5qcfswgIxSxBD5JC0gt35NCii3gNKYRBriFTBIJiKXR1sbYiXfYPr6uVmKjJ/NYgfHHGXfR4+F1+ycn8JYZcDEArw7JN1A2iEmq3XCQ5Kvl8uc4VWJ/I0KHD0i/sTW8834/AkrLML+XGY4pmNr4kqENJNULEi4ZOBRQawiOn0LiZ",
					"verification": "FQwhAkhv0VcCxEkKJnAxEqXMHQkj/Wl6M0Br1aHADgATsJpwDCECTHt/tsMQ/M8bozsIJRnYKWTqk4aNZ2Zi1KWa1UjfDn0MIQKq7DhHD2qtAELG6HfP2Ah9Jnaw9Rb93TYoAbm9OTY5ngwhA7IJ/U9TpxcOpERODLCmu2pTwr0BaSaYnPhfmw+6F6cMDCEDuNnVdx2PUTqghpucyNUJhkA7eMbaNokGOMPUalrc4EoMIQLKDidpe5wkj28W4IX9AGHib0TahbWO6DXBEMql7DulVAwhAt9I9g6PPgHEj/QLm38TENeosqGTGIvv4cLj33QOiVCTF0Ge0Nw6"
				}
			],
			"confirmations": 7198226,
			"nextblockhash": "0xd0e2c5cd98d58eeb66c4f8413a798a75e4adaca7f1e8862bf6c3ad9d671ee6f5"
		}`,
	))
	require.NoError(t, err)
	current := new(block.Header)
	err = current.UnmarshalJSON([]byte(
		`{
			"hash": "0xd0e2c5cd98d58eeb66c4f8413a798a75e4adaca7f1e8862bf6c3ad9d671ee6f5",
			"size": 696,
			"version": 0,
			"previousblockhash": "0x580ede92e9c41f6e0edd491d66bfac11cb38749744f725117636b0f600ac0bda",
			"merkleroot": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"time": 1628062144879,
			"nonce": "7796968F9028CE3B",
			"index": 10000,
			"primary": 4,
			"nextconsensus": "NVg7LjGcUSrgxgjX3zEgqaksfMaiS8Z6e1",
			"witnesses": [
				{
					"invocation": "DECY2CGlKOpDLVwHn9j+EqB2OFW1hpuy0SZubdmf6Ggiu+PTKxTU4yTi7HYQEceROv91BYTyKGf0WxVVd9XhZxCtDECO3t113PC6I3456CrmbQRn3rlL7fvv5jDlCRMPpNRO7pH59VsG6yfvpnyqjmfl2D6NtIUcePM9CYBFTDG8WzUfDED7Guu6CT0LDKKEXUuarc9UaCyFOE9/nit7qDwY/YD/A04Nxxy604xbcLrgNjYFBCO0zrLwNaZVMuRGDKwdCGYCDED11qlTYFpj0BGsT4o1eh93Xz1BC1UU65gebQTW9+ZzVQbqYbZi8hEUZChBV9Fhw1R6Wm2ZLZGUjYV5woGLQRYGDEAMmnC3AGvGd2VXcH9+d5eOnNrLOFp9686E62OrxWget7D60ND4fsaCANyT/Gd9eZWbiQbJPHh9SO+lex96ssKZ",
					"verification": "FQwhAkhv0VcCxEkKJnAxEqXMHQkj/Wl6M0Br1aHADgATsJpwDCECTHt/tsMQ/M8bozsIJRnYKWTqk4aNZ2Zi1KWa1UjfDn0MIQKq7DhHD2qtAELG6HfP2Ah9Jnaw9Rb93TYoAbm9OTY5ngwhA7IJ/U9TpxcOpERODLCmu2pTwr0BaSaYnPhfmw+6F6cMDCEDuNnVdx2PUTqghpucyNUJhkA7eMbaNokGOMPUalrc4EoMIQLKDidpe5wkj28W4IX9AGHib0TahbWO6DXBEMql7DulVAwhAt9I9g6PPgHEj/QLm38TENeosqGTGIvv4cLj33QOiVCTF0Ge0Nw6"
				}
			],
			"confirmations": 7198223,
			"nextblockhash": "0xf884452a7b7aea2710e03e02f2e53a232ae986453c81df00fc8d095190177a74"
		}`,
	))
	require.NoError(t, err)
	require.Equal(t, true, VerifyUpdateHeader(parent, current, 860833102))
}

func BenchmarkVerify(b *testing.B) {
	var parent *block.Header
	var current *block.Header
	for i := 0; i < 1000; i++ {
		req := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "getblockheader",
			"params":  []interface{}{i, true},
			"id":      1,
		}
		reqBody, _ := json.Marshal(req)
		resp, err := http.Post("http://seed5.neo.org:10332", "application/json", bytes.NewReader(reqBody))
		require.NoError(b, err)

		defer resp.Body.Close()
		require.NoError(b, err)
		var temp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&temp)
		require.NoError(b, err)

		parent = current
		header, err := json.Marshal(temp["result"])
		require.NoError(b, err)
		current = new(block.Header)
		current.UnmarshalJSON(header)

		if i > 0 {
			require.Equal(b, true, VerifyUpdateHeader(parent, current, 860833102))
		}
	}
}
