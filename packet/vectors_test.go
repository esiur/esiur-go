package packet

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/esiur/esiur-go/data"
)

// Differential test of the packet layer against the real esiur-ts parser and composer (fixture
// shared with esiur-python, tools/gen-packet-vectors.mjs there).

type tduExpect struct {
	Identifier    int `json:"identifier"`
	Index         int `json:"index"`
	TduClass      int `json:"tduClass"`
	Offset        int `json:"offset"`
	PayloadOffset int `json:"payloadOffset"`
	PayloadLength int `json:"payloadLength"`
	TotalLength   int `json:"totalLength"`
}

type expect struct {
	Error          any        `json:"error"`
	Ret            int        `json:"ret"`
	Method         int        `json:"method"`
	Action         int        `json:"action"`
	CallbackID     uint32     `json:"callbackId"`
	HasTdu         bool       `json:"hasTdu"`
	Tdu            *tduExpect `json:"tdu"`
	Command        int        `json:"command"`
	AuthMode       int        `json:"authMode"`
	EncryptionMode int        `json:"encryptionMode"`
}

type parseVector struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Hex    string `json:"hex"`
	Offset int    `json:"offset"`
	Expect expect `json:"expect"`
}

type fixture struct {
	Compose []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Args struct {
			Action         uint8   `json:"action"`
			CallbackID     uint32  `json:"callbackId"`
			Tdu            *string `json:"tdu"`
			AuthMode       uint8   `json:"authMode"`
			EncryptionMode uint8   `json:"encryptionMode"`
			Method         uint8   `json:"method"`
		} `json:"args"`
		Hex string `json:"hex"`
	} `json:"compose"`
	PacketSweep []parseVector `json:"packetSweep"`
	AuthSweep   []parseVector `json:"authSweep"`
	Prefixes    []parseVector `json:"prefixes"`
	Edges       []parseVector `json:"edges"`
}

func load(t *testing.T) fixture {
	raw, err := os.ReadFile("testdata/ts-packet-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func checkTdu(t *testing.T, tdu *data.ParsedTdu, e *tduExpect, base int) {
	t.Helper()
	if e == nil {
		if tdu != nil {
			t.Errorf("unexpected tdu %+v", tdu)
		}
		return
	}
	if tdu == nil {
		t.Fatal("missing tdu")
	}
	if int(tdu.Identifier) != e.Identifier || int(tdu.Index) != e.Index || int(tdu.Class) != e.TduClass ||
		tdu.TduOffset-base != e.Offset || tdu.PayloadOffset-base != e.PayloadOffset ||
		tdu.PayloadLength != e.PayloadLength || tdu.TotalLength != e.TotalLength {
		t.Errorf("tdu %+v, want %+v", tdu, e)
	}
}

func check(t *testing.T, v parseVector) {
	t.Helper()
	b, _ := hex.DecodeString(v.Hex)
	if v.Kind != "packet" {
		checkAuth(t, b, v)
		return
	}
	var pk Packet
	ret, err := pk.Parse(b, v.Offset, len(b), data.DefaultMaximumPayloadLength)
	if v.Expect.Error != nil {
		if !errors.Is(err, data.ErrLimit) {
			t.Errorf("want a limit error, got %d %v", ret, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if ret != v.Expect.Ret {
		t.Fatalf("ret %d, want %d", ret, v.Expect.Ret)
	}
	if ret < 0 {
		if pk != (Packet{}) {
			t.Error("a short buffer must leave the packet untouched")
		}
		return
	}
	if int(pk.Method) != v.Expect.Method || int(pk.Action) != v.Expect.Action ||
		pk.CallbackID != v.Expect.CallbackID || pk.HasTdu() != v.Expect.HasTdu {
		t.Errorf("packet %+v, want %+v", pk, v.Expect)
	}
	checkTdu(t, pk.Tdu, v.Expect.Tdu, v.Offset)
}

func checkAuth(t *testing.T, b []byte, v parseVector) {
	t.Helper()
	var pk AuthPacket
	ret, err := pk.Parse(b, v.Offset, len(b), data.DefaultMaximumPayloadLength)
	if v.Expect.Error != nil {
		if !errors.Is(err, data.ErrLimit) {
			t.Errorf("want a limit error, got %d %v", ret, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if ret != v.Expect.Ret {
		t.Fatalf("ret %d, want %d", ret, v.Expect.Ret)
	}
	if ret < 0 {
		if pk != (AuthPacket{}) {
			t.Error("a short buffer must leave the packet untouched")
		}
		return
	}
	if int(pk.Command) != v.Expect.Command || pk.HasTdu() != v.Expect.HasTdu {
		t.Errorf("auth packet %+v, want %+v", pk, v.Expect)
	}
	if pk.Command == AuthInitialize {
		if int(pk.AuthMode) != v.Expect.AuthMode || int(pk.EncryptionMode) != v.Expect.EncryptionMode {
			t.Errorf("modes %+v, want %+v", pk, v.Expect)
		}
	} else if int(pk.Method) != v.Expect.Method {
		t.Errorf("method %x, want %x", pk.Method, v.Expect.Method)
	}
	checkTdu(t, pk.Tdu, v.Expect.Tdu, v.Offset)
}

func TestComposeMatchesEsiurTs(t *testing.T) {
	for _, v := range load(t).Compose {
		t.Run(v.Name, func(t *testing.T) {
			var tdu []byte
			if v.Args.Tdu != nil {
				tdu, _ = hex.DecodeString(*v.Args.Tdu)
				if tdu == nil {
					tdu = []byte{}
				}
			}
			var got []byte
			var err error
			switch v.Kind {
			case "request":
				got, err = ComposeRequest(v.Args.Action, v.Args.CallbackID, tdu)
			case "reply":
				got, err = ComposeReply(v.Args.Action, v.Args.CallbackID, tdu)
			case "notification":
				got, err = ComposeNotification(v.Args.Action, tdu)
			case "auth_initialize":
				got, err = ComposeInitialize(AuthenticationMode(v.Args.AuthMode), EncryptionMode(v.Args.EncryptionMode), tdu)
			case "auth_method":
				got, err = ComposeMethod(AuthMethod(v.Args.Method), tdu)
			default:
				t.Fatalf("unknown kind %s", v.Kind)
			}
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.Hex {
				t.Errorf("got %x want %s", got, v.Hex)
			}
		})
	}
}

func TestEveryHeaderByteParsesLikeEsiurTs(t *testing.T) {
	f := load(t)
	for _, v := range f.PacketSweep {
		v.Kind = "packet"
		check(t, v)
	}
	for _, v := range f.AuthSweep {
		v.Kind = "auth"
		check(t, v)
	}
}

func TestEveryTruncationReportsTheSameShortfall(t *testing.T) {
	for _, v := range load(t).Prefixes {
		check(t, v)
	}
}

func TestEdgeCasesMatchEsiurTs(t *testing.T) {
	for _, v := range load(t).Edges {
		t.Run(v.Name, func(t *testing.T) { check(t, v) })
	}
}
