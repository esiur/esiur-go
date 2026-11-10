package security

import (
	"bytes"
	"testing"

	"github.com/esiur/esiur-go/packet"
)

func pair(t *testing.T) (*AesGcmCipher, *AesGcmCipher) {
	t.Helper()
	ctx := EncryptionContext{
		Key: bytes.Repeat([]byte{7}, 64), Mode: packet.EncryptWithSessionKey, Protocol: AesGcmName,
		OfferedProtocols: []string{AesGcmName}, AuthenticationMode: packet.AuthDualIdentity,
		AuthenticationProtocol: PasswordProtocol, Domain: "d",
		InitiatorNonce: bytes.Repeat([]byte{1}, 32), ResponderNonce: bytes.Repeat([]byte{2}, 32),
	}
	initiator, err := NewAesGcmCipher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Direction = Responder
	responder, err := NewAesGcmCipher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return initiator, responder
}

func TestAesGcmRecordsRoundTripAndFailClosed(t *testing.T) {
	a, b := pair(t)
	for _, msg := range [][]byte{[]byte("one"), {}, bytes.Repeat([]byte("x"), 70000)} {
		record, err := a.Encrypt(msg)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := b.Decrypt(record)
		if err != nil || !bytes.Equal(plain, msg) {
			t.Fatalf("round trip: %v", err)
		}
	}
	// Replayed, tampered and reordered records are refused.
	r1, _ := a.Encrypt([]byte("r1"))
	r2, _ := a.Encrypt([]byte("r2"))
	if _, err := b.Decrypt(r2); err == nil {
		t.Error("an out-of-order record must fail")
	}
	tampered := append([]byte{}, r1...)
	tampered[len(tampered)-1] ^= 1
	if _, err := b.Decrypt(tampered); err == nil {
		t.Error("a tampered record must fail")
	}
	// Each direction has its own key: a record cannot be reflected back.
	back, _ := b.Encrypt([]byte("hi"))
	if _, err := b.Decrypt(back); err == nil {
		t.Error("a reflected record must fail")
	}
}

func TestPasswordExchangeDerivesTheSameKeyInEveryMode(t *testing.T) {
	server, _ := NewStaticPasswordProvider(map[string]string{"alice": "wonderland"}, map[string]string{"server": "srv"}, "server")
	client, _ := NewStaticPasswordProvider(map[string]string{"server": "srv"}, map[string]string{"alice": "wonderland"}, "alice")
	for _, mode := range []AuthenticationMode{packet.AuthInitializerIdentity, packet.AuthResponderIdentity, packet.AuthDualIdentity} {
		i := client.CreateHandler(AuthContext{Direction: Initiator, Mode: mode})
		r := server.CreateHandler(AuthContext{Direction: Responder, Mode: mode})
		fromI := i.Process(nil)
		var fromR AuthResult
		for step := 0; step < 4 && (fromI.Ruling != AuthSucceeded || fromR.Ruling != AuthSucceeded); step++ {
			if fromR.Ruling != AuthSucceeded {
				if fromR = r.Process(fromI.AuthenticationData); fromR.Ruling == AuthFailed {
					t.Fatalf("mode %d: the responder failed at step %d", mode, step)
				}
			}
			if fromI.Ruling != AuthSucceeded {
				if fromI = i.Process(fromR.AuthenticationData); fromI.Ruling == AuthFailed {
					t.Fatalf("mode %d: the initiator failed at step %d", mode, step)
				}
			}
		}
		if fromI.Ruling != AuthSucceeded || fromR.Ruling != AuthSucceeded || !bytes.Equal(fromI.SessionKey, fromR.SessionKey) || len(fromI.SessionKey) != 64 {
			t.Errorf("mode %d: %v %v", mode, fromI.Ruling, fromR.Ruling)
		}
	}
}
