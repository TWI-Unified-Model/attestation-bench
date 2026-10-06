package fresh

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func ts(t time.Time) []byte { return binary.BigEndian.AppendUint64(nil, uint64(t.Unix())) }

func TestPresentNonceIsSingleUseAndScoped(t *testing.T) {
	now := time.Unix(1790600000, 0)
	s := New(func() time.Time { return now })
	h := s.MintNonce("https://db.example", "x509", 5*time.Minute)
	if err := s.Accept(PresentNonce, h, "https://db.example", "x509", 0, 0); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := s.Accept(PresentNonce, h, "https://db.example", "x509", 0, 0); !errors.Is(err, ErrStale) {
		t.Fatalf("second use: %v", err)
	}
	h = s.MintNonce("https://db.example", "x509", 5*time.Minute)
	if err := s.Accept(PresentNonce, h, "https://other.example", "x509", 0, 0); !errors.Is(err, ErrStale) {
		t.Fatalf("another Target: %v", err)
	}
	if err := s.Accept(PresentNonce, h, "https://db.example", "x509", 0, 0); !errors.Is(err, ErrStale) {
		t.Fatalf("a Handle refused once is gone: %v", err)
	}
	h = s.MintNonce("https://db.example", "x509", time.Minute)
	now = now.Add(2 * time.Minute)
	if err := s.Accept(PresentNonce, h, "https://db.example", "x509", 0, 0); !errors.Is(err, ErrStale) {
		t.Fatalf("expired: %v", err)
	}
}

func TestEpochs(t *testing.T) {
	s := New(nil)
	e := s.Epoch()
	for _, k := range []Kind{PresentEpoch, AbsentEpoch} {
		if err := s.Accept(k, e, "t", "x509", 0, 0); err != nil {
			t.Fatalf("%s current: %v", k, err)
		}
	}
	s.RotateEpoch()
	if err := s.Accept(AbsentEpoch, e, "t", "x509", 0, 0); !errors.Is(err, ErrStale) {
		t.Fatalf("moved epoch: %v", err)
	}
}

func TestTimestampWindow(t *testing.T) {
	now := time.Unix(1790600000, 0)
	s := New(func() time.Time { return now })
	for _, c := range []struct {
		at   time.Time
		want error
	}{
		{now, nil},
		{now.Add(-59 * time.Second), nil},
		{now.Add(-61 * time.Second), ErrStale},
		{now.Add(4 * time.Second), nil},
		{now.Add(6 * time.Second), ErrStale},
	} {
		if err := s.Accept(AbsentTimestamp, ts(c.at), "t", "x509", time.Minute, 5*time.Second); !errors.Is(err, c.want) {
			t.Fatalf("timestamp %v: %v, want %v", c.at.Sub(now), err, c.want)
		}
	}
	if err := s.Accept(AbsentTimestamp, []byte{1, 2, 3}, "t", "x509", time.Minute, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short timestamp: %v", err)
	}
	if err := s.Accept(AbsentNone, []byte{1}, "t", "x509", 0, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("absent-none with an element: %v", err)
	}
}
