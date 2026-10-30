// Package fresh keeps a RATS Relying Party's side of freshness (draft-novak-lamps-tacra-est): it mints
// present-nonce Handles and accepts each once, for the Target and Credential Type it was issued for and within its
// lifetime; it holds the current epoch marker for present-epoch and absent-epoch; and it checks an absent-timestamp
// element against max_age and the clock skew it tolerates.
package fresh

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Kind is a Freshness Kind.
type Kind string

// The five Freshness Kinds.
const (
	PresentNonce    Kind = "present-nonce"
	PresentEpoch    Kind = "present-epoch"
	AbsentEpoch     Kind = "absent-epoch"
	AbsentTimestamp Kind = "absent-timestamp"
	AbsentNone      Kind = "absent-none"
)

// Valid reports whether k is one of the five kinds.
func (k Kind) Valid() bool {
	switch k {
	case PresentNonce, PresentEpoch, AbsentEpoch, AbsentTimestamp, AbsentNone:
		return true
	}
	return false
}

// Refusals. Both are answered 400 (the draft, Error Handling); on Stale the Attester retries attest-initiate.
var (
	ErrStale     = errors.New("fresh: freshness element is not valid now")
	ErrMalformed = errors.New("fresh: freshness element does not fit the Freshness Kind")
)

type issued struct {
	target, credentialType string
	expires                time.Time
}

// Store is one RRP's freshness state. The zero value is not usable; use New.
type Store struct {
	mu     sync.Mutex
	now    func() time.Time
	nonces map[string]issued
	epoch  []byte
}

// New returns a Store with a fresh epoch marker; now is the RRP's clock (time.Now when nil).
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	s := &Store{now: now, nonces: map[string]issued{}}
	s.RotateEpoch()
	return s
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// MintNonce returns a new 32-octet present-nonce Handle for target and credentialType, valid for ttl.
func (s *Store) MintNonce(target, credentialType string, ttl time.Duration) []byte {
	h := random(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.nonces { // forget expired Handles
		if now.After(v.expires) {
			delete(s.nonces, k)
		}
	}
	s.nonces[hex.EncodeToString(h)] = issued{target, credentialType, now.Add(ttl)}
	return h
}

// Epoch returns the current epoch marker.
func (s *Store) Epoch() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.epoch...)
}

// SetEpoch installs an epoch marker distributed out of band, shared by the deployment's RRPs.
func (s *Store) SetEpoch(marker []byte) error {
	if n := len(marker); n < 8 || n > 64 {
		return fmt.Errorf("%w: an epoch marker is 8 to 64 octets, got %d", ErrMalformed, n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch = append([]byte(nil), marker...)
	return nil
}

// RotateEpoch starts a new epoch; markers of earlier epochs are refused from then on.
func (s *Store) RotateEpoch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch = random(32)
}

// Accept checks the freshness element of a second-leg request of the given kind, for target and credentialType, and
// consumes a present-nonce Handle. maxAge and skew apply to absent-timestamp.
func (s *Store) Accept(kind Kind, element []byte, target, credentialType string, maxAge, skew time.Duration) error {
	switch kind {
	case PresentNonce:
		if n := len(element); n < 8 || n > 64 {
			return fmt.Errorf("%w: a Handle is 8 to 64 octets, got %d", ErrMalformed, n)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		key := hex.EncodeToString(element)
		it, ok := s.nonces[key]
		if !ok {
			return fmt.Errorf("%w: unknown or already used Handle", ErrStale)
		}
		delete(s.nonces, key) // single use, whatever the outcome below
		if s.now().After(it.expires) {
			return fmt.Errorf("%w: Handle expired", ErrStale)
		}
		if it.target != target || it.credentialType != credentialType {
			return fmt.Errorf("%w: Handle was issued for another Target or Credential Type", ErrStale)
		}
		return nil
	case PresentEpoch, AbsentEpoch:
		if len(element) == 0 {
			return fmt.Errorf("%w: an epoch marker is required", ErrMalformed)
		}
		if !bytes.Equal(element, s.Epoch()) {
			return fmt.Errorf("%w: the epoch marker is not the current one", ErrStale)
		}
		return nil
	case AbsentTimestamp:
		if len(element) != 8 {
			return fmt.Errorf("%w: absent-timestamp takes 8 octets, got %d", ErrMalformed, len(element))
		}
		ts := time.Unix(int64(binary.BigEndian.Uint64(element)), 0)
		now := s.now()
		if ts.Before(now.Add(-maxAge)) || ts.After(now.Add(skew)) {
			return fmt.Errorf("%w: timestamp %s outside [now-%s, now+%s]", ErrStale, ts.UTC().Format(time.RFC3339), maxAge, skew)
		}
		return nil
	case AbsentNone:
		if len(element) != 0 {
			return fmt.Errorf("%w: absent-none takes no element", ErrMalformed)
		}
		return nil
	}
	return fmt.Errorf("%w: unknown Freshness Kind %q", ErrMalformed, kind)
}
