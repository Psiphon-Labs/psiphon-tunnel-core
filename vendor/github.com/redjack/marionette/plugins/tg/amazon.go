package tg

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"

	"github.com/redjack/marionette"
	"github.com/redjack/marionette/fte"
)

type AmazonMsgLensCipher struct {
	key    string
	min    int
	max    int
	target int
	regex  string
}

func NewAmazonMsgLensCipher(key, regex string) *AmazonMsgLensCipher {
	return &AmazonMsgLensCipher{
		key:    key,
		min:    fte.COVERTEXT_HEADER_LEN_CIPHERTTEXT + fte.CTXT_EXPANSION + 32,
		max:    1 << 18,
		target: 0,
		regex:  regex,
	}
}

func (h *AmazonMsgLensCipher) Key() string { return h.key }

func (h *AmazonMsgLensCipher) Capacity(fsm marionette.FSM) (int, error) {
	h.target = amazonMsgLens[rand.Intn(len(amazonMsgLens))]
	if h.target < h.min {
		return 0, nil
	} else if h.target > h.max {
		// We do this to prevent unranking really large slices
		// in practice this is probably bad since it unnaturally caps
		// our message sizes to whatever FTE can support
		h.target = h.max
		return h.max, nil
	}
	n := h.target - fte.COVERTEXT_HEADER_LEN_CIPHERTTEXT
	n -= fte.CTXT_EXPANSION
	n -= 1
	return n, nil
}

func (h *AmazonMsgLensCipher) Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error) {
	if h.target < h.min || h.target > h.max {
		dfa, err := fsm.DFA(h.regex, h.target)
		if err != nil {
			return nil, err
		}

		numWords, err := dfa.NumWordsInSlice(h.target)
		if err != nil {
			return nil, err
		}

		rnd, err := crand.Int(crand.Reader, numWords)
		if err != nil {
			return nil, err
		}

		ret, err := dfa.Unrank(rnd)
		if err != nil {
			return nil, err
		}
		return []byte(ret), nil
	}

	cipher, err := fsm.Cipher(h.regex, h.min)
	if err != nil {
		return nil, err
	}

	ciphertext, err = cipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	} else if len(ciphertext) != h.target {
		return nil, fmt.Errorf("Could not find ciphertext of len %d (%d)", h.target, len(ciphertext))
	}
	return ciphertext, nil
}

func (h *AmazonMsgLensCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < h.min {
		return nil, nil
	}
	cipher, err := fsm.Cipher(h.regex, h.min)
	if err != nil {
		return nil, err
	}
	plaintext, _, err = cipher.Decrypt(ciphertext)
	return plaintext, err
}

// This a weighted list of message lengths.
var amazonMsgLens []int

func init() {
	for _, item := range []struct {
		n      int
		weight int
	}{
		{n: 2049, weight: 1},
		{n: 2052, weight: 2},
		{n: 2054, weight: 2},
		{n: 2057, weight: 3},
		{n: 2058, weight: 2},
		{n: 2059, weight: 1},
		{n: 2065, weight: 1},
		{n: 17429, weight: 1},
		{n: 3098, weight: 1},
		{n: 687, weight: 3},
		{n: 2084, weight: 1},
		{n: 42, weight: 58},
		{n: 43, weight: 107},
		{n: 9260, weight: 1},
		{n: 11309, weight: 1},
		{n: 11829, weight: 1},
		{n: 9271, weight: 1},
		{n: 6154, weight: 1},
		{n: 64, weight: 15},
		{n: 1094, weight: 1},
		{n: 12376, weight: 1},
		{n: 89, weight: 1},
		{n: 10848, weight: 1},
		{n: 5223, weight: 1},
		{n: 69231, weight: 1},
		{n: 7795, weight: 1},
		{n: 2678, weight: 1},
		{n: 8830, weight: 1},
		{n: 29826, weight: 1},
		{n: 16006, weight: 10},
		{n: 8938, weight: 1},
		{n: 17055, weight: 2},
		{n: 87712, weight: 1},
		{n: 23202, weight: 1},
		{n: 7441, weight: 1},
		{n: 17681, weight: 1},
		{n: 12456, weight: 1},
		{n: 41132, weight: 1},
		{n: 25263, weight: 6},
		{n: 689, weight: 1},
		{n: 9916, weight: 1},
		{n: 10101, weight: 2},
		{n: 1730, weight: 1},
		{n: 10948, weight: 1},
		{n: 26826, weight: 1},
		{n: 6357, weight: 1},
		{n: 13021, weight: 2},
		{n: 1246, weight: 4},
		{n: 19683, weight: 1},
		{n: 1765, weight: 1},
		{n: 1767, weight: 1},
		{n: 1768, weight: 1},
		{n: 1769, weight: 4},
		{n: 1770, weight: 6},
		{n: 1771, weight: 3},
		{n: 1772, weight: 2},
		{n: 1773, weight: 4},
		{n: 1774, weight: 4},
		{n: 1775, weight: 1},
		{n: 1776, weight: 1},
		{n: 1779, weight: 1},
		{n: 40696, weight: 1},
		{n: 767, weight: 1},
		{n: 17665, weight: 1},
		{n: 27909, weight: 1},
		{n: 12550, weight: 1},
		{n: 5385, weight: 1},
		{n: 16651, weight: 1},
		{n: 5392, weight: 1},
		{n: 26385, weight: 1},
		{n: 12056, weight: 1},
		{n: 41245, weight: 2},
		{n: 13097, weight: 1},
		{n: 15152, weight: 1},
		{n: 310, weight: 1},
		{n: 40759, weight: 1},
		{n: 9528, weight: 1},
		{n: 8000, weight: 7},
		{n: 471, weight: 1},
		{n: 15180, weight: 1},
		{n: 14158, weight: 3},
		{n: 37719, weight: 2},
		{n: 1895, weight: 1},
		{n: 31082, weight: 1},
		{n: 19824, weight: 1},
		{n: 30956, weight: 1},
		{n: 18807, weight: 1},
		{n: 11095, weight: 1},
		{n: 37756, weight: 2},
		{n: 746, weight: 1},
		{n: 10475, weight: 1},
		{n: 4332, weight: 1},
		{n: 35730, weight: 1},
		{n: 11667, weight: 1},
		{n: 16788, weight: 1},
		{n: 12182, weight: 4},
		{n: 39663, weight: 1},
		{n: 9126, weight: 1},
		{n: 35760, weight: 1},
		{n: 12735, weight: 1},
		{n: 6594, weight: 1},
		{n: 451, weight: 15},
		{n: 19402, weight: 1},
		{n: 463, weight: 3},
		{n: 10193, weight: 1},
		{n: 16853, weight: 6},
		{n: 982, weight: 1},
		{n: 15865, weight: 1},
		{n: 2008, weight: 2},
		{n: 476, weight: 1},
		{n: 13655, weight: 1},
		{n: 10213, weight: 1},
		{n: 10737, weight: 1},
		{n: 15858, weight: 1},
		{n: 2035, weight: 6},
		{n: 2039, weight: 1},
		{n: 2041, weight: 2},
	} {
		for i := 0; i < item.weight; i++ {
			amazonMsgLens = append(amazonMsgLens, item.n)
		}
	}
}
