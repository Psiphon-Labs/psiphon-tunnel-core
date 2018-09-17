package tg

import (
	"math/rand"
	"regexp"
	"strings"

	"github.com/redjack/marionette"
)

type SetDNSTransactionIDCipher struct{}

func NewSetDNSTransactionIDCipher() *SetDNSTransactionIDCipher {
	return &SetDNSTransactionIDCipher{}
}

func (c *SetDNSTransactionIDCipher) Key() string {
	return "DNS_TRANSACTION_ID"
}

func (c *SetDNSTransactionIDCipher) Capacity(fsm marionette.FSM) (int, error) {
	return 0, nil
}

func (c *SetDNSTransactionIDCipher) Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error) {
	var id string
	if v := fsm.Var("dns_transaction_id"); v != nil {
		id = v.(string)
	} else {
		id = string([]rune{rune(rand.Intn(253) + 1), rune(rand.Intn(253) + 1)})
		fsm.SetVar("dns_transaction_id", id)
	}
	return []byte(id), nil
}

func (c *SetDNSTransactionIDCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	fsm.SetVar("dns_transaction_id", string(ciphertext))
	return nil, nil
}

type SetDNSDomainCipher struct{}

func NewSetDNSDomainCipher() *SetDNSDomainCipher {
	return &SetDNSDomainCipher{}
}

func (c *SetDNSDomainCipher) Key() string {
	return "DNS_DOMAIN"
}

func (c *SetDNSDomainCipher) Capacity(fsm marionette.FSM) (int, error) {
	return 0, nil
}

func (c *SetDNSDomainCipher) Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error) {
	var domain string
	if v := fsm.Var("dns_domain"); v != nil {
		domain = v.(string)
	} else {
		available := []rune{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
		tlds := []string{"com", "net", "org"}

		buf := make([]rune, rand.Intn(60)+3+1)
		buf[0] = rune(len(buf) - 1) // name length
		for i := 1; i < len(buf); i++ {
			buf[i] = available[rand.Intn(len(available))]
		}
		buf = append(buf, 3) // tld length
		buf = append(buf, []rune(tlds[rand.Intn(len(tlds))])...)

		domain = string(buf)
		fsm.SetVar("dns_domain", domain)
	}
	return []byte(domain), nil
}

func (c *SetDNSDomainCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	fsm.SetVar("dns_domain", string(ciphertext))
	return nil, nil
}

type SetDNSIPCipher struct{}

func NewSetDNSIPCipher() *SetDNSIPCipher {
	return &SetDNSIPCipher{}
}

func (c *SetDNSIPCipher) Key() string {
	return "DNS_IP"
}

func (c *SetDNSIPCipher) Capacity(fsm marionette.FSM) (int, error) {
	return 0, nil
}

func (c *SetDNSIPCipher) Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error) {
	var ip string
	if v := fsm.Var("dns_ip"); v != nil {
		ip = v.(string)
	} else {
		ip = string([]rune{rune(rand.Intn(253) + 1), rune(rand.Intn(253) + 1), rune(rand.Intn(253) + 1), rune(rand.Intn(253) + 1)})
		fsm.SetVar("dns_ip", ip)
	}
	return []byte(ip), nil
}

func (c *SetDNSIPCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	fsm.SetVar("dns_ip", string(ciphertext))
	return nil, nil
}

func parseDNSRequest(data string) map[string]string {
	if !strings.Contains(data, "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00") {
		return nil
	}

	domain := parseDNSDomain(data, false)
	if domain == "" {
		return nil
	}

	return map[string]string{
		"DNS_TRANSACTION_ID": data[:2],
		"DNS_DOMAIN":         domain,
	}
}

func parseDNSResponse(data string) map[string]string {
	if !strings.Contains(data, "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00") {
		return nil
	}

	domain := parseDNSDomain(data, true)
	if domain == "" {
		return nil
	}

	ip := parseDNSIP(data)
	if ip == "" {
		return nil
	}

	return map[string]string{
		"DNS_TRANSACTION_ID": data[:2],
		"DNS_DOMAIN":         domain,
		"DNS_IP":             ip,
	}
}

func parseDNSDomain(data string, isResponse bool) string {
	delim, splitN := "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 2
	if isResponse {
		delim, splitN = "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 3
	}

	a0 := strings.Split(data, delim)
	if len(a0) != 2 {
		return ""
	}

	a1 := strings.Split(a0[1], "\x00\x01\x00\x01")
	if len(a1) != splitN {
		return ""
	}

	// Check for valid prepended length
	// Remove trailing tld prepended length (1), tld (3) and trailing null (1) = 5
	domain := a1[0]
	if int(domain[0]) != len(domain[1:len(domain)-5]) {
		return ""
	} else if domain[len(domain)-5] != 3 {
		return ""
	}

	// Check for valid TLD
	if !strings.HasSuffix(domain, "com\x00") && !strings.HasSuffix(domain, "net\x00") && !strings.HasSuffix(domain, "org\x00") {
		return ""
	}

	// Check for valid domain characters
	if !domainRegex.MatchString(domain[1 : len(domain)-5]) {
		return ""
	}

	return domain
}

func parseDNSIP(data string) string {
	a := strings.Split(data, "\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x02\x00\x04")
	if len(a) != 2 {
		return ""
	} else if len(a[1]) != 4 {
		return ""
	}
	return a[1]
}

var domainRegex = regexp.MustCompile(`^[\w\d]+$`)
