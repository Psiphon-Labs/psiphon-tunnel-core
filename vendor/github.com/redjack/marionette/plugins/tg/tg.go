package tg

import (
	"strings"

	"github.com/redjack/marionette"
)

type Grammar struct {
	Name      string
	Templates []string
	Ciphers   []TemplateCipher
}

type TemplateCipher interface {
	Key() string
	Capacity(fsm marionette.FSM) (int, error)
	Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error)
}

var grammars = make(map[string]*Grammar)

// RegisterGrammar adds grammar to the registry.
func RegisterGrammar(grammar *Grammar) {
	grammars[grammar.Name] = grammar
}

func init() {
	RegisterGrammar(&Grammar{
		Name: "http_request_keep_alive",
		Templates: []string{
			"GET http://%%SERVER_LISTEN_IP%%:8080/%%URL%% HTTP/1.1\r\nUser-Agent: marionette 0.1\r\nConnection: keep-alive\r\n\r\n",
		},
		Ciphers: []TemplateCipher{NewRankerCipher("URL", `[a-zA-Z0-9\?\-\.\&]+`, 2048)},
	})

	RegisterGrammar(&Grammar{
		Name: "http_response_keep_alive",
		Templates: []string{
			"HTTP/1.1 200 OK\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: keep-alive\r\n\r\n%%HTTP-RESPONSE-BODY%%",
			"HTTP/1.1 404 Not Found\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: keep-alive\r\n\r\n%%HTTP-RESPONSE-BODY%%",
		},
		Ciphers: []TemplateCipher{
			NewFTECipher("HTTP-RESPONSE-BODY", ".+", 128, false),
			NewHTTPContentLengthCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "http_request_close",
		Templates: []string{
			"GET http://%%SERVER_LISTEN_IP%%:8080/%%URL%% HTTP/1.1\r\nUser-Agent: marionette 0.1\r\nConnection: close\r\n\r\n",
		},
		Ciphers: []TemplateCipher{
			NewRankerCipher("URL", `[a-zA-Z0-9\?\-\.\&]+`, 2048),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "http_response_close",
		Templates: []string{
			"HTTP/1.1 200 OK\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: close\r\n\r\n%%HTTP-RESPONSE-BODY%%",
			"HTTP/1.1 404 Not Found\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: close\r\n\r\n%%HTTP-RESPONSE-BODY%%",
		},
		Ciphers: []TemplateCipher{
			NewFTECipher("HTTP-RESPONSE-BODY", ".+", 128, false),
			NewHTTPContentLengthCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "pop3_message_response",
		Templates: []string{
			"+OK %%CONTENT-LENGTH%% octets\nReturn-Path: sender@example.com\nReceived: from client.example.com ([192.0.2.1])\nFrom: sender@example.com\nSubject: Test message\nTo: recipient@example.com\n\n%%POP3-RESPONSE-BODY%%\n.\n",
		},
		Ciphers: []TemplateCipher{
			NewRankerCipher("POP3-RESPONSE-BODY", `[a-zA-Z0-9]+`, 2048),
			NewPOP3ContentLengthCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "pop3_password",
		Templates: []string{
			"PASS %%PASSWORD%%\n",
		},
		Ciphers: []TemplateCipher{
			NewRankerCipher("PASSWORD", `[a-zA-Z0-9]+`, 256),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "http_request_keep_alive_with_msg_lens",
		Templates: []string{
			"GET http://%%SERVER_LISTEN_IP%%:8080/%%URL%% HTTP/1.1\r\nUser-Agent: marionette 0.1\r\nConnection: keep-alive\r\n\r\n",
		},
		Ciphers: []TemplateCipher{
			NewFTECipher("URL", `[a-zA-Z0-9\?\-\.\&]+`, 2048, true),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "http_response_keep_alive_with_msg_lens",
		Templates: []string{
			"HTTP/1.1 200 OK\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: keep-alive\r\n\r\n%%HTTP-RESPONSE-BODY%%",
			"HTTP/1.1 404 Not Found\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: keep-alive\r\n\r\n%%HTTP-RESPONSE-BODY%%",
		},
		Ciphers: []TemplateCipher{
			NewFTECipher("HTTP-RESPONSE-BODY", `.+`, 2048, true),
			NewHTTPContentLengthCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "http_amazon_request",
		Templates: []string{
			"GET http://%%SERVER_LISTEN_IP%%:8080/%%URL%% HTTP/1.1\r\nUser-Agent: marionette 0.1\r\nConnection: keep-alive\r\n\r\n",
		},
		Ciphers: []TemplateCipher{
			NewRankerCipher("URL", `[a-zA-Z0-9\?\-\.\&]+`, 2048),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "http_amazon_response",
		Templates: []string{
			"HTTP/1.1 200 OK\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: keep-alive\r\n\r\n%%HTTP-RESPONSE-BODY%%",
			"HTTP/1.1 404 Not Found\r\nContent-Length: %%CONTENT-LENGTH%%\r\nConnection: keep-alive\r\n\r\n%%HTTP-RESPONSE-BODY%%",
		},
		Ciphers: []TemplateCipher{
			NewAmazonMsgLensCipher("HTTP-RESPONSE-BODY", `.+`),
			NewHTTPContentLengthCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "ftp_entering_passive",
		Templates: []string{
			"227 Entering Passive Mode (127,0,0,1,%%FTP_PASV_PORT_X%%,%%FTP_PASV_PORT_Y%%).\n",
		},
		Ciphers: []TemplateCipher{
			NewSetFTPPasvXCipher(),
			NewSetFTPPasvYCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "dns_request",
		Templates: []string{
			"%%DNS_TRANSACTION_ID%%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%%DNS_DOMAIN%%\x00\x00\x01\x00\x01",
		},
		Ciphers: []TemplateCipher{
			NewSetDNSTransactionIDCipher(),
			NewSetDNSDomainCipher(),
		},
	})

	RegisterGrammar(&Grammar{
		Name: "dns_response",
		Templates: []string{
			"%%DNS_TRANSACTION_ID%%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00%%DNS_DOMAIN%%\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x02\x00\x04%%DNS_IP%%",
		},
		Ciphers: []TemplateCipher{
			NewSetDNSTransactionIDCipher(),
			NewSetDNSDomainCipher(),
			NewSetDNSIPCipher(),
		},
	})
}

func Parse(name, data string) map[string]string {
	if strings.HasPrefix(name, "http_response") || name == "http_amazon_response" {
		return parseHTTPResponse(data)
	} else if strings.HasPrefix(name, "http_request") || name == "http_amazon_request" {
		return parseHTTPRequest(data)
	} else if strings.HasPrefix(name, "pop3_message_response") {
		return parsePOP3(data)
	} else if strings.HasPrefix(name, "pop3_password") {
		return parsePOP3Password(data)
	} else if strings.HasPrefix(name, "ftp_entering_passive") {
		return parseFTPEnteringPassive(data)
	} else if strings.HasPrefix(name, "dns_request") {
		return parseDNSRequest(data)
	} else if strings.HasPrefix(name, "dns_response") {
		return parseDNSResponse(data)
	}
	return nil
}
