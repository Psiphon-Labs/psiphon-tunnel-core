package tls

// [Psiphon] shouldFragmentClientHello reports whether data is an eligible
// initial-handshake ClientHello.
func (c *Conn) shouldFragmentClientHello(data []byte) bool {
	return c != nil &&
		c.config != nil &&
		c.config.FragmentClientHello != nil &&
		len(c.config.EncryptedClientHelloConfigList) == 0 &&
		c.isClient &&
		c.quic == nil &&
		c.handshakes == 0 &&
		len(data) > 0 &&
		data[0] == typeClientHello
}

// [Psiphon] writeFragmentedClientHello writes data as one or two handshake
// records. Invalid split points fall back to one record.
func (c *Conn) writeFragmentedClientHello(data []byte) (int, error) {
	split := c.config.FragmentClientHello(data)
	if split <= 0 || split >= len(data) {
		n, err := c.writeRecordLocked(recordTypeHandshake, data)
		if err != nil {
			return n, err
		}
		return n, nil
	}

	n, err := c.writeRecordLocked(recordTypeHandshake, data[:split])
	if err != nil {
		return n, err
	}
	n2, err := c.writeRecordLocked(recordTypeHandshake, data[split:])
	if err != nil {
		return n + n2, err
	}
	c.clientHelloFragmented = true

	return len(data), nil
}
