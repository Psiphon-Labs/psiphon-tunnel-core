// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"
)

func TestALPN(t *testing.T) {
	extension := ALPN{
		ProtocolNameList: []string{"http/1.1", "spdy/1", "spdy/2", "spdy/3"},
	}

	raw, err := extension.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	newExtension := ALPN{}
	err = newExtension.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(newExtension.ProtocolNameList, extension.ProtocolNameList) {
		t.Errorf("extensionALPN marshal: got %s expected %s", newExtension.ProtocolNameList, extension.ProtocolNameList)
	}
}

func TestALPNProtocolSelection(t *testing.T) {
	s, err := ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{"spd/1"})
	if err != nil {
		t.Fatal(err)
	}
	if s != "spd/1" {
		t.Errorf("expected: spd/1, got: %v", s)
	}
	_, err = ALPNProtocolSelection([]string{"http/1.1"}, []string{"spd/1"})
	if !errors.Is(err, errALPNNoAppProto) {
		t.Fatal("expected to fail negotiating an application protocol")
	}
	s, err = ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if s != "" {
		t.Errorf("expected not to negotiate a protocol, got: %v", s)
	}
}
