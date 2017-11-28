package sss

import (
	"testing"
)

func TestMul(t *testing.T) {
	if v, want := mul(90, 21), byte(254); v != want {
		t.Errorf("Was %v, but expected %v", v, want)
	}
}

func TestDiv(t *testing.T) {
	if v, want := div(90, 21), byte(189); v != want {
		t.Errorf("Was %v, but expected %v", v, want)
	}
}

func TestDivZero(t *testing.T) {
	if v, want := div(0, 2), byte(0); v != want {
		t.Errorf("Was %v, but expected %v", v, want)
	}
}

func TestDivByZero(t *testing.T) {
	defer func() {
		m := recover()
		if m != "div by zero" {
			t.Error(m)
		}
	}()

	div(2, 0)
	t.Error("Shouldn't have been able to divide those")
}
