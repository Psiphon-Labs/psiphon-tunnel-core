package sss

import (
	"bytes"
	"testing"
)

var (
	p  = []byte{1, 0, 2, 3}
	p2 = []byte{70, 32, 6}
)

func TestDegree(t *testing.T) {
	if v, want := degree(p), 3; v != want {
		t.Errorf("Was %v, but expected %v", v, want)
	}
}

func TestEval(t *testing.T) {
	if v, want := eval(p, 2), byte(17); v != want {
		t.Errorf("Was %v, but expected %v", v, want)
	}
}

func TestGenerate(t *testing.T) {
	b := []byte{1, 2, 3}

	expected := []byte{10, 1, 2, 3}
	actual, err := generate(3, 10, bytes.NewReader(b))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Was %v, but expected %v", actual, expected)
	}
}

func TestGenerateEOF(t *testing.T) {
	b := []byte{1}

	p, err := generate(3, 10, bytes.NewReader(b))
	if p != nil {
		t.Errorf("Was %v, but expected an error", p)
	}

	if err == nil {
		t.Error("No error returned")
	}
}

func TestGeneratePolyEOFFullSize(t *testing.T) {
	b := []byte{1, 2, 0, 0, 0, 0}

	p, err := generate(3, 10, bytes.NewReader(b))
	if p != nil {
		t.Errorf("Was %v, but xpected an error", p)
	}

	if err == nil {
		t.Error("No error returned")
	}
}

func TestGenerateFullSize(t *testing.T) {
	b := []byte{1, 2, 0, 4}

	expected := []byte{10, 1, 2, 4}
	actual, err := generate(3, 10, bytes.NewReader(b))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Was %v but expected %v", actual, expected)
	}
}

func TestInterpolate(t *testing.T) {
	in := []pair{
		{x: 1, y: 1},
		{x: 2, y: 2},
		{x: 3, y: 3},
	}

	if v, want := interpolate(in, 0), byte(0); v != want {
		t.Errorf("Was %v, but expected %v", v, want)
	}
}
