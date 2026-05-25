package main

import "testing"

func TestNormalizeContentPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "   ", want: ""},
		{in: ".", want: ""},
		{in: "/src/", want: "src"},
		{in: "///a/b///", want: "a/b"},
	}

	for _, tt := range tests {
		got := normalizeContentPath(tt.in)
		if got != tt.want {
			t.Fatalf("normalizeContentPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEncodePathForURL(t *testing.T) {
	in := "folder/a b/#c?.txt"
	want := "folder/a%20b/%23c%3F.txt"
	got := encodePathForURL(in)
	if got != want {
		t.Fatalf("encodePathForURL(%q) = %q, want %q", in, got, want)
	}
}
