package http

import "testing"

func TestParsePath(t *testing.T) {
	paths, id := ParsePath("/", true, true)
	t.Log(paths, id)

	paths, id = ParsePath("/acct/Auth/ss", true, true)
	t.Log(paths, id)
}
