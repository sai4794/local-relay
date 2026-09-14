package security

import "net"

// CanonicalizeIP parses a host spelling into its canonical IP, recognizing
// the same non-canonical numeric forms the SSRF layer blocks: dotted
// decimal, decimal/octal/hex integers (2130706433 == 127.0.0.1), short
// forms (127.1), and trailing-dot spellings that net.ParseIP rejects but
// dialers may still interpret. It strips brackets and one trailing dot
// first (normalizeHostKey), so "[::1]" and "127.0.0.1." canonicalize too.
// Returns nil when the host is not any numeric-IP form.
func CanonicalizeIP(host string) net.IP {
	return parseNumericIP(normalizeHostKey(host))
}
