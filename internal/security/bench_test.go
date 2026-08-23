package security

import (
	"net"
	"testing"
)

// =============================================================================
// SECURITY BENCHMARKS
// =============================================================================

// BenchmarkSSRFBlocker measures SSRF check latency.
func BenchmarkSSRFBlocker(b *testing.B) {
	b.Run("PublicHost", func(b *testing.B) {
		fw := NewFirewall(FirewallConfig{})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fw.AllowHost("example.com")
		}
	})

	b.Run("PrivateHost", func(b *testing.B) {
		fw := NewFirewall(FirewallConfig{})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fw.AllowHost("192.168.1.1")
		}
	})

	b.Run("CachedLookup", func(b *testing.B) {
		fw := NewFirewall(FirewallConfig{})
		// Prime the cache
		fw.AllowHost("localhost")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fw.AllowHost("localhost")
		}
	})
}

// BenchmarkDNSResolution measures DNS lookup latency.
func BenchmarkDNSResolution(b *testing.B) {
	b.Run("NetLookupIP", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			net.LookupIP("localhost")
		}
	})

	b.Run("CachedLookup", func(b *testing.B) {
		fw := NewFirewall(FirewallConfig{})
		// Prime the cache
		fw.AllowHost("localhost")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fw.AllowHost("localhost")
		}
	})
}

// BenchmarkSSRFBlockerBlocked measures blocked host check latency.
func BenchmarkSSRFBlockerBlocked(b *testing.B) {
	fw := NewFirewall(FirewallConfig{})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.AllowHost("10.0.0.1")
	}
}

// BenchmarkSSRFBlockerIPv6 measures IPv6 SSRF check latency.
func BenchmarkSSRFBlockerIPv6(b *testing.B) {
	b.Run("PublicIPv6", func(b *testing.B) {
		fw := NewFirewall(FirewallConfig{})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fw.AllowHost("2001:db8::1")
		}
	})

	b.Run("PrivateIPv6", func(b *testing.B) {
		fw := NewFirewall(FirewallConfig{})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fw.AllowHost("::1")
		}
	})
}

// BenchmarkAddBlockedRange measures range addition cost.
func BenchmarkAddBlockedRange(b *testing.B) {
	fw := NewFirewall(FirewallConfig{})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.AddBlockedRange("192.168.0.0/16")
	}
}

// BenchmarkSSRFBlockerConcurrent measures concurrent SSRF check performance.
func BenchmarkSSRFBlockerConcurrent(b *testing.B) {
	fw := NewFirewall(FirewallConfig{})

	b.Run("ParallelReads", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				fw.AllowHost("example.com")
			}
		})
	})

	b.Run("ParallelMixed", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%2 == 0 {
					fw.AllowHost("example.com")
				} else {
					fw.AllowHost("192.168.1.1")
				}
				i++
			}
		})
	})
}

// BenchmarkSSRFBlockerDNS measures SSRFBlocker DNS resolution with caching.
func BenchmarkSSRFBlockerDNS(b *testing.B) {
	b.Run("UncachedIP", func(b *testing.B) {
		blocker := NewSSRFBlocker([]string{"10.0.0.0/8", "192.168.0.0/16"})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			blocker.IsBlocked("192.168.1.1")
		}
	})

	b.Run("CachedDomain", func(b *testing.B) {
		blocker := NewSSRFBlocker([]string{"10.0.0.0/8", "192.168.0.0/16"})
		// Prime the cache
		blocker.IsBlocked("localhost")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			blocker.IsBlocked("localhost")
		}
	})
}
