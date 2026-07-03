package proxy

// ClearIdleConns closes idle connections in the transport pool.
// Called after NEWNYM to force new connections through new circuits.
func (p *HTTPProxy) ClearIdleConns() {
	p.transport.CloseIdleConnections()
}
