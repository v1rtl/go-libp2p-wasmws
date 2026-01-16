package wasmws

import (
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestParseWebsocketMultiaddrWithSNI(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantHost    string
		wantPort    string
		wantScheme  string
		wantErr     bool
	}{
		{
			name:       "TLS with SNI",
			addr:       "/ip4/49.12.172.37/tcp/32530/tls/sni/49-12-172-37.k2k4r8kibjadgpqco81quegou963p7lbcd9ti0bw8lrcc95ystm6by9d.libp2p.direct/ws",
			wantHost:   "49-12-172-37.k2k4r8kibjadgpqco81quegou963p7lbcd9ti0bw8lrcc95ystm6by9d.libp2p.direct",
			wantPort:   "32530",
			wantScheme: "wss",
			wantErr:    false,
		},
		{
			name:       "TLS without SNI",
			addr:       "/ip4/127.0.0.1/tcp/8080/tls/ws",
			wantHost:   "127.0.0.1",
			wantPort:   "8080",
			wantScheme: "wss",
			wantErr:    false,
		},
		{
			name:       "Plain WebSocket",
			addr:       "/ip4/127.0.0.1/tcp/8080/ws",
			wantHost:   "127.0.0.1",
			wantPort:   "8080",
			wantScheme: "ws",
			wantErr:    false,
		},
		{
			name:       "WSS (legacy)",
			addr:       "/ip4/127.0.0.1/tcp/8080/wss",
			wantHost:   "127.0.0.1",
			wantPort:   "8080",
			wantScheme: "wss",
			wantErr:    false,
		},
		{
			name:       "DNS with SNI",
			addr:       "/dns/example.com/tcp/443/tls/sni/api.example.com/ws",
			wantHost:   "api.example.com",
			wantPort:   "443",
			wantScheme: "wss",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maddr, err := ma.NewMultiaddr(tt.addr)
			if err != nil {
				t.Fatalf("failed to create multiaddr: %v", err)
			}

			url, err := parseMultiaddr(maddr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMultiaddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if url.Hostname() != tt.wantHost {
					t.Errorf("parseMultiaddr() host = %v, want %v", url.Hostname(), tt.wantHost)
				}
				if url.Port() != tt.wantPort {
					t.Errorf("parseMultiaddr() port = %v, want %v", url.Port(), tt.wantPort)
				}
				if url.Scheme != tt.wantScheme {
					t.Errorf("parseMultiaddr() scheme = %v, want %v", url.Scheme, tt.wantScheme)
				}
			}
		})
	}
}

func TestCanDialWithSNI(t *testing.T) {
	transport, err := New(nil, nil)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	tests := []struct {
		name    string
		addr    string
		canDial bool
	}{
		{
			name:    "TLS with SNI",
			addr:    "/ip4/49.12.172.37/tcp/32530/tls/sni/example.com/ws",
			canDial: true,
		},
		{
			name:    "TLS without SNI",
			addr:    "/ip4/127.0.0.1/tcp/8080/tls/ws",
			canDial: true,
		},
		{
			name:    "Plain WebSocket",
			addr:    "/ip4/127.0.0.1/tcp/8080/ws",
			canDial: true,
		},
		{
			name:    "WSS",
			addr:    "/ip4/127.0.0.1/tcp/8080/wss",
			canDial: true,
		},
		{
			name:    "Not a WebSocket address",
			addr:    "/ip4/127.0.0.1/tcp/8080",
			canDial: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maddr, err := ma.NewMultiaddr(tt.addr)
			if err != nil {
				t.Fatalf("failed to create multiaddr: %v", err)
			}

			canDial := transport.CanDial(maddr)
			if canDial != tt.canDial {
				t.Errorf("CanDial() = %v, want %v", canDial, tt.canDial)
			}
		})
	}
}
