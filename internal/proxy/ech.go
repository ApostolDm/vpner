package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"
)

func validateHysteriaECH(raw string) error {
	if raw == "" || strings.Contains(raw, "://") {
		// Xray resolves DNS-based ECH configs at connection time.
		return nil
	}
	config, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return fmt.Errorf("invalid base64 config: %w", err)
	}
	// Hysteria uses native Go TLS for QUIC. Starting its TLS state machine
	// checks ECH before emitting a ClientHello, without opening a socket.
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "ech-check.example",
		NextProtos:                     []string{"h3"},
		EncryptedClientHelloConfigList: config,
	}})
	defer conn.Close()
	conn.SetTransportParameters(nil)
	return conn.Start(context.Background())
}
