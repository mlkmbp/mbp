package ttls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mlkmbp/mbp/common"
	"strings"
)

// loadTLSConfig 支持：
//   - TLSCert/TLSKey：既可为文件路径，也可为直接 PEM 内容（包含 "-----BEGIN" 即视为 PEM 内容）；
//   - TLSSNIGuard：逗号分隔的域名/通配符（如 "*.example.com,api.example.com"）。
//     为空=禁用；启用则：要求客户端 SNI 必须命中白名单，且证书必须覆盖该 SNI（VerifyHostname）。
func LoadTLSConfig(TLSCert, TLSKey, TLSSNIGuard string) (*tls.Config, error) {
	TLSCert = strings.TrimSpace(TLSCert)
	TLSKey = strings.TrimSpace(TLSKey)

	if TLSCert == "" || TLSKey == "" {
		return nil, errors.New("empty cert/key")
	}

	certPEM, err := common.ReadPEMorFile(TLSCert)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := common.ReadPEMorFile(TLSKey)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse keypair: %w", err)
	}

	// 解析 leaf，便于后续 VerifyHostname
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		if leaf, e := x509.ParseCertificate(cert.Certificate[0]); e == nil {
			cert.Leaf = leaf
		}
	}

	guardList := common.ParseGuardList(TLSSNIGuard) // 为空表示禁用 SNI 校验

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},

		// 在服务端上用 VerifyConnection 拦住不满足 SNI 白名单或证书覆盖的情况
		VerifyConnection: func(cs tls.ConnectionState) error {
			// 未启用 SNI guard：直接放行
			if len(guardList) == 0 {
				return nil
			}
			sni := strings.ToLower(strings.TrimSpace(cs.ServerName))
			if sni == "" {
				return errors.New("sni required")
			}
			// 白名单匹配
			if !common.MatchAnyHostPattern(sni, guardList) {
				return fmt.Errorf("sni not allowed: %s", sni)
			}
			// 证书覆盖校验（SAN/CN）
			leaf := cert.Leaf
			if leaf == nil && len(cert.Certificate) > 0 {
				if l, e := x509.ParseCertificate(cert.Certificate[0]); e == nil {
					leaf = l
				}
			}
			if leaf != nil {
				if err := leaf.VerifyHostname(sni); err != nil {
					return fmt.Errorf("sni not covered by certificate: %w", err)
				}
			}
			return nil
		},
	}

	return cfg, nil
}
