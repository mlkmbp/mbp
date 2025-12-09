package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/gin-gonic/gin"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type TLSConfig struct {
	Cert string `json:"cert" yaml:"cert"` // 证书 PEM
	Key  string `json:"key"  yaml:"key"`  // 私钥 PEM
}

// Gin 接口：根据 host 生成自签名 TLS 证书，返回给前端
func (s *Server) generateTLS(c *gin.Context) {
	host := strings.TrimSpace(c.Query("host"))
	cfg, err := generateSelfSignedCert(host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, cfg)
}

// ===== 工具函数：生成自签名证书 + 私钥（PEM 字符串）=====

func generateSelfSignedCert(host string) (*TLSConfig, error) {
	// 1. 生成私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// 2. 证书模板
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 有效期 1 年

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	// 3. 自签名
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// 4. 证书 PEM
	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}

	// 5. 私钥 PEM
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyBuf := new(bytes.Buffer)
	if err := pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, err
	}

	return &TLSConfig{
		Cert: certBuf.String(),
		Key:  keyBuf.String(),
	}, nil
}

// 返回给前端用的结构
type TLSConfigResp struct {
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	SniGuard string `json:"sni_guard"`
}

// GET /api/tls/config
func (s *Server) getTLSConfig(c *gin.Context) {
	config := s.App.Cfg.TLSConfig

	resp := TLSConfigResp{
		Cert:     config.Cert,
		Key:      config.Key,
		SniGuard: config.SniGuard,
	}

	c.JSON(http.StatusOK, resp)
}
