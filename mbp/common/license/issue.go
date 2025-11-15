package license

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mlkmbp/mbp/common"
	"strings"
)

type envelope struct {
	V     int    `json:"v"`
	Algo  string `json:"algo"`            // "ed25519" 或 "ed25519+aesgcm"
	Enc   string `json:"enc,omitempty"`   // base64url(nonce|ciphertext|tag)（加密时）
	Plain string `json:"plain,omitempty"` // base64url(payloadJSON)（不加密时）
	Sig   string `json:"sig"`             // base64url(Ed25519 签名)
}

// 发行端：对 LicenseCfg 做 Ed25519 签名；可选 AES-GCM(+AAD) 加密。
// sk:   Ed25519 私钥（只在发行端保存）
// aesKey: 可选 16/24/32B；nil/len=0 表示不加密，仅签名
// aad:   可选 AAD（两端一致；不用就传 nil）
//func IssueLicenseEd25519(cfg common.LicenseCfg) (string, error) {
//
//	// 1) 解析 AES-256 key（32B）
//	aesKey, err := ParseAES256Key(common.AESKEY)
//	if err != nil {
//		return "", err
//	}
//
//	// 2) 解析 AAD（任意长度）
//	aad := ParseAAD(common.AAD)
//
//	// 3) 解析 Ed25519 私钥 / 公钥
//	sk, err := ParseEd25519PrivateKey(common.SK) // 支持 32B seed 或 64B 私钥
//	if err != nil {
//		return "", err
//	}
//
//	canon, err := marshalCanonicalPayload(&cfg)
//	if err != nil {
//		return "", err
//	}
//	sig := ed25519.Sign(sk, canon)
//
//	env := envelope{V: 1}
//	if len(aesKey) == 0 {
//		env.Algo = "ed25519"
//		env.Plain = b64e(canon)
//	} else {
//		env.Algo = "ed25519+aesgcm"
//		raw, err := aesGCMEncrypt(aesKey, canon, aad)
//		if err != nil {
//			return "", err
//		}
//		env.Enc = b64e(raw)
//	}
//	env.Sig = b64e(sig)
//
//	j, err := json.Marshal(env)
//	if err != nil {
//		return "", err
//	}
//	return b64e(j), nil // 外层再包一层 base64url，得到单行字符串
//}

// ===== 工具 =====

func aesGCMEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	if n := len(key); n != 16 && n != 24 && n != 32 {
		return nil, errors.New("aes key must be 16/24/32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return append(nonce, ct...), nil
}

func b64e(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// 固定字段顺序的 struct 直接编码；禁用 HTML 转义，移除末尾换行
func marshalCanonicalPayload(p *common.LicenseCfg) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return out, nil
}

// 示例：生成 Ed25519 密钥（生产环境把私钥安全保存）
func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// 生成 32 字节随机密钥（AES-256）
func GenerateAES256Key() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// 方便落盘/配置：返回 Base64URL（无填充）与 Hex 两种表示
func GenerateAES256KeyStrings() (b64url string, hexstr string, err error) {
	key, err := GenerateAES256Key()
	if err != nil {
		return "", "", err
	}
	b64url = base64.RawURLEncoding.EncodeToString(key) // 推荐：短、URL安全
	hexstr = hex.EncodeToString(key)                   // 兼容性强
	return
}

// 解析密钥字符串（支持 base64url/base64/hex），并校验长度=32
func ParseAES256Key(s string) ([]byte, error) {
	try := []func(string) ([]byte, error){
		func(x string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return base64.URLEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return base64.StdEncoding.DecodeString(x) },
		func(x string) ([]byte, error) { return hex.DecodeString(x) },
	}
	var lastErr error
	for _, f := range try {
		if b, err := f(s); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("aes key length must be 32 bytes, got %d", len(b))
			}
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("invalid key format: %v", lastErr)
}

// 解码 base64url/base64/hex 三选一
func decodeFlexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("unsupported encoding for: %q", s[:min(12, len(s))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 公钥：必须 32B
func ParseEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	b, err := decodeFlexible(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// 私钥：支持 32B seed 或 64B 私钥
func ParseEd25519PrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := decodeFlexible(s)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize: // 32
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize: // 64
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("ed25519 private key must be 32-byte seed or 64-byte key, got %d", len(b))
	}
}

// AAD：如果能按上面规则解码就用解码后的；否则就把原字符串当作明文 AAD
func ParseAAD(s string) []byte {
	if b, err := decodeFlexible(s); err == nil {
		return b
	}
	return []byte(s)
}
