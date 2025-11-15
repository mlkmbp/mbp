package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mlkmbp/mbp/common"
	"strings"
	"time"
)

// 解析 + 验签（Ed25519）+ 可选解密（AES-GCM），返回业务载荷。
//
// licenseB64: 最外层 base64url 的信封字符串
// pk:         Ed25519 公钥（客户端内置）
// aesKey:     algo=ed25519+aesgcm 时必填；不加密则传 nil
// aad:        若发行端使用了 AAD，这里必须一致；否则传 nil
func ParseAndVerifyEd25519(licenseB64 string, pk ed25519.PublicKey, aesKey, aad []byte) (*common.LicenseCfg, error) {
	envBytes, err := b64dFlexible(licenseB64)
	if err != nil {
		return nil, fmt.Errorf("decode envelope b64: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		return nil, fmt.Errorf("parse envelope json: %w", err)
	}
	if env.V != 1 {
		return nil, fmt.Errorf("unsupported envelope version: %d", env.V)
	}

	// 取 payload 原始 JSON 字节
	var canon []byte
	switch env.Algo {
	case "ed25519":
		if env.Plain == "" {
			return nil, errors.New("missing plain")
		}
		b, err := b64dFlexible(env.Plain)
		if err != nil {
			return nil, fmt.Errorf("decode plain: %w", err)
		}
		canon = b

	case "ed25519+aesgcm":
		if env.Enc == "" {
			return nil, errors.New("missing enc")
		}
		raw, err := b64dFlexible(env.Enc)
		if err != nil {
			return nil, fmt.Errorf("decode enc: %w", err)
		}
		b, err := aesGCMDecrypt(raw, aesKey, aad)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		canon = b

	default:
		return nil, fmt.Errorf("unsupported algo: %s", env.Algo)
	}

	// 验签（Ed25519）
	sig, err := b64dFlexible(env.Sig)
	if err != nil {
		return nil, fmt.Errorf("decode sig: %w", err)
	}
	if !ed25519.Verify(pk, canon, sig) {
		return nil, errors.New("ed25519 signature verify failed")
	}

	// 反序列化到业务载荷
	var lp common.LicenseCfg
	if err := json.Unmarshal(canon, &lp); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &lp, nil
}

// ===== 公共最小校验 =====
// 机器码：若 lp.MachineCode == "" 则不校验；否则与传入 machineID 比对。
func BasicValidate(lp *common.LicenseCfg, machineID string, now time.Time) (bool, string) {
	if lp.RunTime.IsZero() || !lp.User {
		return false, "license missing Invalid RunTimeLimit or UserLimit"
	}
	if now.After(lp.RunTime) {
		return false, "license expired"
	}
	if want := strings.TrimSpace(lp.MachineCode); want != "" {
		if have := strings.TrimSpace(machineID); have != "" && !strings.EqualFold(want, have) {
			return false, "license not valid for this machine " + have
		}
	}
	return true, "ok"
}

// 入口封装：Parse → Verify → BasicValidate（返回最终 JSON）
func VerifyLicenseEd25519(licenseB64 string) (bool, string, *common.LicenseCfg) {
	pk, err := ParseEd25519PublicKey(common.PK) // 必须 32B
	if err != nil {
		return false, err.Error(), nil
	}
	aesKey, err := ParseAES256Key(common.AESkye)
	if err != nil {
		return false, err.Error(), nil
	}
	aad := ParseAAD(common.AAD)
	lp, err := ParseAndVerifyEd25519(licenseB64, pk, aesKey, aad)
	if err != nil {
		return false, err.Error(), nil
	}
	id, err := common.StableMachineID()
	if err != nil {
		return false, err.Error(), nil
	}
	ok, msg := BasicValidate(lp, id, time.Now())
	return ok, msg, lp
}

// ===== 工具 =====

func aesGCMDecrypt(raw, key, aad []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("aes key required")
	}
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

	ns := gcm.NonceSize()
	if len(raw) < ns+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, msg := raw[:ns], raw[ns:]
	plain, err := gcm.Open(nil, nonce, msg, aad)
	if err != nil {
		return nil, errors.New("aes-gcm authentication failed")
	}
	return plain, nil
}

func b64dFlexible(s string) ([]byte, error) {
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
	return nil, errors.New("invalid base64")
}
