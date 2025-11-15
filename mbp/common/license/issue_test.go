package license

import (
	"fmt"
	"mlkmbp/mbp/common"
	"testing"
	"time"
)

func TestExample(t *testing.T) {
	cfg := common.LicenseCfg{
		User:        true,
		Rule:        true,
		Pve:         true,
		RunTime:     time.Now().Add(90 * 24 * time.Hour),
		MachineCode: "", // 为空则不校验机器码
	}
	licStr, err := IssueLicenseEd25519(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(licStr)

	// 5) 验证（验签 + 可选解密 + 最小校验）
	ok, msg, lp := VerifyLicenseEd25519(licStr)
	fmt.Println("[enc] verify:", ok, msg, lp != nil)
	if !ok {
		t.Fatal(msg)
	}
}
