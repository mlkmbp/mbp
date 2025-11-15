package ttime

import (
	"database/sql/driver"
	"fmt"
	"github.com/goccy/go-json"
	"strings"
	"time"
)

const (
	FORMAT_DATE_TIME = "2006-01-02 15:04:05"
	FORMAT_DATE      = "2006-01-02"
)

type TimeFormat struct {
	time.Time
	// 输出格式：只在 JSON 序列化时使用；反序列化时会根据输入自动设置
	// - 日期时间：FORMAT_DATE_TIME
	// - 仅日期：  FORMAT_DATE
	Format string
}

/************** JSON **************/

// 统一按“本地时区”输出，不带时区偏移
func (m TimeFormat) MarshalJSON() ([]byte, error) {
	if m.Format == "" {
		m.Format = FORMAT_DATE_TIME
	}
	if m.Time.IsZero() {
		return json.Marshal("")
	}
	return json.Marshal(m.Time.In(time.Local).Format(m.Format))
}

func (m *TimeFormat) UnmarshalJSON(data []byte) error {
	if m.Format == "" {
		m.Format = FORMAT_DATE_TIME
	}
	s := strings.Trim(string(data), "\"")
	if s == "" || s == "null" {
		*m = TimeFormat{}
		return nil
	}

	// 明确“仅日期”
	if len(s) == len(FORMAT_DATE) && strings.Count(s, ":") == 0 {
		if t, err := time.ParseInLocation(FORMAT_DATE, s, time.Local); err == nil {
			m.Time = t
			m.Format = FORMAT_DATE
			return nil
		}
	}

	// 优先尝试当前既定格式（本地时区解释）
	if t, err := time.ParseInLocation(m.Format, s, time.Local); err == nil {
		m.Time = t
		return nil
	}

	// 多格式兜底（含小数秒与各种时区写法）
	if t, err := parseFlexible(s); err == nil {
		m.Time = t.In(time.Local)   // 统一转本地
		m.Format = FORMAT_DATE_TIME // 反序列化为日期时间时，统一设成日期时间格式
		return nil
	}

	return fmt.Errorf("TimeFormat UnmarshalJSON: cannot parse %q", s)
}

/************** SQL Scanner / Valuer **************/

func (m *TimeFormat) Scan(value interface{}) error {
	if value == nil {
		*m = TimeFormat{}
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		*m = TimeFormat{Time: v.In(time.Local), Format: FORMAT_DATE_TIME}
		return nil
	case string:
		return m.scanFromString(v)
	case []byte:
		return m.scanFromString(string(v))
	default:
		return fmt.Errorf("TimeFormat Scan: unsupported src type %T", value)
	}
}

func (m *TimeFormat) scanFromString(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || s == "0000-00-00 00:00:00" {
		*m = TimeFormat{}
		return nil
	}

	// 仅日期
	if len(s) == len(FORMAT_DATE) && strings.Count(s, ":") == 0 {
		if t, err := time.ParseInLocation(FORMAT_DATE, s, time.Local); err == nil {
			*m = TimeFormat{Time: t, Format: FORMAT_DATE}
			return nil
		}
	}

	// 多格式兜底
	if t, err := parseFlexible(s); err == nil {
		*m = TimeFormat{Time: t.In(time.Local), Format: FORMAT_DATE_TIME}
		return nil
	}
	return fmt.Errorf("TimeFormat Scan: cannot parse %q", s)
}

// 写库统一用“本地时区 + 指定布局”的字符串，避免驱动把 time.Time 编成 RFC3339(+08:00)
func (m TimeFormat) Value() (driver.Value, error) {
	if m.Time.IsZero() {
		return nil, nil // 零值 -> NULL
	}
	layout := m.Format
	if layout == "" {
		layout = FORMAT_DATE_TIME // 默认 "2006-01-02 15:04:05"
	}
	return m.Time.In(time.Local).Format(layout), nil
}

/************** Flexible Parser **************/

// 统一的多格式解析（支持空格/T、可选小数秒、可选时区名/偏移）
// 成功后返回值仍可包含时区信息；调用方负责 .In(time.Local)
func parseFlexible(s string) (time.Time, error) {
	layouts := []string{
		// 无时区（按本地时区解释）
		"2006-01-02 15:04:05.999999999",
		FORMAT_DATE_TIME,

		// 空格 + 时区偏移（±hh:mm / ±hhmm）
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999 -0700",
		"2006-01-02 15:04:05 -0700",

		// 空格 + 时区名
		"2006-01-02 15:04:05.999999999 MST",
		"2006-01-02 15:04:05 MST",

		// RFC3339 / RFC3339Nano（带 T）
		time.RFC3339Nano,
		time.RFC3339,

		// 少见但存在的 Z±hh:mm / Z±hhmm 变体（与空格同时出现）
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05.999999999Z0700",
		"2006-01-02 15:04:05Z0700",

		// 仅日期（最后再试）
		FORMAT_DATE,
	}

	var lastErr error
	for _, layout := range layouts {
		var (
			t   time.Time
			err error
		)
		switch layout {
		// 含时区信息的必须用 Parse（保留偏移）
		case time.RFC3339, time.RFC3339Nano,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02 15:04:05.999999999 -0700",
			"2006-01-02 15:04:05 -0700",
			"2006-01-02 15:04:05.999999999 MST",
			"2006-01-02 15:04:05 MST",
			"2006-01-02 15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05Z07:00",
			"2006-01-02 15:04:05.999999999Z0700",
			"2006-01-02 15:04:05Z0700":
			t, err = time.Parse(layout, s)
		default:
			// 无时区信息：按本地时区解释
			t, err = time.ParseInLocation(layout, s, time.Local)
		}
		if err == nil {
			return t, nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}
