package logx

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	glogger "gorm.io/gorm/logger"
	"io"
	"log"
	"mlkmbp/mbp/common"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

/******** Levels ********/
type Level int32

const (
	Trace Level = iota
	Debug
	Info
	Warn
	Error
	Off
)

var globalLevel = int32(Info)

func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return Trace
	case "debug":
		return Debug
	case "warn", "warning":
		return Warn
	case "info":
		return Info
	case "off", "silent":
		return Off
	default:
		return Error
	}
}
func (l Level) String() string {
	switch l {
	case Trace:
		return "trace"
	case Debug:
		return "debug"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Error:
		return "error"
	case Off:
		return "off"
	default:
		return "error"
	}
}
func levelTag(l Level) string {
	switch l {
	case Trace:
		return "[TRACE]"
	case Debug:
		return "[DEBUG]"
	case Info:
		return "[INFO]"
	case Warn:
		return "[WARN]"
	case Error:
		return "[ERROR]"
	default:
		return "[ERROR]"
	}
}
func SetLevel(l Level)        { atomic.StoreInt32(&globalLevel, int32(l)) }
func SetLevelString(s string) { SetLevel(ParseLevel(s)) }
func GetLevel() Level         { return Level(atomic.LoadInt32(&globalLevel)) }
func GetLevelString() string  { return GetLevel().String() }

/******** Dir/Files ********/
func logDir() string {
	if common.IsDesktop() {
		return "log"
	}
	return "/var/log/mlkmbp"
}
func mustOpen(path string) *os.File {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		panic(err)
	}
	return f
}

/******** Writers (global sinks) ********/
var (
	// app
	appInfoW io.Writer = os.Stdout
	appErrW  io.Writer = os.Stderr
	// gin
	ginInfoW io.Writer = os.Stdout
	ginErrW  io.Writer = os.Stderr
	// gorm
	gormInfoW io.Writer = os.Stdout
	gormErrW  io.Writer = os.Stderr

	onceInit atomic.Bool
)

/******** level-gated writer ********/
type levelWriter struct {
	min Level
	dst io.Writer
}

func (w levelWriter) Write(p []byte) (int, error) {
	if GetLevel() <= w.min {
		return w.dst.Write(p)
	}
	return len(p), nil
}

/******** Init ********/
func MustInit() (ginInfo *os.File, ginErr *os.File, gormInfo *os.File, gormErr *os.File, appInfo *os.File, appErr *os.File) {
	if onceInit.Load() {
		return nil, nil, nil, nil, nil, nil
	}
	d := logDir()

	ginInfo = mustOpen(filepath.Join(d, "gin_info.log"))
	ginErr = mustOpen(filepath.Join(d, "gin_error.log"))
	gormInfo = mustOpen(filepath.Join(d, "gorm_info.log"))
	gormErr = mustOpen(filepath.Join(d, "gorm_error.log"))
	appInfo = mustOpen(filepath.Join(d, "info.log"))
	appErr = mustOpen(filepath.Join(d, "error.log"))

	// app: INFO/WARN -> stdout(+file)；ERROR -> stderr(+file)
	appInfoW = io.MultiWriter(os.Stdout, appInfo)
	appErrW = io.MultiWriter(os.Stderr, appErr)

	// gorm: WARN 及以下 -> info；ERROR -> error（受全局级别门控）
	gormInfoW = io.MultiWriter(levelWriter{min: Info, dst: os.Stdout}, gormInfo)
	gormErrW = io.MultiWriter(levelWriter{min: Error, dst: os.Stderr}, gormErr)

	// gin：使用重写器，统一风格；同样只 ERROR 进 stderr
	ginInfoW = io.MultiWriter(levelWriter{min: Info, dst: os.Stdout}, ginInfo)
	ginErrW = io.MultiWriter(levelWriter{min: Error, dst: os.Stderr}, ginErr)
	gr := &ginRewriter{infoW: ginInfoW, errW: ginErrW}
	gin.DefaultWriter = gr
	gin.DefaultErrorWriter = gr

	// —— 关键：覆盖 Gin 的调试打印，获取业务 file:line —— //
	gin.DebugPrintRouteFunc = func(method, path, handler string, nHandlers int) {
		site := findCaller(ginExclude, 1)
		ts := time.Now().Format("2006/01/02 15:04:05.000000")
		msg := fmt.Sprintf("%-6s %-30s --> %s (%d handlers)", method, path, handler, nHandlers)
		line := fmt.Sprintf("%s %s: %s gin - %s\n", ts, site, levelTag(Debug), msg)
		// 直接写 info sink，避免再经 DefaultWriter 二次处理
		_, _ = ginInfoW.Write([]byte(line))
	}
	gin.DebugPrintFunc = func(format string, values ...any) {
		s := fmt.Sprintf(format, values...)
		lvl := Info
		if strings.Contains(s, "[WARNING]") || strings.Contains(s, "[WARN]") {
			lvl = Warn
		} else if strings.Contains(s, "[ERROR]") {
			lvl = Error
		} else if strings.Contains(s, "[GIN-debug]") {
			lvl = Debug
		}
		site := findCaller(ginExclude, 1)
		ts := time.Now().Format("2006/01/02 15:04:05.000000")
		line := fmt.Sprintf("%s %s: %s gin - %s\n", ts, site, levelTag(lvl), stripGinPrefix(s))
		dst := ginInfoW
		if lvl >= Error {
			dst = ginErrW
		}
		_, _ = dst.Write([]byte(line))
	}

	onceInit.Store(true)
	return
}

/******** Component Logger (app own) ********/
type Logger struct {
	level int32
	pfx   atomic.Value
}
type Option func(*Logger)

func WithPrefix(p string) Option { return func(l *Logger) { l.pfx.Store(strings.TrimSpace(p)) } }
func WithLogLevel(lvl Level) Option {
	return func(l *Logger) { atomic.StoreInt32(&l.level, int32(lvl)) }
}

func New(opts ...Option) *Logger {
	l := &Logger{level: -1}
	l.pfx.Store("")
	for _, o := range opts {
		o(l)
	}
	return l
}
func (l *Logger) effLevel() Level {
	if lv := atomic.LoadInt32(&l.level); lv >= 0 {
		return Level(lv)
	}
	return GetLevel()
}
func (l *Logger) SetPrefix(p string)      { l.pfx.Store(strings.TrimSpace(p)) }
func (l *Logger) SetLevel(lv Level)       { atomic.StoreInt32(&l.level, int32(lv)) }
func (l *Logger) shouldLog(at Level) bool { return l.effLevel() <= at && at < Off }
func (l *Logger) dstFor(at Level) io.Writer {
	// Only ERROR -> stderr; WARN and below -> stdout
	if at >= Error {
		return appErrW
	}
	return appInfoW
}
func (l *Logger) site(skip int) string {
	if _, f, ln, ok := runtime.Caller(skip); ok {
		return fmt.Sprintf("%s:%d", filepath.Base(f), ln)
	}
	return "-"
}

// ts file:line: [LEVEL] prefix - message...
func (l *Logger) out(at Level, format string, args ...any) {
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	site := l.site(3)
	pfx := l.pfx.Load().(string)
	var b bytes.Buffer
	if pfx != "" {
		fmt.Fprintf(&b, "%s %s: %s %s - ", ts, site, levelTag(at), pfx)
	} else {
		fmt.Fprintf(&b, "%s %s: %s - ", ts, site, levelTag(at))
	}
	fmt.Fprintf(&b, format, args...)
	b.WriteByte('\n')
	_, _ = l.dstFor(at).Write(b.Bytes())
}
func (l *Logger) Tracef(format string, args ...any) {
	if l.shouldLog(Trace) {
		l.out(Trace, format, args...)
	}
}
func (l *Logger) Debugf(format string, args ...any) {
	if l.shouldLog(Debug) {
		l.out(Debug, format, args...)
	}
}
func (l *Logger) Infof(format string, args ...any) {
	if l.shouldLog(Info) {
		l.out(Info, format, args...)
	}
}
func (l *Logger) Warnf(format string, args ...any) {
	if l.shouldLog(Warn) {
		l.out(Warn, format, args...)
	}
}
func (l *Logger) Errorf(format string, args ...any) {
	if l.shouldLog(Error) {
		l.out(Error, format, args...)
	}
}

/******** std log helpers (boot logs) ********/
func NewStdInfo(dst *os.File) *log.Logger {
	flags := log.LstdFlags | log.Lmicroseconds | log.Lshortfile | log.Lmsgprefix
	return log.New(io.MultiWriter(os.Stdout, dst), "[INFO] ", flags)
}
func NewStdErr(dst *os.File) *log.Logger {
	flags := log.LstdFlags | log.Lmicroseconds | log.Lshortfile | log.Lmsgprefix
	return log.New(io.MultiWriter(os.Stderr, dst), "[ERROR] ", flags)
}

/******** Stack helpers: find first non-library frame ********/
var ginExclude = []string{
	"/gin-gonic/gin", "github.com/gin-gonic/gin", // 覆盖不同构建路径
	"/net/http", "runtime/", "/go/src/net/http", "/logx/",
}
var gormExclude = []string{
	"gorm.io/gorm", "gorm.io/driver", "/database/sql", "runtime/", "/logx/",
}

func findCaller(excludes []string, additionalSkip int) string {
	// skip=0 runtime.Callers; +1 findCaller; +additionalSkip caller
	depth := 64
	pcs := make([]uintptr, depth)
	n := runtime.Callers(2+additionalSkip, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		fr, more := frames.Next()
		if fr.File != "" {
			path := fr.File
			skip := false
			for _, e := range excludes {
				if strings.Contains(path, e) {
					skip = true
					break
				}
			}
			if !skip {
				return fmt.Sprintf("%s:%d", filepath.Base(path), fr.Line)
			}
		}
		if !more {
			break
		}
	}
	return "-"
}

/******** GORM logger: unified style + file:line ********/
type gormSplitLogger struct {
	level glogger.LogLevel
	slow  time.Duration
	infoW io.Writer
	errW  io.Writer
}

func NewGormLogger(level string, slowThreshold time.Duration) glogger.Interface {
	return &gormSplitLogger{
		level: toGormLevel(level),
		slow:  slowThreshold,
		infoW: gormInfoW,
		errW:  gormErrW,
	}
}
func (l *gormSplitLogger) LogMode(level glogger.LogLevel) glogger.Interface {
	cp := *l
	cp.level = level
	return &cp
}

func gormWrite(dst io.Writer, lvl Level, site string, msg string) {
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	for _, line := range strings.Split(strings.TrimRight(msg, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var b bytes.Buffer
		fmt.Fprintf(&b, "%s %s: %s gorm - %s\n", ts, site, levelTag(lvl), line)
		_, _ = dst.Write(b.Bytes())
	}
}
func (l *gormSplitLogger) Info(ctx context.Context, s string, args ...any) {
	if l.level >= glogger.Info {
		site := findCaller(gormExclude, 1)
		gormWrite(l.infoW, Info, site, fmt.Sprintf(s, args...))
	}
}
func (l *gormSplitLogger) Warn(ctx context.Context, s string, args ...any) {
	if l.level >= glogger.Warn {
		site := findCaller(gormExclude, 1)
		gormWrite(l.infoW, Warn, site, fmt.Sprintf(s, args...))
	}
}
func (l *gormSplitLogger) Error(ctx context.Context, s string, args ...any) {
	if l.level >= glogger.Error {
		site := findCaller(gormExclude, 1)
		gormWrite(l.errW, Error, site, fmt.Sprintf(s, args...))
	}
}
func (l *gormSplitLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.level == glogger.Silent {
		return
	}
	site := findCaller(gormExclude, 1)
	elapsed := time.Since(begin)
	sql, rows := fc()
	rowStr := "-"
	if rows >= 0 {
		rowStr = fmt.Sprintf("%d", rows)
	}
	ms := float64(elapsed.Microseconds()) / 1000.0
	switch {
	case err != nil && l.level >= glogger.Error:
		gormWrite(l.errW, Error, site, fmt.Sprintf("[%.3fms] rows=%s %s | err=%v", ms, rowStr, sql, err))
	case l.slow > 0 && elapsed > l.slow && l.level >= glogger.Warn:
		gormWrite(l.infoW, Warn, site, fmt.Sprintf("[SLOW >= %s] [%.3fms] rows=%s %s", l.slow, ms, rowStr, sql))
	case l.level >= glogger.Info:
		// 仅 debug（映射到 GORM Info）才打印 SQL
		gormWrite(l.infoW, Debug, site, fmt.Sprintf("[%.3fms] rows=%s %s", ms, rowStr, sql))
	default:
	}
}
func toGormLevel(s string) glogger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "silent", "off":
		return glogger.Silent
	case "error":
		return glogger.Error
	case "warn", "warning":
		return glogger.Warn
	case "debug":
		return glogger.Info // Debug => 打 SQL
	case "info":
		return glogger.Warn // Info => 仅警告/慢查询
	default:
		return glogger.Warn
	}
}
func GormLoggerDefault(level string) glogger.Interface {
	return NewGormLogger(level, 500*time.Millisecond)
}

/******** Gin rewriter: unified style + file:line ********/
type ginRewriter struct {
	infoW io.Writer // stdout + gin_info.log（受全局级别门控）
	errW  io.Writer // stderr + gin_error.log（受全局级别门控）
}

func (w *ginRewriter) Write(p []byte) (n int, err error) {
	lines := bytes.Split(p, []byte{'\n'})
	written := 0
	for _, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}

		lvl, msg := ginDetect(ln)
		site := findCaller(ginExclude, 1)
		dst := w.infoW
		if lvl >= Error {
			dst = w.errW
		}

		// 多行也逐行带头部
		for _, one := range strings.Split(msg, "\n") {
			one = strings.TrimSpace(one)
			if one == "" {
				continue
			}
			var b bytes.Buffer
			ts := time.Now().Format("2006/01/02 15:04:05.000000")
			fmt.Fprintf(&b, "%s %s: %s gin - %s\n", ts, site, levelTag(lvl), one)
			m, _ := dst.Write(b.Bytes())
			written += m
		}
	}
	return written, nil
}
func ginDetect(line []byte) (Level, string) {
	s := string(line)
	if strings.Contains(s, "[WARNING]") || strings.Contains(s, "[WARN]") {
		return Warn, stripGinPrefix(s)
	}
	if strings.Contains(s, "[ERROR]") {
		return Error, stripGinPrefix(s)
	}
	if strings.HasPrefix(s, "[GIN-debug]") || strings.Contains(s, "(handlers)") || strings.Contains(s, "-->") {
		return Debug, stripGinPrefix(s)
	}
	if strings.HasPrefix(s, "- ") || strings.HasPrefix(s, " - ") {
		return Info, strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s, "- "), " - "))
	}
	return Info, stripGinPrefix(s)
}
func stripGinPrefix(s string) string {
	if strings.HasPrefix(s, "[GIN") {
		if i := strings.Index(s, "]"); i >= 0 && i+1 < len(s) {
			s = strings.TrimSpace(s[i+1:])
		}
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 && i+1 < len(s) {
			s = strings.TrimSpace(s[i+1:])
		}
	}
	return s
}
