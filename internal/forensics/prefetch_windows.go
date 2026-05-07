//go:build windows

package forensics

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	modntdll                = syscall.NewLazyDLL("ntdll.dll")
	procRtlDecompressBuffer = modntdll.NewProc("RtlDecompressBuffer")
)

const (
	COMPRESSION_FORMAT_LZNT1   = 0x0002
	COMPRESSION_ENGINE_MAXIMUM = 0x0100
)

// PrefetchInfo 包含解析后的 Prefetch 信息
type PrefetchInfo struct {
	ExecutableName string
	RunCount       uint32
	LastRunTimes   []time.Time
	FilesLoaded    []string // 依赖的文件列表
	Hash           uint32
}

// ParsePrefetch 解析指定的 .pf 文件
func ParsePrefetch(path string) (*PrefetchInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) < 8 {
		return nil, fmt.Errorf("file too small")
	}

	// 检查头部签名
	// Windows 10/11 Prefetch 通常以 'MAM\x04' 开头 (压缩)
	// 未压缩的以 Version (数字) 开头
	header := string(data[:3])

	var rawData []byte
	if header == "MAM" {
		// 解压 MAM 格式
		decompressed, err := decompressMAM(data)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress MAM: %v", err)
		}
		rawData = decompressed
	} else {
		rawData = data
	}

	return parseRawPrefetch(rawData)
}

// decompressMAM 使用 RtlDecompressBuffer 解压
func decompressMAM(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("invalid MAM header")
	}

	// MAM 头部格式: Signature(4) + UncompressedSize(4)
	uncompressedSize := binary.LittleEndian.Uint32(data[4:8])

	output := make([]byte, uncompressedSize)
	var finalUncompressedSize uint32

	// 调用 RtlDecompressBuffer
	format := uint16(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM)

	ret, _, _ := procRtlDecompressBuffer.Call(
		uintptr(format),
		uintptr(unsafe.Pointer(&output[0])),
		uintptr(uncompressedSize),
		uintptr(unsafe.Pointer(&data[8])), // 跳过 8 字节头
		uintptr(len(data)-8),
		uintptr(unsafe.Pointer(&finalUncompressedSize)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("RtlDecompressBuffer failed with status 0x%x", ret)
	}

	return output, nil
}

// parseRawPrefetch 解析解压后的 Prefetch 二进制数据
func parseRawPrefetch(data []byte) (*PrefetchInfo, error) {
	if len(data) < 84 {
		return nil, fmt.Errorf("data too short")
	}

	version := binary.LittleEndian.Uint32(data[0:4])
	var info PrefetchInfo

	// 不同版本的偏移量不同
	// 这里主要实现 Win10/11 (Version 30) 和 Win7 (Version 23)
	var offHash, offRunCount int

	switch version {
	case 30: // Windows 10 / 11
		offHash = 0x4C
		offRunCount = 0xD0

	case 23: // Windows 7
		offHash = 0x4C
		offRunCount = 0x98

	case 26: // Windows 8.1
		offHash = 0x4C
		offRunCount = 0xD0

	default:
		return nil, fmt.Errorf("unsupported prefetch version: %d", version)
	}

	name, err := extractExeName(data, offHash)
	if err == nil {
		info.ExecutableName = name
	}

	if offRunCount > 0 && offRunCount+4 <= len(data) {
		info.RunCount = binary.LittleEndian.Uint32(data[offRunCount : offRunCount+4])
	}

	// 解析最近运行时间
	if version == 30 {
		start := 0xD4 // Win10 valid
		// Win10 有 8 个时间戳插槽 (8 * 8 bytes)
		for i := 0; i < 8; i++ {
			pos := start + i*8
			if pos+8 > len(data) {
				break
			}
			ft := binary.LittleEndian.Uint64(data[pos : pos+8])
			if ft > 0 {
				info.LastRunTimes = append(info.LastRunTimes, filetimeToTime(ft))
			}
		}
	} else if version == 23 {
		start := 0x9C
		pos := start
		if pos+8 <= len(data) {
			ft := binary.LittleEndian.Uint64(data[pos : pos+8])
			if ft > 0 {
				info.LastRunTimes = append(info.LastRunTimes, filetimeToTime(ft))
			}
		}
	}

	return &info, nil
}

// extractExeName 提取可执行文件名
func extractExeName(data []byte, offHash int) (string, error) {
	if len(data) < 0x10+60 {
		return "", fmt.Errorf("buffer too small for name")
	}

	nameBytes := data[0x10 : 0x10+60]
	runes := make([]rune, 0, 30)
	for i := 0; i < len(nameBytes); i += 2 {
		val := binary.LittleEndian.Uint16(nameBytes[i : i+2])
		if val == 0 {
			break
		}
		runes = append(runes, rune(val))
	}
	return string(runes), nil
}
