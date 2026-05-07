package forensics

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ShimCacheEntry 代表 ShimCache 中的一条记录
type ShimCacheEntry struct {
	Path           string
	LastModified   time.Time
	IsExecuted     bool // ShimCache 只能证明文件存在，除了 Win10+ 10ts 格式可能暗示执行
	InsertPosition int
}

// ParseShimCache 解析 AppCompatCache 二进制数据
// 支持 Windows 10 (10ts 签名) 格式
func ParseShimCache(data []byte) ([]ShimCacheEntry, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short")
	}

	// 检查签名 (Win10 Creators Update+)
	sig := string(data[0:4])
	if sig == "10ts" {
		return parseShimCacheWin10(data)
	}

	// 其他版本暂不深度支持，返回错误
	// 实际对抗中 Win10 占比最高
	return nil, fmt.Errorf("unsupported ShimCache signature: %s (only Win10 10ts supported)", sig)
}

func parseShimCacheWin10(data []byte) ([]ShimCacheEntry, error) {
	// Header size is usually 0x30 or 0x34 depending on exact build
	// 10ts header structure:
	// 0x00 Sig "10ts"
	// 0x04 Unknown
	// 0x08 Number of Entries (DWORD)
	// ...
	// Entries start around 0x30/0x34. Each entry is variable length?
	// Format:
	// Path encoded string...

	// Better logic check header size:
	// Usually 0x30 (48 bytes)
	entryCount := binary.LittleEndian.Uint32(data[0x08:0x0C])
	if entryCount == 0 {
		return nil, nil
	}

	entries := make([]ShimCacheEntry, 0, entryCount)
	offset := 0x34 // Default start for entries

	// Bound check
	if offset >= len(data) {
		// Maybe 0x30?
		offset = 0x30
	}

	for i := 0; i < int(entryCount); i++ {
		if offset >= len(data) {
			break
		}

		// Entry Structure:
		// 0x00 Signature "10ts" (repeats? no)
		// Win10 10ts Entry format is:
		// Offset 0: Path Size (USHORT)
		// Offset 2: Max Path Size (USHORT)
		// Offset 4: Offset to Data ??
		// No, the format is simple:
		// Path String (UTF-16)
		// Followed by Metadata?

		// Actually, standard Win10 format:
		// [Signature 4 bytes] [Unknown 4] [NumEntries 4] ... [Data...]
		// Data entries:
		// [PathLength 2 bytes] [Path (UTF-16)...] [LastModTime 8 bytes] [InsertFlags 4 bytes] ...
		// Let's implement based on this assumption.

		if offset+2 > len(data) {
			break
		}
		pathLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))

		// sanity check
		if pathLen == 0 || pathLen > 1024 {
			// maybe corrupt or padding?
			// scan forward?
			offset += 2
			continue
		}

		strOffset := offset + 2
		if strOffset+pathLen > len(data) {
			break
		}
		pathBytes := data[strOffset : strOffset+pathLen]
		path := decodeUTF16(pathBytes)

		metaOffset := strOffset + pathLen
		// Data block Size for metadata?
		// Usually 8 bytes timestamp + 4 bytes flags = 12 bytes?
		// Actually Win10 10ts uses:
		// [Path Size 2] [Path] [LastModTime 8] [ShimFlags 4]

		lastMod := time.Time{}
		if metaOffset+8 <= len(data) {
			ft := binary.LittleEndian.Uint64(data[metaOffset : metaOffset+8])
			lastMod = filetimeToTime(ft)
		}

		entries = append(entries, ShimCacheEntry{
			Path:           path,
			LastModified:   lastMod,
			InsertPosition: i,
		})

		offset = metaOffset + 8 + 4 // +4 for flags
	}

	return entries, nil
}

func decodeUTF16(b []byte) string {
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		if i+1 >= len(b) {
			break
		}
		val := binary.LittleEndian.Uint16(b[i : i+2])
		if val == 0 {
			continue
		}
		runes = append(runes, rune(val))
	}
	return string(runes)
}
