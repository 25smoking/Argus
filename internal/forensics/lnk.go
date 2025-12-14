package forensics

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"time"
)

// LnkInfo 包含 LNK 文件的关键取证信息
type LnkInfo struct {
	HeaderTimes  [3]time.Time // Creation, Access, Write
	TargetPath   string
	RelativePath string
	WorkDir      string
	IconLocation string
}

const (
	HasLinkTargetIDList = 1 << 0
	HasLinkInfo         = 1 << 1
	HasName             = 1 << 2
	HasRelativePath     = 1 << 3
	HasWorkingDir       = 1 << 4
	HasArguments        = 1 << 5
	HasIconLocation     = 1 << 6
	IsUnicode           = 1 << 7
)

// ParseLnk 解析 .lnk 文件
func ParseLnk(path string) (*LnkInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) < 76 { // LNK Header is 76 bytes
		return nil, fmt.Errorf("file too small")
	}

	info := &LnkInfo{}

	// 1. Parse Header
	// Size: 0x00 (4)
	// GUID: 0x04 (16)
	// Flags: 0x14 (4)
	flags := binary.LittleEndian.Uint32(data[0x14:0x18])

	// Times: Creation(0x1C), Access(0x24), Write(0x2C)
	info.HeaderTimes[0] = filetimeToTime(binary.LittleEndian.Uint64(data[0x1C:0x24])) // Creation
	info.HeaderTimes[1] = filetimeToTime(binary.LittleEndian.Uint64(data[0x24:0x2C])) // Access
	info.HeaderTimes[2] = filetimeToTime(binary.LittleEndian.Uint64(data[0x2C:0x34])) // Write

	cursor := 76

	// 2. Skip LinkTargetIDList if present
	if flags&HasLinkTargetIDList != 0 {
		if cursor+2 > len(data) {
			return info, nil
		}
		idListSize := int(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2 + idListSize
	}

	// 3. Parse LinkInfo if present
	if flags&HasLinkInfo != 0 {
		if cursor+4 > len(data) {
			return info, nil // truncated
		}
		linkInfoSize := int(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
		// 确保不做越界读取
		if cursor+linkInfoSize <= len(data) {
			parseLinkInfo(data[cursor:cursor+linkInfoSize], info)
		}
		cursor += linkInfoSize
	}

	// 4. String Data (Name, RelativePath, WorkingDir, Arguments, IconLocation)
	// 顺序固定，如果Flag设置则存在
	// 都是 Counted String (First 2 bytes = Length in chars)
	// 如果 IsUnicode (Flag bit 7), chars are 2 bytes (UTF-16). 否则 1 byte.

	isUnicode := flags&IsUnicode != 0

	// Helper to read string
	readStr := func() string {
		if cursor+2 > len(data) {
			return ""
		}
		charCount := int(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		byteCount := charCount
		if isUnicode {
			byteCount *= 2
		}

		if cursor+byteCount > len(data) {
			return ""
		}

		b := data[cursor : cursor+byteCount]
		cursor += byteCount

		if isUnicode {
			return decodeUTF16(b)
		}
		return string(b)
	}

	// HasName
	if flags&HasName != 0 {
		_ = readStr() // Description / Name (Skip)
	}
	// HasRelativePath
	if flags&HasRelativePath != 0 {
		info.RelativePath = readStr()
	}
	// HasWorkingDir
	if flags&HasWorkingDir != 0 {
		info.WorkDir = readStr()
	}
	// HasArguments
	if flags&HasArguments != 0 {
		_ = readStr() // Skip args for now
	}
	// HasIconLocation
	if flags&HasIconLocation != 0 {
		info.IconLocation = readStr()
	}

	return info, nil
}

func parseLinkInfo(data []byte, info *LnkInfo) {
	if len(data) < 28 {
		return
	}
	// LinkInfoSize(4), LinkInfoHeaderSize(4), Flags(4), VolumeIDOffset(4), LocalBasePathOffset(4)
	linkInfoSize := binary.LittleEndian.Uint32(data[0:4])
	if int(linkInfoSize) != len(data) {
		// mismatch
	}

	// headerSize := binary.LittleEndian.Uint32(data[4:8])
	// flags := binary.LittleEndian.Uint32(data[8:12])
	// (Bit 0: VolumeIDAndLocalBasePath present)

	localBasePathOffset := int(binary.LittleEndian.Uint32(data[16:20]))

	if localBasePathOffset > 0 && localBasePathOffset < len(data) {
		// LocalBasePath is a null-terminated string (ANSI usually? Or depends on header size >= 0x24 ?)
		// Standard is ANSI. If header size >= 0x24, there is LocalBasePathOffsetUnicode at offset 0x1C.

		// extract null terminated
		end := localBasePathOffset
		for end < len(data) && data[end] != 0 {
			end++
		}
		info.TargetPath = string(data[localBasePathOffset:end])
	}
}

// CalculateEntropy 计算数据的香农熵
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}

	total := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
