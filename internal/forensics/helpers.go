package forensics

import (
	"time"
)

// filetimeToTime 将 Windows FILETIME 转换为 Go Time
func filetimeToTime(ft uint64) time.Time {
	// 100-nanosecond intervals since January 1, 1601 (UTC)
	// 1601 to 1970 偏移秒数: 11644473600
	const epochDiff = 11644473600

	// 转换为秒和纳秒，避免溢出
	// ft 是 100ns 单位
	seconds := int64(ft / 10000000)
	nanos := int64((ft % 10000000) * 100)

	// time.Unix 需要 1970 后的秒数
	return time.Unix(seconds-epochDiff, nanos).UTC()
}
