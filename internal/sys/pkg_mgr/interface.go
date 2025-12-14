package pkg_mgr

// PackageManager 定义了包管理器需要实现的接口
// 用于屏蔽 RPM 和 DPKG 的差异
type PackageManager interface {
	// Name 返回包管理器的名称 (e.g., "rpm", "dpkg")
	Name() string

	// ListPackages 返回所有已安装包的列表
	ListPackages() ([]string, error)

	// VerifyFile 检查指定文件的完整性
	// 返回: passed(是否通过), info(详细信息或错误), error
	VerifyFile(path string) (bool, string, error)

	// GetFileOwner 返回拥有该文件的软件包名称
	GetFileOwner(path string) (string, error)
}
