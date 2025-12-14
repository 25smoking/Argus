package windows

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/25smoking/Argus/internal/core"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
)

type AccountPlugin struct{}

func (p *AccountPlugin) Name() string {
	return "WindowsAccountScan"
}

func (p *AccountPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}

	var results []core.Result

	results = append(results, checkHiddenUsers()...)
	results = append(results, checkGuestStatus()...)
	results = append(results, checkAdminGroup()...)

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "账户安全检测完成，未发现异常",
			Reference:   "已检查隐藏账户、Guest状态、管理员组",
		})
	}

	return results, nil
}

func execCmdOutput(name string, args ...string) string {
	// Deprecated: No longer using CLI commands
	return ""
}

func checkHiddenUsers() []core.Result {
	var results []core.Result

	users, err := winsys.EnumLocalUsers()
	if err != nil {
		results = append(results, core.Result{
			Plugin:      "WindowsAccountScan",
			Level:       "low",
			Description: "用户枚举失败 (Native API error)",
			Reference:   fmt.Sprintf("Error: %v", err),
		})
		return results
	}

	for _, u := range users {
		// 1. 检查以 $ 结尾的影子账户
		if strings.HasSuffix(u.Name, "$") {
			results = append(results, core.Result{
				Plugin:      "WindowsAccountScan",
				Level:       "critical",
				Description: "发现疑似隐藏账户 (以 $ 结尾)",
				Reference:   fmt.Sprintf("User: %s (SID: %s)", u.Name, u.SID),
				Advice:      "Windows 只有机器账户才以 $ 结尾，出现在 Users 中极有可能是影子账户。",
			})
		}
	}

	// 顺便做克隆账户检测
	results = append(results, checkCloneAccounts(users)...)

	return results
}

func checkCloneAccounts(users []winsys.UserAccountInfo) []core.Result {
	var results []core.Result

	// RID -> []Usernames
	ridMap := make(map[uint32][]string)

	for _, u := range users {
		ridMap[u.RID] = append(ridMap[u.RID], u.Name)
	}

	for rid, names := range ridMap {
		if len(names) > 1 {
			// 多个用户共享同一个 RID -> 克隆账号
			level := "high"
			if rid == 500 {
				level = "critical" // Administrator 克隆
			}

			results = append(results, core.Result{
				Plugin:      "WindowsAccountScan",
				Level:       level,
				Description: fmt.Sprintf("发现克隆账号 (共享 RID %d)", rid),
				Reference:   fmt.Sprintf("Users: %v", names),
				Advice:      "极高风险！多个账户拥有相同的 RID，这是典型的克隆账号后门。",
			})
		}
	}
	return results
}

func checkGuestStatus() []core.Result {
	var results []core.Result

	users, err := winsys.EnumLocalUsers()
	if err != nil {
		return nil
	}

	// UF_ACCOUNTDISABLE = 0x0002
	const UF_ACCOUNTDISABLE = 0x0002

	for _, u := range users {
		if strings.EqualFold(u.Name, "Guest") {
			// 检查 Flags 是否包含 DISABLED
			if (u.Flags & UF_ACCOUNTDISABLE) == 0 {
				results = append(results, core.Result{
					Plugin:      "WindowsAccountScan",
					Level:       "high",
					Description: "Guest (来宾) 账户已被启用",
					Reference:   fmt.Sprintf("Guest Account is Active (Flags: 0x%x)", u.Flags),
					Advice:      "攻击者常利用 Guest 账户进行横向移动或持久化，请禁用。",
				})
			}
		}
	}
	return results
}

func checkAdminGroup() []core.Result {
	var results []core.Result

	// 目前 Native API 获取组成员稍微复杂 (NetLocalGroupGetMembers)，
	// 暂保留逻辑接口，后续实现
	// 或者通过 EnumLocalUsers 检查 Priv 标志 (Priv == 2 is Admin)

	users, err := winsys.EnumLocalUsers()
	if err != nil {
		return nil
	}

	for _, u := range users {
		if u.Priv == 2 { // USER_PRIV_ADMIN
			if !strings.EqualFold(u.Name, "Administrator") && !strings.Contains(u.Name, "$") {
				results = append(results, core.Result{
					Plugin:      "WindowsAccountScan",
					Level:       "notice",
					Description: "发现非默认管理员用户",
					Reference:   fmt.Sprintf("User: %s (Priv: Admin)", u.Name),
				})
			}
		}
	}

	return results
}
