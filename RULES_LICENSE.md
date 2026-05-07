# Argus 规则库许可证说明

Argus 当前采用“现有优先”的规则策略：继续支持项目已有的 Elastic 与 Neo23x0/signature-base 等规则来源，但使用者需要遵守对应上游许可证。

默认规则源：

| 来源 | 用途 | 许可证 |
| --- | --- | --- |
| Neo23x0/signature-base | THOR/LOKI 风格 YARA 与 Webshell 规则 | Detection Rule License (DRL) 1.1 |
| elastic/protections-artifacts | Elastic 安全 YARA 规则 | Elastic License v2 |

执行 `argus rules update` 后，`.rule/RULES_LICENSE.md` 会根据实际下载的规则源重新生成。
