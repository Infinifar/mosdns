# 来源、作者与移植范围

## 直接来源

| 来源 / 作者 | 贡献及本版本关系 |
|---|---|
| [IrineSistiana/mosdns](https://github.com/IrineSistiana/mosdns) 及贡献者 | 原始 MosDNS 项目、核心插件架构和主要实现；原模块路径 github.com/IrineSistiana/mosdns/v5 保留 |
| [alecthw/mosdns](https://github.com/alecthw/mosdns) | 本集成版本的直接代码基线，保留其 MMDB 响应 IP 匹配等修改；基线提交 a61e0ed |
| [sbwml/luci-app-mosdns](https://github.com/sbwml/luci-app-mosdns/tree/v5/mosdns/patches) / sbwml | stats_api 插件与相关统计修复、查询上下文、日志和 fallback 元数据处理等移植来源 |
| Infinifar | 将上述修改集成到固件使用的源码快照，保留并移植统计链路、对应测试与公开说明；不冒充上游作者 |

stats_api 的原始补丁 [216-plugin-add-stats_api-plugin.patch](https://github.com/sbwml/luci-app-mosdns/blob/v5/mosdns/patches/216-plugin-add-stats_api-plugin.patch) 标明作者及 Signed-off-by 为 sbwml。fallback 上下文补丁见 [225-fix-fallback-preserve-upstream-and-query-context-met.patch](https://github.com/sbwml/luci-app-mosdns/blob/v5/mosdns/patches/225-fix-fallback-preserve-upstream-and-query-context-met.patch)。同目录的后续统计修复是本移植的参考来源；不因此声称整个补丁目录或以后更新的补丁已全部应用。

## 许可证与既有署名

- 原项目 GPL-3.0 LICENSE 全文保留；源码中的版权头、作者信息和许可证声明不删改。
- 本公开仓库是文件级源码快照，不包含私有运维仓库历史。原作者的贡献通过来源链、基线、原版权头和上游链接说明，而不是改写成集成者原创。
- Go 依赖和版本见 go.mod / go.sum。DNS、HTTP、QUIC、MMDB、Prometheus、日志等第三方依赖各有作者与许可证，不能用此说明替代它们的独立许可。
- 不重新打包或冒用上游官方预编译发行物的名义。若发布本集成版本的二进制，应附对应源码、修改说明和许可证。

## 此次公开化

仅将现有集成源码作为公开快照，补充 README / CREDITS 及手动触发的测试入口，不含账号、令牌、路由器状态、DNS 查询日志和私有 GitLab 访问地址。未在此次公开化中另外修改 Go 实现。
