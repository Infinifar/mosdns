# MosDNS：MMDB 基线与 stats_api 集成

这是社区集成版本，不是 MosDNS 上游的官方发行版。

本版本直接基于 [alecthw/mosdns](https://github.com/alecthw/mosdns)，保留其 MMDB 响应 IP 匹配等修改；原始项目由 [IrineSistiana/mosdns](https://github.com/IrineSistiana/mosdns) 及其贡献者开发。

在该基线上移植了 [sbwml/luci-app-mosdns v5 的 stats_api 系列补丁](https://github.com/sbwml/luci-app-mosdns/tree/v5/mosdns/patches)，并集成统计所需的查询上下文和 fallback 元数据处理。移植和集成不改变原作者署名，也不表示所有其他上游补丁都已包含。

## 本集成版本的主要差异

- 保留 alecthw 的 MMDB 相关修改。
- 增加 stats_api 插件，供新版 LuCI MosDNS 的统计页面读取。
- 支持查询日志、热门域名/客户端、历史统计、实时 QPS 和可选持久化。
- 接入统计所需的来源、规则命中、缓存/阻断与上游上下文；保留对应单元测试。

源码不包含路由器账号、节点密钥、代理订阅、登录状态或个人 DNS 配置。固件集成示例见 [Infinifar/openwrt-actions](https://github.com/Infinifar/openwrt-actions)。

## 使用与安全边界

遵循原项目配置方式，功能说明见 [MosDNS wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)。启用 stats_api 时，需要在插件配置中设置 listen，并按示例将插件加入自己的执行链；监听地址和执行顺序应依据所用 LuCI 配置生成器核对，不应只复制一段没有执行链的插件定义。

统计接口含域名、客户端和查询历史。请绑定回环或可信管理网，配置访问控制，不要直接暴露到公网；持久化选项由用户自行决定。本仓库没有把任何真实统计数据或设备配置打包进去。

## 验证与许可证

使用满足 go.mod 及依赖要求的 Go 工具链执行：

```sh
go test ./...
```

本次公开化未改动 Go 实现，只调整公开文档和手动测试工作流；没有宣称在本次发布时重新编译过二进制。

完整 [GPL-3.0 LICENSE](LICENSE) 和源文件版权头均保留。来源、版本与移植范围见 [CREDITS.md](CREDITS.md)；依赖的其他许可证应分别遵守。
