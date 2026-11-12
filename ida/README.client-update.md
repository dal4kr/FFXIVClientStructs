# 客户端声明维护

比较两个客户端，检查 C# 声明中的字段偏移、结构大小、虚函数序号和特征码，并生成修复计划。支持版本更新及国际服、国服之间的比较。分析脚本在 IDA 外运行，生成新特征码时需要目标客户端的 IDA 数据库。

## 检查与修复

### 运行要求

- Python 3.10 及更高版本，以及 `capstone`、`pefile`、`PyYAML`、`ahocorasick-rs`、`Send2Trash`。
- 两个客户端的 `ffxiv_dx11.exe`，以及对应参考客户端的 FFCS 命名数据。
- FFCS、Expansion 和需要检查的源码仓库；使用旧版本声明时，仓库中须保留配置指定的 Git 提交。
- 生成特征码修复计划时，需要 IDA 9 及更高版本，并启用 `ida-pro-mcp`。

### 运行过程

1. 在 FFCS 的 `ida` 目录打开 PowerShell，安装 Python 依赖：

```powershell
python -m pip install capstone pefile PyYAML ahocorasick-rs Send2Trash
```

2. 在本目录选择配置，检查客户端和源码路径：

| 配置文件 | 比较方向 | 源码范围 |
| --- | --- | --- |
| `client-update.cn.json` | 国服 7.57 → 国服 7.58 | FFCS、Expansion、Daily Routines、OmenTools、KamiToolKit |
| `client-update.global.json` | 国际服 7.57hf1 → 国际服 7.58 | FFCS、Expansion |
| `client-update.global-to-cn.json` | 国际服 7.58 → 国服 7.58 | FFCS、Expansion |

配置中的相对路径均以配置文件所在目录为起点。`source`、`target` 是参考和目标客户端，`roots` 是待检查的源码目录。只读取已纳入 Git 的 C# 文件。

`data` 是参考客户端的命名数据，用于查找构造函数和虚表。国服配置使用 `data.generated.yml`；缺少该文件或文件对应其他客户端时，先按 [跨客户端符号导入](README.crossclient.md) 的示例生成国服 7.57 数据。国际服版本配置使用 `old/data_2026.10.16.0000.0000.yml`，地区比较配置使用国际服 7.58 的 `data.yml`。

`baseline_root` 和 `baseline_revision` 指定更新前的源码目录和 Git 版本；`baselines` 为其他仓库指定旧版本。脚本直接读取 Git 中的旧声明，与当前源码一并比较，不切换工作区。维护后续版本时，应同时更新客户端路径、旧版本提交、命名数据和输出文件名。

3. 分别建立参考端、目标端的函数索引，再执行比较。以下示例检查国服更新：

```powershell
$config = '.\client-update.cn.json'
python -X utf8 -B .\ffxiv_client_update.py --config $config --phase source
python -X utf8 -B .\ffxiv_client_update.py --config $config --phase target
python -X utf8 -B .\ffxiv_client_update.py --config $config
```

检查国际服更新时，将 `$config` 改为 `.\client-update.global.json`，执行相同的三条命令。每条命令默认限时 270 秒；执行失败时，先处理报错再运行下一条。

索引和报告均输出至本目录，文件名由配置中的 `cache` 和 `report` 决定。例如国服配置生成 `update-cn-7.58.cache.source.json`、`update-cn-7.58.cache.target.json` 和 `update-cn-7.58.json`。保留索引后，修改源码只需重新运行比较命令；更换客户端则须重建对应索引。

4. 国际服和国服的索引均建立后，执行地区比较：

```powershell
python -X utf8 -B .\ffxiv_client_update.py --config .\client-update.global-to-cn.json
```

此配置通过 `source_index`、`target_index` 复用前两份配置生成的 7.58 目标索引，不需要再次建立索引。报告为 `update-global-to-cn-7.58.json`。出现索引缺失或客户端不匹配的报错时，应先重新执行相应版本配置的 `--phase target` 命令。

5. 打开报告，查看 `structures` 中的字段、大小和虚函数结果，以及 `signatures` 中的特征码结果。结构相关状态按下表处理：

| 状态 | 含义与处理方式 |
| --- | --- |
| `unchanged` | 已取得的证据表明该项未变化 |
| `candidate` | 找到修改候选，核对证据后可生成布局修复计划 |
| `already-updated` | 当前声明已被调整，无需重复应用候选；结构大小仍需结合分配证据确认 |
| `conflict` | 证据给出不同结果，需要在 IDA 中核对 |
| `unobserved`、`unresolved`、`unproven` | 缺少访问、虚表或分配证据，尚未完成验证 |
| `declaration-removed` | 当前源码已移除旧字段，无需恢复旧声明 |

字段证据包含方法名及两端指令地址，可据此在 IDA 中检查。结构大小只有取得分配证据时才会进入修复计划；观察到的最大访问偏移不能证明结构的完整大小。

特征码中的 `wrong-target` 表示命中了其他位置，`target-unresolved` 表示目标端未能唯一定位，`source-unresolved` 表示参考端未能唯一定位，均需继续处理。`matched` 表示命中位置与函数映射一致；`unverified-target` 虽然唯一命中，但尚未证明函数身份。`declaration-updated` 表示原签名声明已被替换，应检查当前声明的结果。

6. 生成布局修复计划。以下命令使用国服报告，其他配置应替换为对应报告：

```powershell
python -X utf8 -B .\ffxiv_client_update_apply.py --kind layouts --report .\update-cn-7.58.json --plan .\layouts.plan.json
```

计划中的 `edits` 包含待修改文件、原文、替换内容和证据，`rejected` 列出未纳入计划的项目。生成计划不会修改源码。

7. 需要更新成员函数特征码时，在 IDA 中打开目标客户端，并填入该数据库的 MCP 地址：

```powershell
$idaURL = 'http://127.0.0.1:13338/mcp'
python -X utf8 -B .\ffxiv_client_update_apply.py --report .\update-cn-7.58.json --ida-url $idaURL --plan .\signatures.plan.json
```

脚本先核对 IDA 数据库的客户端 SHA-256，再逐个生成特征码，原样保存工具结果，并检查是否在目标客户端唯一命中预期地址。自动计划只处理 `MemberFunction`；`CompSig`、内存补丁、静态地址和读取指令立即数的签名，需要结合调用方的读取偏移、宽度及用途单独处理。

8. 核对计划后，应用相应修改：

```powershell
python -X utf8 -B .\ffxiv_client_update_apply.py --plan .\layouts.plan.json --apply
```

应用特征码计划时，将计划路径替换为 `.\signatures.plan.json`。应用前会统一校验源码 SHA-256 和替换范围；校验失败不会写入，应基于当前源码重新生成报告和计划。原文件副本会送入系统回收站，写入时保留换行方式并使用 UTF-8 无 BOM 编码；符号链接和硬链接不会修改。

两份计划若涉及同一文件，应在应用第一份后重新生成报告及第二份计划，避免文件校验失败。完成修改后，重新运行对应比较命令检查剩余项目；共用声明还需检查其他受支持的客户端。
