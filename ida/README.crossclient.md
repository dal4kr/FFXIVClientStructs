# 跨客户端符号导入

将 FFCS 的函数名、虚表和结构声明导入其他版本或地区的客户端。先在 IDA 外生成目标客户端的数据，再在 IDA 内导入。需要检查源码中的字段偏移、结构大小和特征码时，参见 [客户端声明维护](README.client-update.md)。

## 导入至 IDA

### 运行要求

- Python 3.10 及更高版本，以及 `pefile`、`capstone`、`PyYAML`。
- IDA 9 及更高版本，并完成 FFCS 原有导入脚本所需的 Python 依赖和游戏数据路径配置。
- 参考客户端和目标客户端的 `ffxiv_dx11.exe`，以及对应参考客户端的命名数据。

### 运行过程

1. 在本目录打开 PowerShell，安装 Python 依赖：

```powershell
python -m pip install pefile capstone PyYAML
```

2. 指定两个客户端，执行数据转换。以下示例从国际服 7.57hf1 生成国服 7.57 的命名数据，也用于国服版本更新配置中的 `data`：

```powershell
$sourceClient = 'E:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\clients\7.57hf1\ffxiv_dx11.exe'
$targetClient = 'E:\Program Files (x86)\上海数龙科技有限公司\clients\7.57\ffxiv_dx11.exe'
$data = '.\old\data_2026.10.16.0000.0000.yml'

python -X utf8 -B .\ffxiv_crossclient.py --source $sourceClient --target $targetClient --data $data --output .\data.generated.yml --mapping .\crossclient.generated.json --report .\crossclient.report.json
```

替换客户端路径后即可使用。`--data` 必须与参考客户端对应；使用当前国际服客户端时，可指定 `data.yml`。结构声明默认读取本目录的 `ffxiv_structs.yml`，也可通过 `--structs` 指定其他文件。输出文件应与输入文件使用不同路径。

3. 检查本目录生成的文件：

| 文件 | 用途 |
| --- | --- |
| `data.generated.yml` | 目标客户端的命名数据，供 IDA 导入或声明维护脚本使用 |
| `crossclient.generated.json` | 两端函数映射和解析缓存，保留后可复用 |
| `crossclient.report.json` | 无法定位、地址冲突及签名定位分歧的具体条目 |

报告中未解析或存在冲突的地址不会写入命名数据，需要在 IDA 中继续定位。冲突已计入未解析项，无需重复统计。命令中断后可执行原命令继续处理；更换任一客户端时，应更换映射缓存的文件名。

4. 在 IDA 中打开目标客户端，选择运行本目录的 `ffxiv_crossclient_ida.py`，在文件选择对话框中选择 `data.generated.yml`。脚本会核对客户端 SHA-256；不匹配时应重新选择数据库或生成数据。

5. 按提示完成命名和结构导入，结构导入建议选择 SrcLang。缺少 EXD 基础类型时，脚本会先执行 EXD 导入，游戏数据路径沿用 FFCS 原有配置。等待脚本运行完成即可。

导入过程不修改磁盘上的 `data.yml` 和 `ffxiv_structs.yml`。需要向国际服导入时，同样执行上述过程；若两个客户端是同一文件，脚本会直接沿用原地址。
