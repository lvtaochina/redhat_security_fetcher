# Red Hat CVE Security Data Fetcher

通过 Red Hat Security Data API 获取 CVE 数据，按配置筛选关注的 RHEL 版本和软件包状态，并将结果写入报告文件。

## 功能概览

- 从文本文件读取 CVE ID；每行一个 ID，自动去除行首、行尾空白，并忽略空行。
- 调用 Red Hat Security Data API 获取每个 CVE 的 JSON 数据。
- 根据 `config.py` 中的 `WANT_RHELS` 和 `FIX_STATES` 筛选数据。
- 提取 CVE 名称、严重性、公开日期、受影响版本的组件信息及软件包状态。
- 将结果写入报告文件，并将运行信息和请求失败信息写入日志。
- 支持使用命令行参数指定输入文件和输出报告路径。

程序目前**未实现自动重试机制**。单个 CVE 请求失败时会记录警告并继续处理后续 CVE。

## 项目结构

```text
redhat_security_fetcher/
├── api_client.py          # 调用 Red Hat API，并封装成功/失败结果
├── config.py              # API、RHEL 筛选、输入输出路径和日志等配置
├── get_affected_cves.py   # 主程序、数据筛选、报告输出和执行流程
├── requirements.txt       # 第三方 Python 依赖
├── input/                 # 本地 CVE 输入文件（默认纳入 Git 版本管理）
├── reports/               # 生成的报告（默认不纳入 Git 版本管理）
├── log/                   # 程序日志（默认不纳入 Git 版本管理）
├── tests/                 # 测试文件
└── .venv/                 # 本地 Python 虚拟环境（不纳入 Git 版本管理）
```
示例输入文件 input/cves.example.txt 随项目提供。使用者可以修改该文件中的 CVE 列表，或通过 --input 参数指定自己的输入文件。生成的报告`reports/`和日志 `log/`保存在各自配置的目录中，这些生成内容不纳入 Git 版本管理。

## 环境要求

- Python 3.12 或更高版本。项目使用了 Python 3.12 引入的泛型函数语法。
- 能够访问 Red Hat Security Data API 的网络连接；如果环境需要代理，请在 `config.py` 中配置 `PROXIES`。

## 安装与准备环境

建议在项目根目录使用独立的虚拟环境。

```bash
# 创建虚拟环境
python3 -m venv .venv

# 激活虚拟环境（Linux）
source .venv/bin/activate

# 升级当前虚拟环境中的 pip
python -m pip install --upgrade pip

# 安装项目依赖
python -m pip install -r requirements.txt
```

退出虚拟环境：

```bash
deactivate
```

`requirements.txt` 声明项目所需的第三方依赖。Python 标准库模块（例如 `pathlib`、`argparse` 和 `logging`）不需要单独通过 pip 安装。

## 输入文件

默认输入路径由 `config.py` 中的 `CVE_INPUT_PATH` 指定。当前配置使用 `input/cves.example.txt`。

输入文件采用每行一个 CVE ID 的文本格式，例如：

```text
CVE-2026-1234
CVE-2026-5678
```

空行会被忽略，行首和行尾的空白会被移除。输入文件或其父目录不存在时，程序会报告输入错误；程序不会自动创建缺失的输入目录，也不会自动生成 CVE 输入文件。

请根据实际需要维护输入文件。示例中的 CVE ID 仅用于说明格式。

## 配置说明

主要配置位于 `config.py`：

| 配置项 | 作用 |
|---|---|
| `WANT_RHELS` | 需要筛选的 RHEL 产品版本集合 - 请按需配置|
| `CVE_INPUT_PATH` | 默认 CVE 输入文件路径 - 请按需配置|
| `CVE_OUTPUT_PATH` | 默认报告文件路径|
| `API_HOST` | Red Hat Security Data API 基础地址 |
| `PROXIES` | HTTP 请求的代理配置；默认不设置代理 |
| `REQ_TIME_OUT` | HTTP 请求超时时间 |
| `FIX_STATES` | 需要保留的软件包状态集合 |
| `AFFECTED_KEYS` | 从 `affected_release` 数据中提取的字段 - 请勿修改|
| `PACKAGE_KEYS` | 从 `package_state` 数据中提取的字段  - 请勿修改|
| `LOG_FILENAME` | 日志文件路径 |
| `LOG_LEVEL` | 日志级别 |

如需使用代理，请按当前网络环境调整 `PROXIES`。不要将组织内部代理凭据等敏感信息提交到版本库。
`AFFECTED_KEYS`和`PACKAGE_KEYS`:当前实现要求第一个元素为 product_name，除非同步修改筛选逻辑，否则不要改变该约定。

## 运行程序

在项目根目录、并激活虚拟环境后，使用默认路径运行：

```bash
./get_affected_cves.py
```

也可以通过命令行参数指定输入文件和输出文件：

```bash
./get_affected_cves.py \
  --input /path/to/cves.txt \
  --output /path/to/report.txt
```

参数说明：

| 参数 | 简写 | 说明 |
|---|---|---|
| `--input` | `-i` | CVE 输入文件路径；未指定时使用 `CVE_INPUT_PATH` |
| `--output` | `-o` | 报告输出路径；未指定时使用 `CVE_OUTPUT_PATH` |
| `--help` | | 显示命令行帮助 |

程序会在需要时创建输出报告的父目录，并以写入模式生成报告，因此同一路径下的同名报告可能会被覆盖。日志目录由日志初始化逻辑创建；日志以追加模式写入配置的日志文件。

默认配置路径基于项目配置文件的位置构建。通过命令行提供的相对路径则应以启动命令时的当前工作目录为基准；为避免歧义，也可以传入绝对路径。

## 报告与日志

- **报告**：默认输出位置由 `CVE_OUTPUT_PATH` 指定（通常位于 `reports/`）。报告包含 CVE 基本信息，以及符合当前筛选配置的 RHEL 发布信息和软件包状态。
- **日志**：默认日志路径由 `LOG_FILENAME` 指定（当前配置为 `log/rhel_cve_fetcher.log`）。日志用于记录处理进度、未匹配到筛选记录的情况及 API 请求失败等信息。
- **请求失败**：API 请求异常、非 HTTP 200 响应、JSON 解析失败或返回空数据时，`api_client.py` 返回结构化的失败结果；主程序记录警告并继续处理其他 CVE。

注意：某个 CVE 在当前筛选条件下没有匹配记录，只表示当前配置下未找到匹配结果，不应据此单独断定该 CVE 不影响任何 Red Hat 产品。

## 运行测试

测试文件统一位于 `tests/`。开发过程中已经对主要功能执行了单元测试，并完成了使用真实 Red Hat API 数据的整体集成测试；在升级 `requests` 后也重新执行并确认通过。

请在项目根目录打开终端，并激活项目的虚拟环境后执行以下测试命令。
测试覆盖的主要功能/测试命令包括：
- 字典辅助函数 `add_to_dict()` 的添加和去重行为；
```bash
   python -m tests.test_add_to_dict
```

- `filter_cve_data()` 的字段提取、筛选和缺失字段处理；
```bash
   python -m tests.test_filter_cve_data
```

- `api_client.py` 中 `get_data()` 的成功、空数据、HTTP 错误、请求异常和 JSON 解析错误处理；
```bash
   python -m tests.test_get_data
```

- `read_cves()` 对正常文件、空文件和空白行的处理；
```bash
   python -m tests.test_read_cves
```

- `print_rhel_table()` 的报告文本输出。
```bash
   python -m tests.test_print_rhel_table
```

## 当前限制

- 当前没有实现自动重试和并发处理, 在作者开发环境下处理约261个CVE条目约需要2~3分钟。
- 查询结果取决于 API 返回的数据，以及 `WANT_RHELS`、`FIX_STATES` 等筛选配置。
- 输入 CVE ID 的格式验证目前较为基础；请自行确保输入文件内容有效。
- `reports/`、`log/`和 `.venv/` 等本地数据或生成内容由 Git 忽略规则管理，不应假设这些内容会随代码仓库一同交付。