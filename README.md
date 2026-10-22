# SQLBlind_Tools

从 PCAP/PCAPNG 中提取 SQL 注入流量，并**自动还原盲注结果**的通用工具。

面向流量分析 / 应急响应 / CTF 取证：输入抓包，输出盲注实际抽到的字符串。

## 当前能力

- HTTP GET / POST（含 `application/x-www-form-urlencoded`）
- tshark 十六进制 body、gzip 响应体自动解码
- gopher 包裹的内层 HTTP 请求还原（含多层 URL 编码）
- 布尔盲注：响应长度 / 正文指纹 / 状态码二元聚类 + 极性自动校正
- 时间盲注：`sleep` / `benchmark` / `pg_sleep` 等时延判定
- 探针识别：`length`、`ascii/ord(substr/mid)`（含 `FROM n FOR 1`）、字符等值、`IN`、`least()/greatest()` 区间等价
- 全假位置自动截断、非 ASCII `ord` 字节显式标记、结果形态提示（PNG hex / 密文等）
- 自定义正则补充提取

## 依赖

- Python 3.10+
- 系统已安装并可调用 `tshark`（Wireshark 自带）
- 可选：`pip install pyshark`（`--engine pyshark`）

## 用法

```bash
python sqlblind_tools.py -f demo/Sqlmap_Boolean.pcapng
python sqlblind_tools.py -f demo/Sqlmap_Time.pcapng
python sqlblind_tools.py -f demo/vnctf_2024_sqlshark.pcap
python sqlblind_tools.py -f capture.pcapng -o requests.txt --json out.json
```

```text
optional arguments:
  -f FILE, --file FILE   PCAP/PCAPNG 文件路径
  -r REGEXP, --regexp    自定义正则从归一化请求提取
  -o OUTPUT, --output    导出归一化 HTTP 请求
  --json JSON            导出分析结果 JSON
  --top N                展示前 N 个目标（默认 5）
  --engine {tshark,pyshark}
  --sample-limit N       终端请求样本数
```

## 架构

```text
sqlblind_tools.py          CLI 入口
sqlblind/
  capture.py               tshark/pyshark 抽取 + 噪音过滤
  decode.py                URL/hex/gzip/gopher/form 解码
  probe.py                 SQL 探针规范化与提取
  signal.py                真值聚类与极性推断
  solver.py                约束求解与字符串还原
  report.py                终端 / JSON 输出
  pipeline.py              编排
```

## 说明

- 工具先归一化请求再识别探针，因此 POST body、hex body、gopher 内嵌请求会一并处理。
- 真/假响应极性通过聚类 + 双极性试解按还原质量选择，**不假设“更长=真”**。
- 若内置规则无法覆盖，可用 `-r` 自定义正则补充。
