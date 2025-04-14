# 三方包供应链攻击检测工具

一款基于静态分析的多语言第三方包供应链攻击检测工具。

## 主要功能

- **多语言支持**: 检测 JavaScript/TypeScript (npm)、Python (pip)、Go (go modules)和 Rust (crates.io)包中的恶意代码
- **多维度分析**: 结合 AST 分析、模式匹配和特定行为识别
- **风险分级**: 将风险分为高、中、低三级，便于优先处理高风险问题
- **代码上下文**: 显示可疑代码的上下文行，便于分析和审查
- **混淆代码检测**: 专门检测高度混淆的恶意代码，针对供应链攻击常用的代码混淆技术
- **自定义规则**: 支持通过 YAML/JSON 文件自定义检测规则

## 安装方法

### 前置条件

- Python 3.6+
- Node.js 12+ (用于 JavaScript 代码分析)

### 安装步骤

1. 克隆仓库:

```bash
git clone https://github.com/yourusername/package-scanner.git
cd package-scanner
```

2. 安装 Python 依赖:

```bash
pip install -r requirements.txt
```

3. 安装 Node.js 解析器依赖:

```bash
cd node_parser
npm install
cd ..
```

## 使用说明

### 基本使用

扫描目录或包:

```bash
python cli.py ./path/to/project
```

### 常用参数

```bash
# 显示帮助
python cli.py --help

# 详细模式
python cli.py ./path/to/project --verbose

# 指定输出格式(json或text)
python cli.py ./path/to/project --output json

# 跳过TypeScript定义文件(.d.ts)
python cli.py ./path/to/project --skip-dts

# 指定上下文行数
python cli.py ./path/to/project --context-lines 3

# 按风险级别过滤(high, medium, low)
python cli.py ./path/to/project --severity high

# 仅检测代码混淆
python cli.py ./path/to/project --obfuscation-only
```

## 检测范围

该工具可以检测多种恶意行为，包括但不限于:

### 高风险行为

- **代码执行**: 如 eval()、new Function()等动态代码执行
- **高度混淆**: 无意义变量名、字符串拆分、数组混淆等
- **敏感信息泄露**: 私钥、Token 等敏感信息传输
- **可疑安装脚本**: 利用 preinstall/postinstall 执行恶意命令

### 中风险行为

- **动态导入**: 如动态 require()可能导致执行外部代码
- **环境探测**: 检测沙箱、调试或 CI 环境以规避检测
- **系统命令执行**: 如 exec、shell 命令等

### 低风险行为

- **编码操作**: Base64 编码/解码等可能用于混淆数据
- **存储访问**: 访问本地存储、Cookie 等
- **文件操作**: 写入文件等操作

## 项目结构

```
package-scanner/
├── cli.py                      # 主入口脚本
├── requirements.txt            # Python依赖
├── README.md                   # 项目文档
├── scanner/                    # 目录扫描器
│   ├── __init__.py
│   └── scanner.py              # 扫描器实现
├── engine/                     # 规则引擎
│   ├── __init__.py
│   └── rule_engine.py          # 规则执行核心
├── node_parser/                # Node.js解析器
│   ├── __init__.py
│   ├── parser.py               # Python与Node.js交互
│   ├── parse.js                # JavaScript AST解析脚本
│   └── package.json            # Node.js依赖
├── reporter/                   # 报告生成器
│   ├── __init__.py
│   └── reporter.py             # 结果报告实现
├── obfuscation_detector.py     # 混淆代码检测器
├── rules/                      # 规则定义
│   ├── high_rules.yaml         # 高风险规则
│   ├── medium_rules.yaml       # 中风险规则
│   └── low_rules.yaml          # 低风险规则
├── report/                     # 扫描报告输出目录
│   └── .gitkeep
└── testcases/                  # 测试用例
    └── malicious-example.js    # 混淆代码样本
```

## 案例检测

该工具可以检测多种已知的供应链攻击案例，包括:

1. **event-stream 事件 (2018)**:

   - 攻击者在流行包中注入窃取比特币钱包的代码
   - 特征: 动态 require、eval 字符串拼接等

2. **ua-parser-js 事件 (2021)**:

   - 攻击者劫持维护者账户发布恶意版本
   - 特征: 恶意安装脚本、混淆代码等

3. **高度混淆代码**:
   - 使用十六进制变量名和数组
   - 字符串拆分和重组
   - 函数解混淆逻辑

## 自定义规则

您可以在`rules/`目录下创建自定义规则。规则文件支持 YAML 和 JSON 格式:

```yaml
- rule_name: "example_rule"
  description: "示例规则"
  language: "javascript"
  pattern: "危险函数\\s*\\("
  severity: "high"
  context_lines: 2
```

## 案例输出

```
=== 检测结果 ===

发现 7 个可疑问题

[HIGH 级别问题] 共 3 个
--------------------------------------------------------------------------------
[HIGH] obfuscated_code_pattern
文件: ./testcases/malicious-example.js:5:12
描述: 高度混淆的代码模式

代码上下文:
  3   | var _0x12a3=['log','fetch','application/json','stringify','parse','env','TOKEN','concat','api.example.com/data'];
  4   | (function(_0x213a,_0x4f41){
> 5   |     var _0x3b2d=function(_0x14a3){
  6   |         while(--_0x14a3){
  7   |             _0x213a['push'](_0x213a['shift']());
--------------------------------------------------------------------------------

[MEDIUM 级别问题] 共 2 个
--------------------------------------------------------------------------------
[MEDIUM] environment_detection
文件: ./testcases/malicious-example.js:38:12
描述: 环境检测，可能用于沙箱逃逸

代码上下文:
  36  | // 4. 环境检测与沙箱逃逸
  37  | function checkEnvironment() {
> 38  |     if (process.env.CI || process.env.JENKINS || process.env.TRAVIS) {
  39  |         // 在CI环境中，不执行恶意代码
  40  |         return false;
--------------------------------------------------------------------------------

扫描完成，用时: 0.75 秒
```

## 贡献

欢迎提交 Issue 和 Pull Request 来改进此工具。如有任何问题或建议，请联系项目维护者。

## 许可

MIT
