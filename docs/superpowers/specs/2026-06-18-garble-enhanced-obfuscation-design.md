# Garble 增强混淆改造设计

## 概述

对 garble Go 代码混淆器进行深度改造，达成两个目标：

1. **绕过 AV 误报** — 让 garble 产出的二进制不被常见杀软（360、火绒、Defender 等）误报
2. **防止逆向工程** — 增加反编译/逆向的难度

## 改造范围

| 阶段 | 改动 | 改动量 | 上游冲突风险 |
|------|------|--------|-------------|
| P-1 | **清除硬编码 garble 特征（前置必做）** | ~30 行 | 低 |
| P-2 | **Go 二进制结构暴露修复** | ~150 行 | 中 |
| P-3 | **运行时行为特征掩盖** | ~100 行 | 中 |
| P-4 | **Windows PE 特征处理** | ~200 行 | 中 |
| P0 | 自定义字符串加密算法 | ~300 行 | 极低 |
| P1 | 名字哈希输出格式：前缀 + 哈希 | ~80 行 | 极低 |
| P2 | 控制流平坦化默认开启 | ~20 行 | 低 |
| P3 | 死代码注入增强 + PE 清理 | ~400 行 | 中等 |

## 约束

- **目标平台**：Windows + Linux
- **使用方式**：私用（仅自己），不对外发布
- **开发者经验**：Go 日常开发者，不熟悉 go/ast、go/ssa 内部
- **上游同步**：需要保持与 burrowers/garble 上游的可同步性

## 上游同步策略

```
origin   → Ch1ngg/garble（个人 fork）
upstream → burrowers/garble（官方）
```

同步流程：
```bash
git fetch upstream
git rebase upstream/master
git push origin master --force-with-lease
```

原则：自定义改动集中到尽量少的文件里，减少冲突面。

---

## P-1：清除硬编码 garble 特征（前置必做）

### 目标

**最低要求**：garble 编译产出的二进制中不能搜到 `garble` 字符串。这是所有改造的前提。

### 问题

当前 garble 在多处硬编码了 `garble` 字符串，这些字符串会直接出现在编译后的二进制中：

| 位置 | 硬编码字符串 | 严重度 |
|------|-------------|--------|
| `internal/literals/obfuscators.go:153` | `"garbleExternalKey"` | 致命 |
| `internal/ctrlflow/ctrlflow.go:24` | `"___garble_import"` | 致命 |
| `internal/ctrlflow/hardening.go:36` | `"_garble"` | 致命 |
| `hash.go:88` | `"+garble buildID=_/_/_/"` | 高 |

### 改动方案

#### 1. External Key 变量名（`obfuscators.go:153`）

```go
// 改前：
name: "garbleExternalKey" + strconv.Itoa(idx)

// 改后：
name: "extKey" + strconv.Itoa(idx) + "_" + randomHexString(rand, 4)
```

用随机后缀替代固定的 `garble` 前缀，每次编译产出不同名字。

#### 2. Import 前缀（`ctrlflow.go:24`）

```go
// 改前：
importPrefix = "___garble_import"

// 改后：
importPrefix = "___imp_"  // 或随机生成
```

#### 3. Hardening 前缀（`hardening.go:36`）

```go
// 改前：
return "_garble" + strconv.FormatUint(rnd.Uint64(), 32)

// 改后：
return "_" + strconv.FormatUint(rnd.Uint64(), 32)
```

#### 4. buildID 格式（`hash.go:88`）

```go
// 改前：
fmt.Printf("%s +garble buildID=_/_/_/%s\n", line, encodeBuildIDHash(contentID))

// 改后：
fmt.Printf("%s buildID=_/_/_/%s\n", line, encodeBuildIDHash(contentID))
```

去掉 `+garble` 前缀，只保留 `buildID=_/_/_/`（这是 Go 编译器的标准格式）。

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `internal/literals/obfuscators.go` | **改 1 行** | External Key 变量名加随机后缀 |
| `internal/ctrlflow/ctrlflow.go` | **改 1 行** | Import 前缀去掉 `garble` |
| `internal/ctrlflow/hardening.go` | **改 1 行** | Hardening 前缀去掉 `garble` |
| `hash.go` | **改 1 行** | buildID 格式去掉 `+garble` |

### 验证

```bash
# 编译一个简单项目
echo 'package main; func main(){}' > /tmp/test.go
go run . build -o /tmp/test.bin /tmp/test.go

# 搜索 garble 字符串
strings /tmp/test.bin | grep -i garble
# 预期：无输出
```

### 上游冲突风险

低。每个文件只改一行，且改动是纯重命名，不影响逻辑。

---

## P0：自定义字符串加密算法

### 目标

替换 garble 现有的 5 种字符串加密算法，使用自定义的多轮混合加密，让 AV 无法匹配已知的解密函数模式。

### 现有架构

加密算法通过 `obfuscator` 接口实现（`internal/literals/obfuscators.go`）：

```go
type obfuscator interface {
    obfuscate(rand *mathrand.Rand, data []byte, extKeys []*externalKey) *ast.BlockStmt
}
```

每个算法接收原始字节 + 外部密钥，返回一个 Go AST 代码块（运行时解密逻辑）。

现有 5 种算法：

| 算法 | 文件 | 核心思路 | AV 可匹配的特征 |
|------|------|---------|----------------|
| simple | simple.go | 随机 key XOR | `for i, b := range key { data[i] ^= b }` |
| seed | seed.go | 级联 XOR | 嵌套函数调用 `fnc(x)(y)(z)...` |
| split | split.go | 随机分块 XOR | `switch { case 0: ... case 1: ... }` |
| shuffle | shuffle.go | XOR + 字节洗牌 | 洗牌/反洗牌索引数组 |
| swap | swap.go | 位置置换 | 索引重排 |

### 新算法：多轮混合加密

使用 3 层变换，生成与现有 5 种算法完全不同的 AST 结构：

**加密过程（编译时，在 obfuscate() 中执行）：**

1. **第 1 层：S-Box 字节替换**
   - 随机生成 256 字节的置换表（每个值 0-255 恰好出现一次）
   - 用 S-Box 替换每个字节

2. **第 2 层：字节位置循环移位**
   - 每 N 字节为一组（N 随机，8-16）
   - 每组内循环左移 R 位（R 随机，1-7）

3. **第 3 层：多密钥 XOR**
   - 使用 externalKeys 的值，每个字节用不同密钥字节做 XOR

**解密 AST（运行时，在二进制中执行）：**

```go
func() []byte {
    // 1. 加载加密数据
    data := []byte{...加密后的字节...}

    // 2. 反向第 3 层：XOR 解密
    for i := range data {
        data[i] = data[i] ^ key[i%len(key)]
    }

    // 3. 反向第 2 层：反向循环移位
    for i := 0; i < len(data); i += chunkSize {
        // 循环右移 R 位（与加密时的左移相反）
        rotated := make([]byte, chunkSize)
        for j := 0; j < chunkSize; j++ {
            rotated[(j+shift)%chunkSize] = data[i+j]
        }
        copy(data[i:i+chunkSize], rotated)
    }

    // 4. 反向第 1 层：S-Box 反向替换
    invSbox := [256]byte{...根据 S-Box 计算的逆表...}
    for i := range data {
        data[i] = invSbox[data[i]]
    }

    // 5. 去除 junk 填充（由 obfuscateString 添加）
    return data[start:end]
}()
```

### 为什么这个模式难被 AV 识别

- 现有 5 种算法的解密代码模式已经入库（range XOR、嵌套函数、switch/case 等）
- 新算法用 **S-Box 查表 + 三重变换**，生成的机器码模式完全不同
- S-Box 的随机填充让每次编译产出的字节序列都不一样

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `internal/literals/custom.go` | **新增** | custom 结构体实现 obfuscator 接口（多轮混合加密） |
| `internal/literals/obfuscators.go` | **改 1 行** | 在 Obfuscators 切片中注册新算法 |

### 上游冲突风险

极低。新增文件不会冲突，`obfuscators.go` 只改一行注册，上游很少改动这里。

---

## P1：名字哈希输出格式

### 目标

将 garble 的标识符混淆输出从 base62 改为"前缀 + 哈希"格式，消除哈希值的可识别特征。

### 现有输出

```go
// hash.go hashWithPackage() 输出
// ProcessData → aB3xK9mQ（base62，全字母数字）
```

特征：全是 `[a-zA-Z0-9]`，长度固定，容易被归类为 garble 产物。

### 新输出格式

```
obf_7a3f8e1b2c4d
```

- 固定前缀 `obf_`（可通过 CLI flag 配置）
- 哈希值截断为 12 个十六进制字符
- 示例：`ProcessData` → `obf_7a3f8e1b2c4d`

### 为什么这个格式好

- **工具兼容性**：合法的 Go 标识符，所有工具都能处理
- **不可逆**：无法从 `obf_7a3f8e1b2c4d` 反推出原始名
- **唯一性**：SHA256 碰撞概率为零
- **长度固定**：所有混淆后名字长度一致

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `hash.go` | **改 `hashWithPackage()` 函数** | 修改输出编码，~30 行 |

### 上游冲突风险

极低。只改 `hash.go` 里的一个函数，上游很少改这里。

---

## P2：控制流平坦化默认开启

### 目标

去掉控制流平坦化的实验性门控，默认启用 CFG flattening。

### 现有行为

需要同时满足：
1. 源码里加 `//garble:controlflow` 指令
2. 设置环境变量 `GARBLE_EXPERIMENTAL_CONTROLFLOW=1`

### 改后行为

去掉环境变量检查，只要有 `//garble:controlflow` 指令就启用。

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `main.go` | **改 1 处** | 去掉 `GARBLE_EXPERIMENTAL_CONTROLFLOW` 环境变量检查 |
| `internal/ctrlflow/ctrlflow.go` | **改 1 处** | 去掉 experimental 标记 |

### 风险

SSA-to-AST 转换（`internal/ssa2ast/func.go`，1193 行）是 garble 最复杂的部分。启用后如果编译出错，需要调试 SSA 转换逻辑。建议先用简单项目测试。

### 上游冲突风险

低。改动量很小，但上游可能在未来版本中修改控制流相关的代码。

---

## P3：死代码注入增强 + PE 清理

### 目标

增加垃圾代码的多样性，清除更多 Go 二进制特征。

### 死代码增强

增强 `internal/ctrlflow/trash.go`，增加更多垃圾代码模式：

| 新模式 | 示例 | 效果 |
|--------|------|------|
| 假 HTTP 请求 | `http.Get("http://...")` | 逆向者误以为有网络通信逻辑 |
| 假数据库操作 | `sql.Open(...)` | 误以为有数据库交互 |
| 假网络连接 | `net.Dial(...)` | 误以为有 TCP 连接 |
| 假文件操作 | `os.Open(...)` | 误以为有文件读写 |
| 假加密操作 | `aes.NewCipher(...)` | 误以为有加密逻辑 |

这些假代码只在死代码块中生成，永远不会执行。

### PE/二进制清理

增强 `runtime_patch.go` 和 `position.go`：

| 清理项 | 说明 |
|--------|------|
| 清除 `go.buildid` 段 | 移除 Go 编译器嵌入的 build ID |
| 修改 `.gopclntab` magic number | 防止 `go tool objdump` 等工具分析 |
| 清除编译时间戳 | 移除嵌入的时间信息 |
| 清除调试段 | `.gosymtab` 等调试信息段 |

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `internal/ctrlflow/trash.go` | **增强** | 增加 5 种新垃圾代码模式 |
| `runtime_patch.go` | **增强** | 清除更多 Go 二进制特征 |
| `position.go` | **增强** | 清除更多调试信息 |

### 上游冲突风险

中等。`trash.go` 和 `runtime_patch.go` 上游偶尔会改，但冲突应该容易解决。

---

## P-2：Go 二进制结构暴露修复

### 目标

消除 Go 编译产物中可被自动化工具识别的结构特征，让工具链（IDA、Ghidra、Detect-It-Easy）无法通过段名、版本字符串等特征识别这是 Go 二进制。

### 问题

Go 编译器会嵌入以下特有结构，garble 完全没动：

| 特征 | 位置 | 可识别性 |
|------|------|---------|
| `.gosymtab` 段名 | ELF/PE 段表 | 100% 识别为 Go |
| `.gopclntab` 段名 | ELF/PE 段表 | 100% 识别为 Go |
| `.typelink` 段名 | ELF/PE 段表 | 100% 识别为 Go |
| `.itablink` 段名 | ELF/PE 段表 | 100% 识别为 Go |
| `go1.26.1` 版本字符串 | runtime 内嵌 | 暴露 Go 版本 |
| `go.buildid` | ELF note 段 | 追踪编译环境 |
| 模块路径 | `runtime.modinfo` | 识别项目 |

### 改动方案

#### 1. 段名随机化

在链接阶段（`transformLink`），通过修改 Go linker 源码的段名常量：

```go
// 改前（Go 编译器内部）：
const symtabSection = ".gosymtab"
const pclntabSection = ".gopclntab"

// 改后：
// 用 linker patch 把段名改为随机值
const symtabSection = ".data1"    // 伪装成普通数据段
const pclntabSection = ".data2"   // 伪装成普通数据段
```

或者更彻底：改为 `.rdata`、`.bss` 等 Windows/Linux 通用段名。

#### 2. 清除版本字符串

在 `runtime_patch.go` 中，扫描 runtime 包的源码，替换 Go 版本字符串：

```go
// 替换 "go1.26.1" 为 ""
// 或替换为 "go1.0.0" 这种无意义的值
```

#### 3. 清除模块信息

在链接阶段清除 `runtime.modinfo` 中的模块路径和版本信息。

#### 4. 清除 `go.buildid`

在链接阶段移除或覆盖 `.note.go.buildid` ELF note。

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `runtime_patch.go` | **增强** | 清除版本字符串、模块信息 |
| `internal/linker/patches/` | **新增 patch** | 段名随机化、buildid 清除 |
| `transformer.go` transformLink() | **增强** | 调用新的 patch 逻辑 |

### 难度评估

- 段名随机化：中等，需要写 linker patch 文件
- 版本字符串清除：低，runtime_patch.go 已有类似逻辑
- 模块信息清除：低，链接器有 `-X` 机制可覆盖

### 上游冲突风险

中等。linker patch 文件上游会随 Go 版本更新而更新，但段名常量本身很少改。

---

## P-3：运行时行为特征掩盖

### 目标

让 `.gopclntab` 的函数边界信息无法被提取，减少运行时可被分析的元数据。

### 问题

`.gopclntab` 中存储了所有函数的起始地址、大小、名称映射。garble 只改了 magic number，但结构本身完整保留。工具更新后仍然可以解析。

### 改动方案

#### 1. `.gopclntab` 深度混淆

在 `runtime_patch.go` 中，不仅改 magic number，还要：

- **打乱函数顺序** — 在 PCLN 表中随机重排函数条目
- **插入空函数** — 在表中插入无意义的空函数记录
- **模糊函数名映射** — 把函数名指针指向随机偏移或空字符串

#### 2. 标准库函数名残留处理

garble 不混淆标准库函数名（因为是共享代码）。但可以在最终二进制中：

- 用空字符串替换标准库函数名（不影响运行，因为 Go 运行时不依赖这些名字做函数查找）
- 或者把函数名替换为混淆后的名字（需要改 linker）

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `runtime_patch.go` | **大幅增强** | PCLN 表深度混淆 |
| `internal/linker/patches/` | **增强** | 函数名清除 patch |

### 难度评估

高。PCLN 表结构复杂，需要深入理解 Go runtime 的 pc-value table 编码格式。

### 上游冲突风险

中高。PCLN 表格式可能随 Go 版本变化。

---

## P-4：Windows PE 特征处理

### 目标

处理 Windows PE 格式特有的 Go 特征，减少在 Windows 平台上的可识别性。

### 问题

| 特征 | 说明 | 可识别性 |
|------|------|---------|
| PE 导入表 | IAT 直接列出 Windows API（`CreateFileW`、`WSAConnect` 等） | 暴露功能意图 |
| 非标准段名 | `.gosymtab`、`.gopclntab` 在 PE 中非常显眼 | 100% 识别为 Go |
| PE 子系统 | Go 程序通常是 `CONSOLE` 或 `WINDOWS` 子系统 | 中等 |

### 改动方案

#### 1. PE 段名伪装

在链接阶段把 PE 段名改为标准的 Windows PE 段名：

```go
// 改前：.gosymtab, .gopclntab
// 改后：.rdata, .pdata（标准 Windows PE 段名）
```

#### 2. 导入表函数排序随机化

Go linker 生成的导入表按字母序排列，可以随机化顺序。

#### 3. PE 时间戳清除

Go linker 会把编译时间戳写入 PE 头，需要清零或随机化。

### 改动文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `internal/linker/patches/` | **新增** | PE 段名伪装、时间戳清除 patch |
| `transformer.go` transformLink() | **增强** | 平台相关的 PE 处理 |

### 难度评估

中高。需要理解 PE 格式和 Go linker 的 PE 生成逻辑。

### 上游冲突风险

中等。linker patch 需要随 Go 版本更新。

---

## 实施顺序

```
Phase 0: P-1（清除硬编码 garble 特征）     → 验证二进制中无 garble 字符串
Phase 1: P-2（Go 二进制结构暴露修复）      → 验证段名、版本字符串已清除
Phase 2: P-3（运行时行为特征掩盖）         → 验证 PCLN 表无法解析函数边界
Phase 3: P-4（Windows PE 特征处理）        → 验证 PE 导入表和段名已伪装
Phase 4: P0  （自定义字符串加密）          → 验证 AV 误报是否解决
Phase 5: P1  （名字格式）                  → 验证逆向难度提升
Phase 6: P2  （控制流平坦化）              → 验证编译正确性
Phase 7: P3  （死代码 + PE）               → 验证整体效果
```

每个阶段完成后独立测试，确认无误再进入下一阶段。阶段 0-3 是消除已知特征（防御性），阶段 4-7 是增加新混淆（进攻性）。

## 验证方法

- **AV 测试**：用 VirusTotal 检查 garble 产出的二进制
- **功能测试**：garble 现有测试套件（`go test ./...`）
- **逆向测试**：用 `go tool objdump` 和 IDA/Ghidra 尝试分析混淆后的二进制
- **特征测试**：`strings <binary> | grep -iE "garble|gosymtab|gopclntab|go1\."` 验证无已知特征
- **性能测试**：对比混淆前后的编译时间和二进制大小
