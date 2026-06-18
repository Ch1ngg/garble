# Garble 增强混淆改造设计

## 概述

对 garble Go 代码混淆器进行深度改造，达成两个目标：

1. **绕过 AV 误报** — 让 garble 产出的二进制不被常见杀软（360、火绒、Defender 等）误报
2. **防止逆向工程** — 增加反编译/逆向的难度

## 改造范围

| 阶段 | 改动 | 改动量 | 上游冲突风险 |
|------|------|--------|-------------|
| P-1 | **清除硬编码 garble 特征（前置必做）** | ~30 行 | 低 |
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

## 实施顺序

```
Phase 0: P-1（清除硬编码 garble 特征）→ 验证二进制中无 garble 字符串
Phase 1: P0（字符串加密）→ 验证 AV 误报是否解决
Phase 2: P1（名字格式）→ 验证逆向难度提升
Phase 3: P2（控制流）→ 验证编译正确性
Phase 4: P3（死代码 + PE）→ 验证整体效果
```

每个阶段完成后独立测试，确认无误再进入下一阶段。

## 验证方法

- **AV 测试**：用 VirusTotal 检查 garble 产出的二进制
- **功能测试**：garble 现有测试套件（`go test ./...`）
- **逆向测试**：用 `go tool objdump` 和 IDA/Ghidra 尝试分析混淆后的二进制
- **性能测试**：对比混淆前后的编译时间和二进制大小
