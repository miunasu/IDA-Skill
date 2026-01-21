# IDA Skill for AI Agent

[English](README_EN.md) | 中文

> 🤖 让 AI Agent 像安全分析师一样分析恶意样本

## 这是什么？

这是一个 **AI Agent skill**，让 AI 能够使用 IDA Pro 自动分析恶意软件，就像人类安全分析师一样：

- 🔍 **自动识别恶意行为** - 分析 C2 通信、进程注入、持久化机制、恶意行为
- 🧩 **理解代码功能** - 自动分析函数逻辑、识别加密算法、追踪数据流
- 📊 **提取关键信息** - 导入表、字符串、操作码特征、YARA 规则
- 🎯 **定位威胁指标** - IP 地址、域名、文件路径、注册表键值

## 演示视频

使用我的多agent框架Spore进行演示：
由于readme内嵌视频上传失败，请下载movie.mp4。

## 如何使用？

**超级简单！只需 3 步：**

### 1️⃣ 配置 IDA 路径

编辑 `config.json`：

```json
{
  "idat_path": "C:/Program Files/IDA Pro 9.0/idat64.exe"
}
```

### 2️⃣ 让 AI Agent 使用skill

将 IDA Skill 放在你的skill文件夹即可。

### 3️⃣ 开始分析

AI Agent 会自动：
- 初始化 IDA 数据库
- 提取导入表、字符串、反编译代码
- 像人类一样进行逆向分析
- 分析功能、提取C2
- 识别加密算法和可疑行为
- 生成分析报告

**就这么简单！** 🎉

## 内置工具

这个技能包集成了多个强大的分析工具，Agent 会自动调用它们：

### 🤖 REAI - AI 函数分析

> 基于我的开源项目 [REAI](https://github.com/miunasu/REAI_IDA)

**功能：** 使用 LLM 自动理解函数功能，递归分析调用链
- 自动识别函数功能（如"解密配置"、"连接 C2"）
- 自动重命名函数（`sub_401000` → `AI_decrypt_config`）
- 在调用处添加注释说明子函数作用

**配置：** 编辑 `tools/reai.py` 设置你的 LLM API

```python
API_KEY = "sk-..."           # 你的 API 密钥
API_URL = "https://..."      # API 地址（支持 OpenAI/Azure/deepseek/本地模型）
MODEL = "gpt-4"              # 模型名称
```

---

### 🔍 FindCrypt - 加密算法识别

> 基于开源项目 FindCrypt

**功能：** 自动检测代码中的加密常量
- 支持算法：AES, DES, RC4, Blowfish, TEA
- 支持哈希：MD5, SHA1, SHA256
- 支持编码：Base64, CRC32

---

### 📝 mkYARA - YARA 规则生成

> 基于开源项目 mkYARA

**功能：** 从代码片段生成威胁检测规则
- 支持多种匹配模式（strict/normal/loose）
- 自动提取特征代码
- 生成可用于威胁检测的 YARA 规则

---

### 💾 Dump - 内存导出

**功能：** 提取代码或数据用于外部分析
- 支持导出地址范围、段、函数
- 支持多种格式（raw, hex, c_array, python）

---

### 📊 Export Check - 导出表分析

**功能：** 检测 DLL 异常导出函数
- 分析导出函数大小
- 识别异常导出模式

## 常见问题

### Q: 我需要懂 IDAPython 吗？

A: **不需要！** 只要让 AI Agent 读取 `SKILL.md`，Agent 会自动使用这些工具。你只需要用自然语言描述需求。

### Q: 可以商用吗？

A: **不可以。** 本项目采用 GPL-3.0 许可证，仅供学习和研究使用，禁止商业用途。如需商业使用，请联系作者获取授权。

## 许可证

**GPL-3.0 License** - 详见 [LICENSE](LICENSE) 文件

本项目采用 GPL-3.0 许可证，**仅供学习和研究使用，禁止商业用途**。

- ✅ 可以自由使用、修改和分发
- ✅ 必须保持开源，衍生作品也必须使用 GPL-3.0
- ❌ 禁止用于商业目的
- ❌ 禁止闭源使用

**免责声明：** 使用本项目进行逆向分析时，请遵守相关法律法规和软件许可协议。作者不对使用本项目造成的任何后果负责。
