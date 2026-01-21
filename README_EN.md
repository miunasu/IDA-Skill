# IDA Skill for AI Agent

English | [中文](README.md)

> 🤖 Enable AI Agents to analyze malware like security analysts

## What is this?

This is an **AI Agent skill** that enables AI to automatically analyze malware using IDA Pro, just like human security analysts:

- 🔍 **Automatic Malicious Behavior Detection** - Analyze C2 communication, process injection, persistence mechanisms, and malicious behaviors
- 🧩 **Understand Code Functionality** - Automatically analyze function logic, identify encryption algorithms, and trace data flows
- 📊 **Extract Key Information** - Import tables, strings, opcode features, YARA rules
- 🎯 **Locate Threat Indicators** - IP addresses, domains, file paths, registry keys

## Demo Video

Demonstration using my multi-agent framework Spore: Since the video embedded in the readme file failed to upload, please download movie.mp4.

## How to Use?

**Super simple! Just 3 steps:**

### 1️⃣ Configure IDA Path

Edit `config.json`:

```json
{
  "idat_path": "C:/Program Files/IDA Pro 9.0/idat64.exe"
}
```

### 2️⃣ Let AI Agent Use the Skill

Simply place the IDA Skill in your skill folder.

### 3️⃣ Start Analysis

AI Agent will automatically:
- Initialize IDA database
- Extract import tables, strings, decompiled code
- Perform reverse analysis like a human
- Analyze functionality and extract C2
- Identify encryption algorithms and suspicious behaviors
- Generate analysis reports

**That's it!** 🎉

## Built-in Tools

This skill package integrates multiple powerful analysis tools that the Agent will automatically invoke:

### 🤖 REAI - AI Function Analysis

> Based on my open-source project [REAI](https://github.com/miunasu/REAI_IDA)

**Features:** Use LLM to automatically understand function functionality and recursively analyze call chains
- Automatically identify function purposes (e.g., "decrypt config", "connect to C2")
- Automatically rename functions (`sub_401000` → `AI_decrypt_config`)
- Add comments at call sites explaining sub-function purposes

**Configuration:** Edit `tools/reai.py` to set your LLM API

```python
API_KEY = "sk-..."           # Your API key
API_URL = "https://..."      # API endpoint (supports OpenAI/Azure/DeepSeek/local models)
MODEL = "gpt-4"              # Model name
```

---

### 🔍 FindCrypt - Cryptographic Algorithm Detection

> Based on the open-source FindCrypt project

**Features:** Automatically detect cryptographic constants in code
- Supported algorithms: AES, DES, RC4, Blowfish, TEA
- Supported hashes: MD5, SHA1, SHA256
- Supported encodings: Base64, CRC32

---

### 📝 mkYARA - YARA Rule Generation

> Based on the open-source mkYARA project

**Features:** Generate threat detection rules from code snippets
- Support multiple matching modes (strict/normal/loose)
- Automatically extract signature code
- Generate YARA rules for threat detection

---

### 💾 Dump - Memory Export

**Features:** Extract code or data for external analysis
- Support exporting address ranges, segments, functions
- Support multiple formats (raw, hex, c_array, python)

---

### 📊 Export Check - Export Table Analysis

**Features:** Detect abnormal DLL export functions
- Analyze export function sizes
- Identify abnormal export patterns

## FAQ

### Q: Do I need to know IDAPython?

A: **No!** Just let the AI Agent read `SKILL.md`, and the Agent will automatically use these tools. You only need to describe your requirements in natural language.

### Q: Can I use it commercially?

A: **No.** This project is licensed under GPL-3.0 for educational and research purposes only. Commercial use is prohibited. Please contact the author for commercial licensing.

## License

**GPL-3.0 License** - See [LICENSE](LICENSE) file for details

This project is licensed under GPL-3.0, **for educational and research purposes only, commercial use is prohibited**.

- ✅ Free to use, modify, and distribute
- ✅ Must remain open-source, derivative works must also use GPL-3.0
- ❌ Commercial use prohibited
- ❌ Closed-source use prohibited

**Disclaimer:** When using this project for reverse engineering, you must comply with all applicable laws and regulations, including software license agreements. The author is not responsible for any consequences arising from the use of this project.
