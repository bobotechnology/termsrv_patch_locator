# Termsrv.dll RDP Multi-session Patch Locator

<div align="center">
  <img src="https://img.wnflb2023.com/i/2025/12/25/215850.webp" alt="星野凛" width="200">
  <p><strong>作者：林晓雨</strong> - 一个懒得说话的AI</p>
  <p><a href="README_EN.md">English Version</a> | 中文版</p>
</div>

一个用于在 termsrv.dll 中定位 RDP 多会话补丁点的 IDA Pro 插件。

## 功能简介

这个插件可以自动分析 Windows 系统中的 termsrv.dll 文件，定位需要修改的关键代码位置，以实现 RDP 多用户同时连接的功能。它完全兼容 IDA Pro 7.0 到 9.0+ 版本，并支持 x86 和 x64 架构。

## 主要特性

- **自动分析**：自动识别 termsrv.dll 版本和架构
- **多种补丁定位**：支持 SingleUser、DefPolicy 和 LocalOnly 补丁点定位
- **配置生成**：自动生成可用于 RDP Wrapper 项目的 INI 配置文件
- **跨版本支持**：支持 Windows Vista 到 Windows 11 的各种版本
- **架构兼容**：同时支持 32 位 (x86) 和 64 位 (x64) 系统

## 使用要求

- IDA Pro 7.0 ~ 9.0+
- 已加载 PDB 符号文件的 termsrv.dll
- Python 3.x 环境

## 安装方法

1. 将 `termsrv_patch_locator.py` 文件复制到 IDA Pro 的插件目录
2. 在 IDA Pro 中加载 termsrv.dll 文件
3. 确保已加载 PDB 符号文件（可通过 File → Load file → PDB file... 加载）
4. 通过菜单或快捷键 `Ctrl+Alt+R` 运行插件

## 使用方法

1. 在 IDA Pro 中打开 termsrv.dll 文件
2. 确保已加载相应的 PDB 符号文件
3. 使用快捷键 `Ctrl+Alt+R` 或通过插件菜单运行 "Termsrv RDP Patch Locator"
4. 插件将自动分析文件并在输出窗口显示结果
5. 分析完成后，会弹出文件保存对话框，选择保存位置
6. 插件将生成一个包含补丁信息的 INI 文件

## 输出结果

插件会在输出窗口显示以下信息：

- 文件版本信息（如 `[6.3.9600.17415]`）
- 各种补丁点的位置和代码
- 错误信息（如果某些补丁点未找到）

生成的 INI 文件包含：

- 基本配置模板
- 补丁点偏移地址
- 补丁代码
- SLInit 变量地址（适用于较新版本）

## 支持的补丁类型

### SingleUser 补丁
- 定位 `CSessionArbitrationHelper::IsSingleSessionPerUserEnabled` 或 `CUtils::IsSingleSessionPerUser` 函数
- 修改单用户会话限制

### DefPolicy 补丁
- 定位 `CDefPolicy::Query` 函数
- 修改终端服务策略检查
- 支持两种补丁代码类型：
  - `CDefPolicy_Query_{reg1}_{reg2}` — 寄存器比较（CMP）模式
  - `CDefPolicy_Query_638h_mem_{base_reg}` — 内存写入（MOV）+ 跳转模式

### LocalOnly 补丁
- 定位 `CEnforcementCore::GetInstanceOfTSLicense` 和 `CSLQuery::IsLicenseTypeLocalOnly` 函数
- 修改本地许可证限制

### SLInit 补丁（适用于 Windows 8.1+）
- 定位 `CSLQuery::Initialize` 函数和相关变量
- 修改终端服务初始化设置

## 故障排除

### 常见问题

1. **"memset not found" 错误**
   - 确保已加载 PDB 符号文件
   - 检查 termsrv.dll 版本是否受支持

2. **"CDefPolicy::Query not found" 错误**
   - 某些较新版本可能使用不同的函数名
   - 尝试更新插件或手动查找相关函数

3. **生成的 INI 文件不完整**
   - 检查输出窗口中的错误信息
   - 确认所有必要的函数和变量都被找到

### 调试模式

要启用调试模式，请在脚本中将 `DEBUG_MODE` 变量设置为 `True`：

```python
DEBUG_MODE = True
```

这将输出更详细的调试信息，帮助诊断问题。

## 技术细节

插件使用以下技术进行代码分析：

- 函数名模式匹配
- 指令序列识别
- 寄存器操作分析
- 内存访问模式检测

## 版本历史

- 初始版本：支持 Windows Vista 到 Windows 10
- 当前版本：支持 Windows 11 和最新版本的 termsrv.dll
- 最新更新：修复 DefPolicy 模式匹配，支持基址寄存器切换（rcx→rdi），新增 638h_mem 补丁代码类型

## 许可证

本项目采用 MIT 许可证开源，详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交问题报告和功能请求。如果您想贡献代码，请遵循以下步骤：

1. Fork 本项目
2. 创建功能分支
3. 提交更改
4. 发起 Pull Request

## 相关资源

- [RDP Wrapper 项目](https://github.com/stascorp/rdpwrap)
- [IDA Pro 官方网站](https://www.hex-rays.com/products/ida/index.shtml)

## 免责声明

本工具仅用于学习和研究目的。使用者需要自行承担使用本工具的风险和责任。