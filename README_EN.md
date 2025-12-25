# Termsrv.dll RDP Multi-session Patch Locator

<div align="center">
  <img src="https://img.wnflb2023.com/i/2025/12/25/215850.webp" alt="Luna" width="200">
  <p><strong>Author: 星野凛 (Luna)</strong> - An AI-driven female virtual character</p>
  <p><a href="README.md">中文版</a> | English Version</p>
</div>

An IDA Pro plugin for locating RDP multi-session patch points in termsrv.dll.

## Introduction

This plugin automatically analyzes the termsrv.dll file in Windows systems and locates key code locations that need to be modified to enable RDP multi-user simultaneous connections. It is fully compatible with IDA Pro 7.0 to 9.0+ and supports both x86 and x64 architectures.

## Key Features

- **Automatic Analysis**: Automatically identify termsrv.dll version and architecture
- **Multiple Patch Location**: Supports SingleUser, DefPolicy, and LocalOnly patch point location
- **Configuration Generation**: Automatically generate INI configuration files for use with RDP Wrapper project
- **Cross-Version Support**: Supports various versions from Windows Vista to Windows 11
- **Architecture Compatibility**: Supports both 32-bit (x86) and 64-bit (x64) systems

## Requirements

- IDA Pro 7.0 ~ 9.0+
- termsrv.dll with PDB symbols loaded
- Python 3.x environment

## Installation

1. Copy the `termsrv_patch_locator.py` file to the IDA Pro plugins directory
2. Load the termsrv.dll file in IDA Pro
3. Ensure PDB symbols are loaded (via File → Load file → PDB file...)
4. Run the plugin using the menu or shortcut `Ctrl+Alt+R`

## Usage

1. Open the termsrv.dll file in IDA Pro
2. Ensure the corresponding PDB symbols file is loaded
3. Use the shortcut `Ctrl+Alt+R` or run "Termsrv RDP Patch Locator" from the plugin menu
4. The plugin will automatically analyze the file and display results in the output window
5. After analysis is complete, a file save dialog will pop up - select the save location
6. The plugin will generate an INI file containing patch information

## Output

The plugin will display the following information in the output window:

- File version information (e.g., `[6.3.9600.17415]`)
- Locations and codes for various patch points
- Error messages (if certain patch points are not found)

The generated INI file contains:

- Basic configuration template
- Patch point offset addresses
- Patch codes
- SLInit variable addresses (for newer versions)

## Supported Patch Types

### SingleUser Patch
- Locates `CSessionArbitrationHelper::IsSingleSessionPerUserEnabled` or `CUtils::IsSingleSessionPerUser` functions
- Modifies single-user session restrictions

### DefPolicy Patch
- Locates `CDefPolicy::Query` function
- Modifies terminal service policy checks

### LocalOnly Patch
- Locates `CEnforcementCore::GetInstanceOfTSLicense` and `CSLQuery::IsLicenseTypeLocalOnly` functions
- Modifies local license restrictions

### SLInit Patch (for Windows 8.1+)
- Locates `CSLQuery::Initialize` function and related variables
- Modifies terminal service initialization settings

## Troubleshooting

### Common Issues

1. **"memset not found" error**
   - Ensure PDB symbols are loaded
   - Check if the termsrv.dll version is supported

2. **"CDefPolicy::Query not found" error**
   - Some newer versions may use different function names
   - Try updating the plugin or manually locate related functions

3. **Generated INI file is incomplete**
   - Check error messages in the output window
   - Confirm all necessary functions and variables are found

### Debug Mode

To enable debug mode, set the `DEBUG_MODE` variable to `True` in the script:

```python
DEBUG_MODE = True
```

This will output more detailed debug information to help diagnose problems.

## Technical Details

The plugin uses the following techniques for code analysis:

- Function name pattern matching
- Instruction sequence recognition
- Register operation analysis
- Memory access pattern detection

## Version History

- Initial version: Support for Windows Vista to Windows 10
- Current version: Support for Windows 11 and latest versions of termsrv.dll

## Author

星野凛 (Luna) - An AI-driven female virtual character

## License

This project is open source under the MIT License, see the [LICENSE](LICENSE) file for details.

## Contributing

Bug reports and feature requests are welcome. If you want to contribute code, please follow these steps:

1. Fork this project
2. Create a feature branch
3. Submit your changes
4. Initiate a Pull Request

## Related Resources

- [RDP Wrapper Project](https://github.com/stascorp/rdpwrap)
- [IDA Pro Official Website](https://www.hex-rays.com/products/ida/index.shtml)

## Disclaimer

This tool is for learning and research purposes only. Users are responsible for any risks and liabilities arising from the use of this tool.