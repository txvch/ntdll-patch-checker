## Ntdll PatchChecker

### 📌 Description

`Ntdll PatchChecker` is a Windows based tool written in Python that performs **in memory integrity checks** against critical `ntdll.dll` APIs (e.g., `NtReadFile`, `NtOpenProcess`, etc.) in the **SysMain service process**. It's designed to help identify hooks and patches by comparing memory pages of system functions.

This tool does not rely on WinDbg or external modules just pure `ctypes`, `pywin32`, and `psutil`.

### 🔬 How It Works
1. Locates the SysMain (SuperFetch) service process using Windows Service Control Manager
2. Opens the target process with appropriate memory read permissions using multiple fallback methods
3. Locates `ntdll.dll` in the target process using:
   - Standard `EnumProcessModules` API
   - Extended enumeration with different filtering flags
   - Manual memory scanning as a last resort when APIs fail
4. For each monitored API function:
   - Reads the first 16 bytes from the local (clean) ntdll.dll copy
   - Reads the corresponding bytes from the remote process memory
   - Performs byte-by-byte comparison of the first 16 bytes (function entry point)
5. Reports any differences found, showing potential hooks or modifications


## 🎮 Monitored Functions
```
File System APIs:
├── NtCreateFile       - Creates/opens files and directories
├── NtOpenFile         - Opens existing files  
├── NtReadFile         - Reads data from files
├── NtWriteFile        - Writes data to files
├── NtQueryInformationFile - Queries file metadata
└── NtSetInformationFile   - Modifies file metadata

Process Management APIs:
├── NtCreateProcess    - Creates new processes
├── NtCreateProcessEx  - Extended process creation
├── NtOpenProcess      - Opens existing processes
└── NtTerminateProcess - Terminates processes
```

## 🚀 Quick Start

### Prerequisites

- **Windows OS** (Any version **except Windows 11 24H2**)
- **Python 3.6+**
- **Administrator Privileges** (Required)
- **Dependencies**:
  ```bash
  pip install psutil pywin32
  ```

### Installation
```bash
git clone https://github.com/yourusername/windows-patch-detector.git
cd windows-patch-detector

pip install psutil pywin32
```

## 💻 Usage

### Basic Usage

```bash
# Must be run as Administrator
python patch_detector.py
```
### Understanding the Output
The tool provides detailed logging and results:
```
starting patch check...
----------------------------------------
[LOG] Looking for SysMain PID
[LOG] Got SysMain at PID 1234
Found SysMain at PID 1234
[LOG] listing modules for PID 1234
ntdll at 0x7FFE12340000, size 2097152

NtCreateFile (0x7ffb933edf80):
  Patch detected: 9/16 bytes changed
  Clean: 4C8BD1B855000000F604250803FE7F01
  Dirty: 48B8220000C000000000C30803FE7F01
NtOpenFile: clean
NtReadFile: clean
NtWriteFile: clean
NtQueryInformationFile: clean
NtSetInformationFile: clean
NtCreateProcess: clean
NtCreateProcessEx: clean
NtOpenProcess: clean
NtTerminateProcess: clean

Done:
----------------------------------------
Result: Found 1 patched functions!
```

## 🔍 Technical Implementation Details

### Process Access Methods
The tool uses a multi layered approach to gain process access:

1. **Primary**: `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` (0x0410)
2. **Fallback 1**: `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` (0x1010)  
3. **Fallback 2**: `PROCESS_VM_READ` only (0x0010)
4. **Last Resort**: `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000)

### Module Discovery Methods

**Method 1: Standard Enumeration**
- Uses `EnumProcessModules` API
- Most reliable on older Windows versions

**Method 2: Extended Enumeration**  
- Uses `EnumProcessModulesEx` with different filter flags:
  - `LIST_MODULES_ALL` (0x03)
  - `LIST_MODULES_DEFAULT` (0x01)  
  - `LIST_MODULES_32BIT` (0x02)

**Method 3: Manual Memory Scanning**
- Scans process memory regions using `VirtualQueryEx`
- Looks for PE headers (MZ signature)
- Searches for ntdll.dll strings in memory
- Used when API-based methods fail

### Patch Detection Algorithm

The tool compares the first 16 bytes of each functions entry point:
- Reads 64 bytes total but focuses on first 16 for comparison
- Counts byte by byte differences
- Reports any modifications found
- Shows both clean and "dirty" (modified) hex dumps

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional API functions to monitor
- Support for other target processes besides SysMain
- Enhanced bypass techniques for protected processes
- Better signature analysis and pattern matching

  **Disclaimer**: This tool is for authorized testing and research only. Unauthorized use against systems you do not own or have explicit permission to
