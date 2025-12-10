# HopperSRK - Hopper Security Researchers Kit v2.0.0

**Comprehensive security analysis suite for macOS binaries in Hopper Disassembler**

<center><img width="784" height="1168" alt="image" src="https://github.com/user-attachments/assets/ee51b1c6-f285-4595-b535-ac7f5ecddbb2" /></center>


Copyright © 2025 Zeyad Azima


## Overview


<img width="912" height="660" alt="image" src="https://github.com/user-attachments/assets/56e778e5-29f2-438f-add4-7d73cdcd40b6" />


HopperSRK is a collection of security analyzer plugins for Hopper Disassembler, designed for macOS malware analysis and binary security research.


## Plugins Included

- 1. File Operations Analyzer: 
Detects file system operations including read/write operations, file permissions, and suspicious file access patterns.

- 2. XPC/IPC Communication Analyzer: 
Analyzes XPC service connections and inter-process communication patterns.

- 3. Network Operations Analyzer: 
Identifies network-related APIs, sockets, connections, and suspicious network activity.

- 4. Mach IPC Analyzer: 
Detects Mach port operations and low-level IPC mechanisms.

- 5. Keychain & Credential Analyzer: 
Identifies keychain access, credential theft attempts, and sensitive data access.

- 6. Process Injection Detector: 
Detects code injection techniques including dylib injection, task_for_pid abuse, and memory manipulation.

- 7. Anti-Analysis Detector: 
Identifies anti-debugging, anti-VM, and anti-analysis techniques.

- 8. Persistence Analyzer: 
Detects persistence mechanisms including LaunchAgents, LaunchDaemons, and startup items.

- 9. C2 Communication Analyzer: 
Identifies command & control communication patterns and beaconing behavior.

- 10. Rootkit Detector: 
Detects rootkit behavior including kernel extension loading and system call hooking.

- 11. Privilege Escalation Detector: 
Identifies privilege escalation attempts and authorization bypass techniques.

- 12. System Call Analyzer: 
Analyzes direct system calls and syscall patterns.

## Requirements

- **Hopper Disassembler v4 or v5**
- **macOS 10.13+**
- **Xcode Command Line Tools** (for building)

  
## Installation

- Quick Install
```bash
git clone https://github.com/Zeyad-Azima/HopperSRK.git
cd HopperSRK
make install
```
- Output:

```ah
HopperSRK % make install

╔════════════════════════════════════════════════════════════════╗
║  HopperSRK - Hopper Security Researchers Kit v2.0.0          ║
║  Building All Security Analyzer Plugins                       ║
╚════════════════════════════════════════════════════════════════╝

[1/12] Building FileOpAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ FileOpAnalyzer built successfully

[2/12] Building XPCAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ XPCAnalyzer built successfully

[3/12] Building NetworkAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ NetworkAnalyzer built successfully

[4/12] Building MachIPCAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ MachIPCAnalyzer built successfully

[5/12] Building KeychainAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ KeychainAnalyzer built successfully

[6/12] Building ProcessInjectionAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ ProcessInjectionAnalyzer built successfully

[7/12] Building AntiAnalysisDetector...
make[1]: Nothing to be done for `all'.
  ✓ AntiAnalysisDetector built successfully

[8/12] Building PersistenceAnalyzer...
make[1]: Nothing to be done for `all'.
  ✓ PersistenceAnalyzer built successfully

[9/12] Building C2Analyzer...
[1/4] Creating bundle structure...
[2/4] Compiling plugin...
[3/4] Copying Info.plist...
[4/4] Build complete!
✓ Plugin bundle: build/C2Analyzer.hopperTool
  ✓ C2Analyzer built successfully

[10/12] Building RootkitDetector...
[1/4] Creating bundle structure...
[2/4] Compiling plugin...
[3/4] Copying Info.plist...
[4/4] Build complete!
✓ Plugin bundle: build/RootkitDetector.hopperTool
  ✓ RootkitDetector built successfully

[11/12] Building PrivilegeEscalationDetector...
[1/4] Creating bundle structure...
[2/4] Compiling plugin...
[3/4] Copying Info.plist...
[4/4] Build complete!
✓ Plugin bundle: build/PrivilegeEscalationDetector.hopperTool
  ✓ PrivilegeEscalationDetector built successfully

[12/12] Building SyscallAnalyzer...
[1/4] Creating bundle structure...
[2/4] Compiling plugin...
[3/4] Copying Info.plist...
[4/4] Build complete!
✓ Plugin bundle: build/SyscallAnalyzer.hopperTool
  ✓ SyscallAnalyzer built successfully

╔════════════════════════════════════════════════════════════════╗
║  All 12 Plugins Built Successfully!                           ║
╚════════════════════════════════════════════════════════════════╝


╔════════════════════════════════════════════════════════════════╗
║  Installing HopperSRK Plugins                                  ║
╚════════════════════════════════════════════════════════════════╝

[1/12] Installing FileOpAnalyzer...
Installing plugin...
✓ Plugin installed to v4: /Users/user/Library/Application\ Support/Hopper/Plugins/v4/Tools/FileOpAnalyzer.hopperTool
✓ Plugin installed to v5: /Users/user/Library/Application\ Support/Hopper/Plugins/v5/Tools/FileOpAnalyzer.hopperTool
<SNIP>
```

This will build and install all 12 plugins to:

Hopper v4: `~/Library/Application Support/Hopper/Plugins/v4/Tools/`

Hopper v5: `~/Library/Application Support/Hopper/Plugins/v5/Tools/`


- Individual Plugin Build
```bash
make FileOpAnalyzer        # Build only File Operations Analyzer
make NetworkAnalyzer       # Build only Network Analyzer
# etc...
```

- Clean Build Artifacts
```bash
make clean
```

---

## Usage

1. **Restart Hopper Disassembler** after installation
2. Load a binary for analysis
3. Access plugins via: **Tools → [Plugin Name]**
4. View analysis results in the log window

<img width="1702" height="820" alt="image" src="https://github.com/user-attachments/assets/12cc4a31-e71c-4027-aa8a-db1bab46cfa6" />




---

## Build System

The unified Makefile provides:
- ✅ Parallel builds for all plugins
- ✅ Automatic installation to Hopper v4 and v5
- ✅ Individual plugin builds
- ✅ Clean build management
- ✅ Colored output for easy monitoring

### Makefile Targets

| Command | Description |
|---------|-------------|
| `make` | Build all 12 plugins |
| `make install` | Build and install all plugins |
| `make clean` | Clean all build artifacts |
| `make help` | Show detailed help |
| `make [PluginName]` | Build specific plugin |

---

## Technical Details

### Plugin Architecture
- **Language**: Objective-C with ARC
- **SDK Version**: Hopper SDK v6
- **Binary Format**: Universal (x86_64 + ARM64)
- **Minimum macOS**: 10.13
- **Average Plugin Size**: ~69KB

### Compiler Flags
- `-arch x86_64 -arch arm64` - Universal binary
- `-mmacosx-version-min=10.13` - macOS 10.13+ compatibility
- `-fobjc-arc` - Automatic Reference Counting
- `-fmodules` - Module support
- `-O2` - Optimization level 2

---

## Plugin Structure

Each plugin is self-contained with:
```
PluginName/
├── PluginName.h          # Header file
├── PluginName.m          # Implementation
├── Info.plist            # Bundle metadata
└── Makefile              # Build configuration
```

---

## Analysis Reports

Plugins generate detailed reports saved to:
```
/tmp/hoppersrk_[analyzer]_report.txt
```

Reports include:
- Severity levels (Critical, High, Medium, Low, Info)
- Memory addresses of findings
- Detailed descriptions
- API call references
- Execution time statistics

---

## Support

For issues, questions, or contributions, please contact:
**Zeyad Azima** - contact@zeyadazima.com (Or just do pull request/Issue from github)

---

## Version History

### v2.0.0 (2025-12-11)
- ✅ Unified build system for all 12 plugins
- ✅ Individual optimized plugin architecture
- ✅ Professional Makefile with colored output
- ✅ Universal binary support (x86_64 + ARM64)
- ✅ Hopper v4 and v5 compatibility
