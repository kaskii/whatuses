# WhatUses

A simple, cross-platform CLI tool to identify which processes are using a specific file or listening on a network port.

[![Crates.io](https://img.shields.io/crates/v/whatuses.svg)](https://crates.io/crates/whatuses)
[![License](https://img.shields.io/badge/license-PolyForm--Noncommercial--1.0.0-blue.svg)](LICENSE)

## Features

- **File Investigation**: Find which processes have a specific file open.
- **Port Investigation**: Identify processes listening on a specific TCP/UDP port.
- **Cross-Platform**: Supports Windows and Linux.
- **Detailed Output**: Provides PID, process name, and executable path.

## Installation

### From Source (using Cargo)

If you have Rust installed, you can install `whatuses` directly from source:

```bash
cargo install whatuses
```

### Binary Downloads

Check the [Releases](https://github.com/kaskii/whatuses/releases) page for pre-compiled binaries for Windows and Linux.

## Usage

### Check a File

To see which processes are using a specific file:

```bash
whatuses C:\path\to\your\file.txt
```

Or explicitly using the `--file` flag:

```bash
whatuses --file C:\path\to\your\file.txt
```

On Linux:
```bash
whatuses /path/to/your/file.txt
```

### Check a Port

To see which processes are listening on a specific port:

```bash
whatuses 8080
```

Or explicitly using the `--port` flag:

```bash
whatuses --port 3000
```

### Verbose Mode

For more detailed logging:

```bash
whatuses 8080 --verbose
```

When enabled, verbose mode provides additional insights into the tool's operations, including:
- **Path Resolution**: Shows how file paths are being canonicalized.
- **Search Progress**: Displays the number of active sockets or processes being scanned.
- **Detailed Matches**: Shows protocol and address information for matching network sockets.
- **Internal Lookups**: Logs attempts to resolve executable paths using platform-specific APIs or fallbacks (e.g., for `svchost.exe` on Windows).
- **System Activity**: Indicates when the internal process list is being refreshed.

## Platform Support

### Windows
- **Files**: Uses the Windows Restart Manager API to accurately identify processes holding file locks.
- **Ports**: Uses native Windows APIs via `netstat-esr` to map ports to PIDs.

### Linux
- **Files**: Inspects `/proc/[pid]/fd` to find processes with open file descriptors.
- **Ports**: Parses network information to identify listening processes.

> **Note**: On both platforms, some process information may require elevated privileges to access. If the tool does not find any processes when you expect it should, try running it with **sudo** (Linux) or as **Administrator** (Windows).

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.
