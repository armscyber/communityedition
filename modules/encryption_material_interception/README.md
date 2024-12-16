# Encryption material intercept

## Overview
This file, `dllmain.cpp`, defines the entry point for the DLL application. It uses the Microsoft Detours library to hook into the BCrypt library functions to intercept and log encryption-related data. The file includes necessary headers, defines global variables, and contains utility functions used throughout the DLL.

## Key Components

### Includes
The file includes several headers:
- `pch.h`: Precompiled header.
- `stdio.h`: Standard I/O functions.
- `windows.h`: Windows API functions.
- `string`: C++ string class.
- `wincrypt.h`: Windows Cryptographic API.
- `bcrypt.h`: Windows Cryptographic API for CNG.
- `detours/detours.h`: Microsoft Detours library for function interception.
- `tchar.h`: Unicode and ANSI portable types.
- `antiransom.h`: Custom header for anti-ransomware functionality.
- `Psapi.h`: Windows API for process status.

### Libraries
The following libraries are linked:
- `advapi32`
- `user32`
- `detours/detours`
- `bcrypt.lib`
- `ntdll`

### Global Variables
- `processbuffer`: Buffer to store process information.
- `g_dwKeyBlobLen_Exfil`: Length of the key blob for exfiltration.
- `g_pbKeyBlob_Exfil`: Pointer to the key blob for exfiltration.
- `recursive` and `recursive2`: Boolean flags for recursion control.
- `NEEDLE`: Byte pattern used for memory scanning.
- `dudd1`, `dudd2`, `dudd3`, `dudd4`: Dummy variables to prevent the needle from being found in the DLL's memory.
- `NEEDLE_END`: End byte for the needle pattern.

### Functions

#### `bool FileExists(LPCWSTR filename)`
Checks if a file exists at the specified path.
- **Parameters**: `filename` - Path to the file.
- **Returns**: `true` if the file exists and is not a directory, `false` otherwise.

## Hooking and Interception
This file uses the Detours library to hook into the BCrypt library functions. The hooked functions intercept and log encryption-related data for analysis and potential anti-ransomware measures.

## Notes
- The `NEEDLE` array is used for memory scanning, and dummy variables are included to prevent the needle from being found in the DLL's memory.
- Ensure proper linking of the specified libraries for successful compilation.