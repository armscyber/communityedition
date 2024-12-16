# Mirror.cpp

## Overview


mirror.cpp

 is a part of the project that implements various file system operations using the Dokan library. This file contains callback functions that handle file operations such as creating, reading, writing, deleting, and moving files. Decoy logic is in MirrorWriteFile and MirrorMoveFile.

## Key Functions

### MirrorCreateFile
```cpp
static NTSTATUS DOKAN_CALLBACK MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles the creation and opening of files and directories.

### MirrorReadFile
```cpp
static NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles reading data from a file.

### MirrorWriteFile
```cpp
static NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles writing data to a file.

### MirrorDeleteFile
```cpp
static NTSTATUS DOKAN_CALLBACK MirrorDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles the deletion of a file.

### MirrorMoveFile
```cpp
static NTSTATUS DOKAN_CALLBACK MirrorMoveFile(LPCWSTR FileName, LPCWSTR NewFileName, BOOL ReplaceIfExisting, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles moving and renaming files.

### MirrorCloseFile
```cpp
static void DOKAN_CALLBACK MirrorCloseFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles closing a file.

### MirrorCleanup
```cpp
static void DOKAN_CALLBACK MirrorCleanup(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo);
```
Handles cleanup operations for a file.

## Debugging
The file uses 

DbgPrint

 for logging debug information. Ensure that 

g_DebugMode

 is enabled to see debug outputs.

## Dependencies
- Dokan library
- Windows API

## Notes
- Ensure proper error handling and resource management to avoid memory leaks and invalid handles.
- The file path operations use 

GetFilePath

 to convert file names to full paths.

## License
This file is part of a project licensed under the GNU General Public License v3.0. See the LICENSE file for more details.