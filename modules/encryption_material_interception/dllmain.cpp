// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <string>
#include <wincrypt.h>
#include <bcrypt.h>
#include "detours/detours.h"
#include <tchar.h>
#include "antiransom.h"
#include "Psapi.h"
#include <sstream>


#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "detours/detours")
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll")


char processbuffer[MAX_PATH];
static DWORD g_dwKeyBlobLen_Exfil = 0;
static PBYTE g_pbKeyBlob_Exfil = NULL;
static BOOL recursive = FALSE;
static BOOL recursive2 = FALSE;

// Works for Crypto++563-Debug
const DWORD NEEDLE_SIZE = 32;
char NEEDLE[NEEDLE_SIZE] = { 0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x24, 0x89, 0x4D, 0xF4, 0x8B, 0x45, 0xF4, 0x8B, 0x55, 0x0C,
                            0x89, 0x14, 0x24, 0x89, 0xC1, 0xE8, 0x8A, 0x02, 0x00, 0x00, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x00 };

/* This is a hack to not find the needle in this DLL's memory */
int dudd1 = 0x123123;
int dudd2 = 0x123123;
int dudd3 = 0x123123;
int dudd4 = 0x123123;
char NEEDLE_END = 0xF4;

bool FileExists(LPCWSTR filename) {
    DWORD fileAttributes = GetFileAttributes(filename);
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

void reentrant_log(std::string logMessage) {
    FILE* fd = fopen("C:\\Users\\Public\\Documents\\Crypto.txt", "a+");
    if (fd) {
        fseek(fd, 0, SEEK_END);
        long fileSize = ftell(fd);
        std::string tmpName = "C:\\Users\\Public\\Documents\\Crypto_archive.tmp";
        std::string archiveName = "C:\\Users\\Public\\Documents\\Crypto_archive.txt";
        if (fileSize > 10 * 1024 * 1024) {
            fclose(fd);
            // For reentry purposes, attempt to rename. if rename was not successful, a second process may have
            // already reached this line and renamed the file. At which point, just open up the original file
            // and continue on
            std::rename("C:\\Users\\Public\\Documents\\Crypto.txt", tmpName.c_str());
            fd = fopen("C:\\Users\\Public\\Documents\\Crypto.txt", "a+");
        }
        // For reentry purposes, if temp file has been in purgatory, archive it
        if (FileExists(L"C:\\Users\\Public\\Documents\\Crypto_archive.tmp")) {
            // if rename didn't work assume the old archive still exists and needs to be deleted
            // so delete the old archive now, and the rename should work the next time the rename
            // is attempted
            if (!std::rename(tmpName.c_str(), archiveName.c_str())) {
                std::remove(archiveName.c_str());
            }
        }
        fwrite(logMessage.c_str(), 1, logMessage.size(), fd);
        fflush(fd);
        fclose(fd);
    }
}

NTSTATUS WINAPI Fake_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    
    std::ostringstream oss;
    std::string mytime = CurrentTime();

    oss << "[BCryptEncrypt] " << processbuffer << " " << mytime << "\n";
    oss << "\t HCRYPTKEY hKey = " << hKey << "\n";
    oss << "\t PUCHAR pbIV size = " << cbIV << "\n";

    BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &g_dwKeyBlobLen_Exfil, 0);
    oss << "\t ExfilKeyLen = " << g_dwKeyBlobLen_Exfil << "\n";
    g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
    BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, g_pbKeyBlob_Exfil, g_dwKeyBlobLen_Exfil, &g_dwKeyBlobLen_Exfil, 0);
    oss << "\t ExfilKeyData = ";
    for (int i = 0; i < g_dwKeyBlobLen_Exfil; i++) {
        char s[] = "00";
        sprintf(s, "%02x", g_pbKeyBlob_Exfil[i]);

        oss << s;
    }
    free(g_pbKeyBlob_Exfil);
    oss << "\n";
    oss << "\t PbIV Contents = ";
    for (int i = 0; i < cbIV; i++) {
        char s[] = "00";
        sprintf(s, "%02x", pbIV[i]);
        oss << s;
    }
    oss << "\n";

    std::string logMessage = oss.str();

    reentrant_log(logMessage);

    return Real_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput,
        pcbResult, dwFlags);
}

BOOL WINAPI Fake_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    std::ostringstream oss;
    std::string mytime = CurrentTime();

    oss << "[CryptGenRandom] " << processbuffer << " " << mytime << "\n";
    oss << "\t HCRYPTPROV hProv = " << hProv << "\n";
    oss << "\t DWORD dwLen = " << dwLen << "\n";
    oss << "\t BYTE* pbBuffer = " << static_cast<void*>(pbBuffer) << ", *pbBuffer = OUTPUT, cannot deref\n";

    BOOL ret = Real_CryptGenRandom(hProv, dwLen, pbBuffer);

    oss << "\t RandomData = ";
    for (DWORD i = 0; i < dwLen; i++) {
        char s[] = "00";
        sprintf(s, "%02x", pbBuffer[i]);
        oss << s;
    }
    oss << "\n";

    std::string logMessage = oss.str();
    reentrant_log(logMessage);
    return ret;
}

BOOL WINAPI Fake_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    std::ostringstream oss;
    std::string mytime = CurrentTime();

    oss << "[CryptGenKey] " << processbuffer << " " << mytime << "\n";
    oss << "\t HCRYPTPROV hProv = " << hProv << "\n";
    oss << "\t ALG_ID Algid = " << Algid << "\n";
    oss << "\t DWORD dwFlags = " << dwFlags << "\n";
    oss << "\t HCRYPTKEY* phKey = " << phKey << ", *phKey = Cannot deref the key directly\n";

    std::string logMessage = oss.str();
    reentrant_log(logMessage);
    return Real_CryptGenKey(hProv, Algid, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptAcquireContext(HCRYPTPROV* phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType,
    DWORD dwFlags) {
    std::ostringstream oss;
    std::string mytime = CurrentTime();

    oss << "[CryptAcquireContext] " << processbuffer << " " << mytime << "\n";
    oss << "\t HCRYPTPROV* phProv = " << phProv << ", *phProv = OUTPUT, so probably can't deref NULL\n";
    oss << "\t LPCTSTR pszContainer = " << pszContainer << "\n";
    oss << "\t LPCTSTR pszProvider = " << pszProvider << "\n";
    oss << "\t DWORD dwProvType = " << dwProvType << "\n";
    oss << "\t DWORD dwFlags = " << dwFlags << "\n";

    std::string logMessage = oss.str();
    reentrant_log(logMessage);
    return Real_CryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI Fake_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
    DWORD* pdwDataLen, DWORD dwBufLen) {
    std::ostringstream oss1;
    std::ostringstream oss2;
    std::string mytime = CurrentTime();

    oss1 << "[CryptEncrypt] " << processbuffer << " " << mytime << "\n";
    oss1 << "\t HCRYPTKEY hKey = " << hKey << "\n";
    oss1 << "\t HCRYPTHASH hHash = " << hHash << "\n";
    oss1 << "\t BOOL Final = " << Final << "\n";
    oss1 << "\t DWORD dwFlags = " << dwFlags << "\n";
    oss1 << "\t BYTE* pbData = " << static_cast<void*>(pbData) << ", *pbData = BROKEN\n";
    oss1 << "\t DWORD* pdwDataLen = " << pdwDataLen << ", *pdwDataLen = BROKEN\n";
    oss1 << "\t DWORD dwBufLen = " << dwBufLen << "\n";

    std::string logMessage1 = oss1.str();
    reentrant_log(logMessage1);

     DWORD dwCount;
     BYTE pbData2[16];
     CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0); // Get size of KP_IV
     CryptGetKeyParam(hKey, KP_IV, pbData2, &dwCount, 0); // Get KP_IV data
     //fprintf(fd, "KP_IV =  ");
     for (int i = 0 ; i < dwCount ; i++) {
         //fprintf(fd, "%02x ",pbData2[i]);
     }

     if (recursive == FALSE) {
         recursive = TRUE;
         if (pbData == NULL) {
             // CryptEncrypt being used to get allocation size for cipher data
             if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                 //MyHandleError(TEXT("[FAIL] Exfil key length failed \n"), GetLastError());
                // fprintf(fd, "[FAIL] Exfil key length failed \n");
             }
             oss2 << "\t ExfilKeyLen = " << g_dwKeyBlobLen_Exfil << "\n";
         }
         else if (g_dwKeyBlobLen_Exfil != NULL) {
             // CryptEncrypt is encrypting data, and was used to get the allocation size
             g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
             if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                 //MyHandleError(TEXT("[FAIL] Exfil key length failed \n"), GetLastError());
                 //fprintf(fd, "[FAIL] Exfil key data failed \n");
             }
             oss2 << "\t ExfilKeyData = ";
             for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                 char s[] = "00";
                 sprintf(s, "%02x", g_pbKeyBlob_Exfil[i]);
                 oss2 << s;
             }
             oss2 << "\n";
         }
         else {
             // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
             // Do the export in one step.

             // Get the size to allocate for the export blob
             if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                 //MyHandleError(TEXT("[FAIL] no-alloca Exfil key length failed \n"), GetLastError());
                // fprintf(fd, "[FAIL] no-alloca Exfil key length failed \n");
             }

             g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);

             // Get the export blob
             if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                // MyHandleError(TEXT("[FAIL] Exfil key data failed \n"), GetLastError());
                // fprintf(fd, "[FAIL] no-alloca Exfil key data failed \n");
             }

             // Print the export blob
            oss2 << "\t no-alloca ExfilKeyData = ";
             for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                 char s[] = "00";
                 sprintf(s, "%02x", g_pbKeyBlob_Exfil[i]);
                 oss2 << s;
             }
            oss2 << "\n";

             free(g_pbKeyBlob_Exfil);
         }
         std::string logMessage2 = oss2.str();
         reentrant_log(logMessage2);
         recursive = FALSE;
     }
     
    return Real_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

BOOL WINAPI Fake_CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen) {
    std::ostringstream oss1;
    std::ostringstream oss2;
    std::string mytime = CurrentTime();

    oss1 << "[CryptExportKey] " << processbuffer << " " << mytime << "\n";
    oss1 << "\t HCRYPTKEY hKey = " << hKey << "\n";
    oss1 << "\t HCRYPTKEY hExpKey = " << hExpKey << "\n";
    oss1 << "\t DWORD dwBlobType = " << dwBlobType << "\n";
    oss1 << "\t DWORD dwFlags = " << dwFlags << "\n";
    oss1 << "\t BYTE* pbData = " << static_cast<void*>(pbData) << ", *pbData = BROKEN\n";
    oss1 << "\t DWORD* pdwDataLen = " << pdwDataLen << ", *pdwDataLen = " << *pdwDataLen << "\n";

    std::string logMessage1 = oss1.str();
    reentrant_log(logMessage1);

    if (recursive == FALSE) {
        recursive = TRUE;
        if (pbData == NULL) {
            // CryptEncrypt being used to get allocation size for cipher data
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)) {
               //fprintf(fd, "[FAIL] Exfil key length failed \n");
            }
            oss2 << "\t ExfilKeyLen = " << g_dwKeyBlobLen_Exfil << "\n";
        }
        else if (g_dwKeyBlobLen_Exfil != NULL) {
            // CryptEncrypt is encrypting data, and was used to get the allocation size
            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)) {
                //fprintf(fd, "[FAIL] Exfil key data failed \n");
            }
            oss2 << "[CryptExportKey] " << mytime << "\n";
            oss2 << "\t ExfilKeyData = ";
            for (int i = 0; i < g_dwKeyBlobLen_Exfil; i++) {
                char s[] = "00";
                sprintf(s, "%02x", g_pbKeyBlob_Exfil[i]);
                oss2 << s;
            }
            oss2 << "\n";
        }
        else {
            // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
            // Do the export in one step.

            // Get the size to allocate for the export blob
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)) {
                //fprintf(fd, "[FAIL] Exfil key length failed \n");
            }

            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);

            // Get the export blob
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)) {
                //fprintf(fd, "[FAIL] Exfil key data failed \n");
            }

            oss2 << "[CryptExportKey] " << mytime << "\n";
            oss2 << "\t ExfilKeyData = ";
            for (int i = 0; i < g_dwKeyBlobLen_Exfil; i++) {
                char s[] = "00";
                sprintf(s, "%02x", g_pbKeyBlob_Exfil[i]);
                oss2 << s;
            }
            oss2 << "\n";

            free(g_pbKeyBlob_Exfil);
        }
        std::string logMessage2 = oss2.str();
        reentrant_log(logMessage2);
        recursive = FALSE;
    }

    return Real_CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}


const std::string CurrentTime() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char currentTime[100] = "";
    sprintf(currentTime, "%d:%d:%d %d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(currentTime);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    
    GetProcessImageFileNameA(GetCurrentProcess(), processbuffer, MAX_PATH);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Real_CryptEncrypt, Fake_CryptEncrypt);
        DetourAttach(&(PVOID&)Real_CryptExportKey, Fake_CryptExportKey);
        DetourAttach(&(PVOID&)Real_CryptAcquireContext, Fake_CryptAcquireContext);
        DetourAttach(&(PVOID&)Real_CryptGenKey, Fake_CryptGenKey);
        DetourAttach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);
        DetourAttach(&(PVOID&)Real_BCryptEncrypt, Fake_BCryptEncrypt);
    
        DetourTransactionCommit();
        break;
        
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_CryptEncrypt, Fake_CryptEncrypt);
        DetourDetach(&(PVOID&)Real_CryptExportKey, Fake_CryptExportKey);
        DetourDetach(&(PVOID&)Real_CryptAcquireContext, Fake_CryptAcquireContext);
        DetourDetach(&(PVOID&)Real_CryptGenKey, Fake_CryptGenKey);
        DetourDetach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);
        DetourAttach(&(PVOID&)Real_BCryptEncrypt, Fake_BCryptEncrypt);

        DetourTransactionCommit();
        break;
    }
    //fclose(fd);
    return TRUE;
}

