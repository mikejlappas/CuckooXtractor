/*****************************************************************************
 * Name : Mike
 * Date : 21 Aug 2022
 * File : Extractor.c
 *****************************************************************************/

#include <File.h>
#include <Image.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CUCKOO_DUMP_FILE_EXTENSION ".dmp"

static void PrintBuildInformation(void);
__attribute__((noreturn)) static void PrintUsageAndExit(int iExitCode);
static void ParseArguments(int argc, char *argv[]);
static int MkstempsDumpFileFilter(const struct dirent *pDirEnt);
static size_t ExtractExecutableFilesFromDumpFile(const char *pNewExecutableBaseFilename,
        void *pDumpFileContents, long lDumpFileSize);

int main(int argc, char *argv[]) {
    PrintBuildInformation();
    ParseArguments(argc, argv);

    printf("[DIR] Opening the current directory... ");
    DIR *pDir = opendir(".");
    if (!pDir) {
        printf("FAILED !\n");
        return EXIT_FAILURE;
    }
    printf("OK !\n");

    printf("[DIR] Searching for valid '" CUCKOO_DUMP_FILE_EXTENSION
           "' files in the current directory... ");
    struct dirent **ppDirEnt;
    int iDirEntries = scandir(".", &ppDirEnt, MkstempsDumpFileFilter, alphasort);
    if (iDirEntries == -1) {
        printf("FAILED !\n");
        return EXIT_FAILURE;
    }
    printf("OK !\n");
    printf("[DIR] Found %d '" CUCKOO_DUMP_FILE_EXTENSION "' files in the current directory !\n",
            iDirEntries);

    for (int i = 0; i < iDirEntries; i++) {
        printf("\n");
        printf("[FIL] Preparing file '%s'... ", ppDirEnt[i]->d_name);
        FILE *pFile = fopen(ppDirEnt[i]->d_name, "rb");
        if (!pFile) {
            printf("failed to open the file !\n");
            goto label_free_dirent;
        }

        long lFileSize;
        if (fseek(pFile, 0, SEEK_END) || ((lFileSize = ftell(pFile)) == -1) ||
                (fseek(pFile, 0, SEEK_SET))) {
            printf("failed to get the size of the file !\n");
            goto label_close_file;
        }

        if (lFileSize == 0) {
            printf("the file is empty !\n");
            goto label_close_file;
        }

        void *pFileContentsBuffer = malloc(lFileSize);
        if (!pFileContentsBuffer) {
            printf("failed to allocate a buffer of size 0x%08lX bytes to hold the "
                   "contents of the file !\n",
                    lFileSize);
            goto label_close_file;
        }

        if (fread(pFileContentsBuffer, sizeof(unsigned char), lFileSize, pFile) != lFileSize) {
            printf("failed to read the contents of the file !\n");
            goto label_free_buffer;
        }
        printf("OK !\n");

        size_t nExtractedExecutableFiles = ExtractExecutableFilesFromDumpFile(ppDirEnt[i]->d_name,
                pFileContentsBuffer, lFileSize);
        printf("[FIL] Extracted %lu executable file%s from the file '%s' !\n",
                nExtractedExecutableFiles, (nExtractedExecutableFiles == 1) ? "" : "s",
                ppDirEnt[i]->d_name);

    label_free_buffer:
        free(pFileContentsBuffer);
    label_close_file:
        fclose(pFile);
    label_free_dirent:
        free(ppDirEnt[i]);
    }
    free(ppDirEnt);

    return EXIT_SUCCESS;
}

static void PrintBuildInformation(void) {
    printf("[SYS] CuckooXtractor by Mike\n");
    printf("[SYS] Built: " __DATE__ " " __TIME__ "\n");
    printf("\n");
}

static void PrintUsageAndExit(int iExitCode) {
    printf("[SYS] Usage: ./CuckooXtractor [-h]\n");
    printf("\n");
    printf("[SYS] Extracts executable files from within Cuckoo generated "
           "'" CUCKOO_DUMP_FILE_EXTENSION "' files\n");
    printf("[SYS] that are in the same directory as the program.\n");
    printf("\n");
    printf("[SYS] -h\tPrints this help message to the console then exits the "
           "program\n");

    exit(iExitCode);
    __builtin_unreachable();
}

static void ParseArguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            PrintUsageAndExit(EXIT_FAILURE);
        }

        for (char *pCharacter = &argv[i][1]; *pCharacter; pCharacter++) {
            if (*pCharacter == 'h') {
                PrintUsageAndExit(EXIT_SUCCESS);
            } else {
                PrintUsageAndExit(EXIT_FAILURE);
            }
        }
    }
}

static int MkstempsDumpFileFilter(const struct dirent *pDirEnt) {
    if (pDirEnt->d_type != DT_REG) {
        return false;
    }

    const char *pFileExtension = strrchr(pDirEnt->d_name, '.');
    if (!pFileExtension) {
        return false;
    }

    return !(strcmp(pFileExtension, CUCKOO_DUMP_FILE_EXTENSION));
}

static size_t ExtractExecutableFilesFromDumpFile(const char *pNewExecutableBaseFilename,
        void *pDumpFileContents, long lDumpFileSize) {
    size_t nExtractedExecutableFiles = 0;

    for (long l = 0; l <= lDumpFileSize - Image_GetDOSHeaderSize(); l++) {
        PIMAGE_DOS_HEADER pImageDOSHeader =
                (PIMAGE_DOS_HEADER)((unsigned char *)pDumpFileContents + l);
        if (!Image_IsDOSHeaderMagicValid(pImageDOSHeader)) {
            continue;
        }

        long lCurrentOffset = l + pImageDOSHeader->e_lfanew;
        if (lCurrentOffset + Image_GetNTHeaderSignatureSize() + Image_GetFileHeaderSize() +
                        Image_GetOptionalHeaderMagicSize() >
                lDumpFileSize) {
            goto label_next_but_one_address;
        }

        PIMAGE_NT_HEADERS32 pImageNTHeader =
                (PIMAGE_NT_HEADERS32)((unsigned char *)pImageDOSHeader + pImageDOSHeader->e_lfanew);
        if (!Image_IsNTHeaderSignatureValid(pImageNTHeader)) {
            goto label_next_but_one_address;
        }

        if (!Image_IsOptionalHeaderMagicValid(pImageNTHeader)) {
            goto label_next_but_one_address;
        }

        size_t nImageNTHeaderSize = Image_GetNTHeaderSize(pImageNTHeader);
        lCurrentOffset += nImageNTHeaderSize;
        if (lCurrentOffset > lDumpFileSize) {
            goto label_next_but_one_address;
        }

        unsigned int uiSizeOfImage = Image_GetSizeOfImage(pImageNTHeader);
        if (l + uiSizeOfImage > lDumpFileSize) {
            goto label_next_but_one_address;
        }

        printf("[DMP] \tFound an executable file @ 0x%08lX !\n", l);

        if (File_SaveExecutableFileToDisk(pNewExecutableBaseFilename, pImageDOSHeader,
                    uiSizeOfImage, l)) {
            nExtractedExecutableFiles++;
        }

    label_next_but_one_address:
        l++;
    }

    return nExtractedExecutableFiles;
}
