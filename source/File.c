/*****************************************************************************
 * Name : Mike
 * Date : 21 Aug 2022
 * File : File.c
 *****************************************************************************/

#include <File.h>

#include <linux/limits.h>
#include <stdio.h>

bool File_SaveExecutableFileToDisk(const char *pNewExecutableBaseFilename, void *pExecutableFile,
        unsigned int uiExecutableFileSize, long lExecutableFileOffset) {
    bool bSavedNewExecutableFile = false;

    char chNewExecutableFilename[NAME_MAX + 1];
    if (snprintf(chNewExecutableFilename, sizeof(chNewExecutableFilename), "%.232s-0x%08lX.exe",
                pNewExecutableBaseFilename, lExecutableFileOffset) <= 0) {
        printf("[SAV] \tFailed to format the name of the new file !\n");
        goto label_return;
    }

    FILE *pFile = fopen(chNewExecutableFilename, "wb");
    if (!pFile) {
        printf("[SAV] \tFailed to open the new file '%s' for writing !\n", chNewExecutableFilename);
        goto label_return;
    }

    if (fwrite(pExecutableFile, sizeof(unsigned char), uiExecutableFileSize, pFile) !=
            uiExecutableFileSize) {
        printf("[SAV] \tFailed to write the contents of the executable to the new "
               "file '%s' !\n",
                chNewExecutableFilename);
        goto label_close_file;
    }

    printf("[SAV] \tSuccessfully saved the contents of the executable to the new "
           "file '%s' !\n",
            chNewExecutableFilename);
    bSavedNewExecutableFile = true;

label_close_file:
    fclose(pFile);
label_return:
    return bSavedNewExecutableFile;
}
