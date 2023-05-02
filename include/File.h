/*****************************************************************************
 * Name : Mike
 * Date : 21 Aug 2022
 * File : File.h
 *****************************************************************************/

#pragma once

#include <stdbool.h>

bool File_SaveExecutableFileToDisk(const char *pNewExecutableBaseFilename, void *pExecutableFile,
        unsigned int uiExecutableFileSize, long lExecutableFileOffset);
