/*
 * Copyright (C) 2012 LGE
 */

#include "config.h"

#if ENABLE(FILE_SYSTEM)

#include "AsyncFileSystemAndroid.h"

#include "AsyncFileSystemCallbacks.h"
#include "AsyncFileWriterAndroid.h"
#include "DOMFilePath.h"
#include "FileError.h"
#include "FileMetadata.h"
#include "FileSystem.h"

namespace WebCore {

DEFINE_STATIC_LOCAL(const String, persistent, ("Persistent"));
DEFINE_STATIC_LOCAL(const String, temporary, ("Temporary"));

bool AsyncFileSystem::isAvailable()
{
    return true;
}

PassOwnPtr<AsyncFileSystem> AsyncFileSystem::create(Type type, const String& rootPath)
{
    return AsyncFileSystemAndroid::create(type, rootPath);
}

void AsyncFileSystem::openFileSystem(const String& basePath, const String& storageIdentifier, Type type, bool create, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    // Do not allow create Persistent file system until quota and security logic will be implemented.
    // Or allow to create, but clear it like Temporary file system.
    if (type != Temporary) {
        callbacks->didFail(FileError::SECURITY_ERR);
        return;
    }

    String typeString = (type == Persistent) ? persistent : temporary;

    String name = storageIdentifier;
    name += ":";
    name += typeString;

    String rootPath = pathByAppendingComponent(basePath, pathByAppendingComponent(typeString, storageIdentifier));
    if (!WebCore::directoryExists(rootPath)) {
        if (create) {
            if (!makeAllDirectories(rootPath)) {
                callbacks->didFail(FileError::SECURITY_ERR);
                return;
            }
        } else {
            callbacks->didFail(FileError::NOT_FOUND_ERR);
            return;
        }
    }
    callbacks->didOpenFileSystem(name, AsyncFileSystem::create(type, rootPath));
}

void AsyncFileSystem::clearFileSystem(const String& basePath)
{
    // Clear Temporary part of file system.
    String temporaryFileSystemPath = pathByAppendingComponent(basePath, temporary);
    if (WebCore::directoryExists(temporaryFileSystemPath)) {
        deleteRecursively(temporaryFileSystemPath);
    }
}

PassOwnPtr<AsyncFileSystem> AsyncFileSystemAndroid::create(Type type, const String& rootPath)
{
    return adoptPtr(new AsyncFileSystemAndroid(type, rootPath));
}

AsyncFileSystemAndroid::AsyncFileSystemAndroid(AsyncFileSystem::Type type, const String& rootPath)
    : AsyncFileSystem(type, rootPath)
{
}

AsyncFileSystemAndroid::~AsyncFileSystemAndroid()
{
}

void AsyncFileSystemAndroid::move(const String& sourcePath, const String& destinationPath, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    // Entry to move can be file or directory
    if (isDirectory(sourcePath)) {
        if (WebCore::directoryExists(destinationPath)) {
            callbacks->didFail(FileError::PATH_EXISTS_ERR);
            return;
        }
        // In current implementation allowed to move only empty directory
        if (!deleteEmptyDirectory(sourcePath) || !makeAllDirectories(destinationPath)) {
            callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    } else {
        if (WebCore::fileExists(destinationPath)) {
            callbacks->didFail(FileError::PATH_EXISTS_ERR);
            return;
        }
        if (!copyFile(sourcePath, destinationPath) || !deleteFile(sourcePath)) {
            callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::copy(const String& sourcePath, const String& destinationPath, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    // Entry to copy can be file or directory
    if (isDirectory(sourcePath)) {
        if (WebCore::directoryExists(destinationPath)) {
            callbacks->didFail(FileError::PATH_EXISTS_ERR);
            return;
        }
        // In current implementation allowed to copy only empty directory
        if (!makeAllDirectories(destinationPath)) {
            callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    } else {
        if (WebCore::fileExists(destinationPath)) {
            callbacks->didFail(FileError::PATH_EXISTS_ERR);
            return;
        }
        if (!copyFile(sourcePath, destinationPath)) {
            callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::remove(const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    // Entry to remove can be file or directory
    if (isDirectory(path)) {
        if (!deleteEmptyDirectory(path)) {
            callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    } else {
        if (!deleteFile(path)) {
            callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::removeRecursively(const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    if (!deleteRecursively(path)) {
        callbacks->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
        return;
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::readMetadata(const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    FileMetadata fileMetadata;
    if (!getFileMetadata(path, fileMetadata)) {
        callbacks->didFail(FileError::NOT_READABLE_ERR);
        return;
    }
    callbacks->didReadMetadata(fileMetadata);
}

void AsyncFileSystemAndroid::createFile(const String& path, bool exclusive, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    if (WebCore::fileExists(path)) {
        if (exclusive) {
            callbacks->didFail(FileError::PATH_EXISTS_ERR);
            return;
        }
    } else {
        PlatformFileHandle fileHandle = openFile(path, OpenForWrite);
        if (!isHandleValid(fileHandle)) {
            callbacks->didFail(FileError::SECURITY_ERR);
            return;
        }
        closeFile(fileHandle);
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::createDirectory(const String& path, bool exclusive, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    if (WebCore::directoryExists(path)) {
        if (exclusive) {
            callbacks->didFail(FileError::PATH_EXISTS_ERR);
            return;
        }
    } else {
        if (!makeAllDirectories(path)) {
            callbacks->didFail(FileError::SECURITY_ERR);
            return;
        }
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::fileExists(const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    if (!WebCore::fileExists(path)) {
        callbacks->didFail(FileError::NOT_FOUND_ERR);
        return;
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::directoryExists(const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    if (!WebCore::directoryExists(path)) {
        callbacks->didFail(FileError::NOT_FOUND_ERR);
        return;
    }
    callbacks->didSucceed();
}

void AsyncFileSystemAndroid::readDirectory(const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    if (!WebCore::directoryExists(path)) {
        callbacks->didFail(FileError::NOT_FOUND_ERR);
        return;
    }

    Vector<String> entries = WebCore::readDirectory(path);
    for (size_t i = 0; i < entries.size(); ++i) {
        callbacks->didReadDirectoryEntry(entries[i], isDirectory(pathByAppendingComponent(path, entries[i])));
    }
    callbacks->didReadDirectoryEntries(false);
}

void AsyncFileSystemAndroid::createWriter(AsyncFileWriterClient* client, const String& path, PassOwnPtr<AsyncFileSystemCallbacks> callbacks)
{
    FileMetadata fileMetadata;
    if (!getFileMetadata(path, fileMetadata) || fileMetadata.length < 0) {
        callbacks->didFail(FileError::NOT_READABLE_ERR);
        return;
    }

    if (fileMetadata.type != FileMetadata::TypeFile) {
        callbacks->didFail(FileError::TYPE_MISMATCH_ERR);
        return;
    }

    OwnPtr<AsyncFileWriter> asyncFileWriterAndroid = adoptPtr(new AsyncFileWriterAndroid(client, path));
    callbacks->didCreateFileWriter(asyncFileWriterAndroid.release(), fileMetadata.length);
}

} // namespace WebCore

#endif // ENABLE(FILE_SYSTEM)
