/*
 * Copyright (C) 2012 LGE
 */

#ifndef AsyncFileSystemAndroid_h
#define AsyncFileSystemAndroid_h

#if ENABLE(FILE_SYSTEM)

#include "AsyncFileSystem.h"

namespace WebCore {

class AsyncFileSystemCallbacks;

class AsyncFileSystemAndroid : public AsyncFileSystem {
public:
    static PassOwnPtr<AsyncFileSystem> create(AsyncFileSystem::Type type, const String& rootPath);

    virtual ~AsyncFileSystemAndroid();

    virtual void move(const String& sourcePath, const String& destinationPath, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void copy(const String& sourcePath, const String& destinationPath, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void remove(const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void removeRecursively(const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void readMetadata(const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void createFile(const String& path, bool exclusive, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void createDirectory(const String& path, bool exclusive, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void fileExists(const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void directoryExists(const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void readDirectory(const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);
    virtual void createWriter(AsyncFileWriterClient* client, const String& path, PassOwnPtr<AsyncFileSystemCallbacks>);

private:
    AsyncFileSystemAndroid(AsyncFileSystem::Type type, const String& rootPath);
};

} // namespace WebCore

#endif // ENABLE(FILE_SYSTEM)

#endif // AsyncFileSystemAndroid_h
