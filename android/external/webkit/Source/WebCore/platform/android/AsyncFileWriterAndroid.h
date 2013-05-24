/*
 * Copyright (C) 2012 LGE
 */

#ifndef AsyncFileWriterAndroid_h
#define AsyncFileWriterAndroid_h

#if ENABLE(FILE_SYSTEM)

#include "AsyncFileWriter.h"
#include "FileSystem.h"

namespace WebCore {

class Blob;
class AsyncFileWriterClient;

class AsyncFileWriterAndroid : public AsyncFileWriter {
public:
    AsyncFileWriterAndroid(AsyncFileWriterClient* client, const String& path);
    virtual ~AsyncFileWriterAndroid();

    // AsyncFileWriter
    virtual void write(long long position, Blob* blob);
    virtual void truncate(long long length);
    virtual void abort();

private:
    AsyncFileWriterClient* m_client;
    String m_path;
};

} // namespace

#endif // ENABLE(FILE_SYSTEM)

#endif // AsyncFileWriterAndroid_h
