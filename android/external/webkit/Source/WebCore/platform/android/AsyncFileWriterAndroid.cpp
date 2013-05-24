/*
 * Copyright (C) 2012 LGE
 */

#include "config.h"
#include "AsyncFileWriterAndroid.h"

#if ENABLE(FILE_SYSTEM)

#include "AsyncFileWriterClient.h"
#include "Blob.h"
#include "BlobRegistry.h"

#include "ResourceError.h"
#include "ResourceRequest.h"
#include "ResourceResponse.h"

namespace WebCore {

Vector<char> getBlobData(Blob* blob)
{
    ResourceRequest request(blob->url());
    request.setHTTPMethod("GET");

    ResourceError error;
    ResourceResponse response;
    Vector<char> responseData;

    blobRegistry().loadResourceSynchronously(request, error, response, responseData);

    return response.httpStatusCode() == 200 ? responseData : Vector<char>();
}

AsyncFileWriterAndroid::AsyncFileWriterAndroid(AsyncFileWriterClient* client, const String& path)
    : m_client(client), m_path(path)
{
}

AsyncFileWriterAndroid::~AsyncFileWriterAndroid()
{
}

void AsyncFileWriterAndroid::write(long long position, Blob* blob)
{
    PlatformFileHandle fileHandle = openFile(m_path, OpenForWriteOnly);
    if (!isHandleValid(fileHandle)) {
        m_client->didFail(FileError::NOT_FOUND_ERR);
        return;
    }

    Vector<char> blobData = getBlobData(blob);
    if (blobData.isEmpty()) {
        closeFile(fileHandle);
        m_client->didFail(FileError::TYPE_MISMATCH_ERR);
        return;
    }

    if (position) {
        if (seekFile(fileHandle, position, SeekFromBeginning) < 0) {
            closeFile(fileHandle);
            m_client->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
            return;
        }
    }

    int writtenBytes = writeToFile(fileHandle, blobData.data(), blobData.size());
    closeFile(fileHandle);

    if (writtenBytes < 0 || writtenBytes != (int)blobData.size()) {
        m_client->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
        return;
    }

    m_client->didWrite((long long)writtenBytes, true);
}

void AsyncFileWriterAndroid::truncate(long long length)
{
    PlatformFileHandle fileHandle = openFile(m_path, OpenForWriteOnly);
    if (!isHandleValid(fileHandle)) {
        m_client->didFail(FileError::NOT_FOUND_ERR);
        return;
    }

    bool truncated = truncateFile(fileHandle, length);
    closeFile(fileHandle);

    if (!truncated) {
        m_client->didFail(FileError::NO_MODIFICATION_ALLOWED_ERR);
        return;
    }

    m_client->didTruncate();
}

void AsyncFileWriterAndroid::abort()
{
}

} // namespace WebCore

#endif // ENABLE(FILE_SYSTEM)
