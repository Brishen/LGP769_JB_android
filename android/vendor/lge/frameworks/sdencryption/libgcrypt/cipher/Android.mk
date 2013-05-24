# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

GCRYPT_CIPHERS := \
    arcfour \
    blowfish \
    camellia \
    camellia-glue \
    cast5 \
    des \
    rfc2268 \
    rijndael \
    seed \
    serpent \
    twofish \
    $(empty)
GCRYPT_PUBKEY_CIPHERS := \
    dsa \
    ecc \
    elgamal \
    rsa \
    $(empty)
GCRYPT_DIGESTS := \
    crc \
    md4 \
    md5 \
    rmd160 \
    sha1 \
    sha256 \
    sha512 \
    tiger \
    whirlpool \
    $(empty)
GCRYPT_MODULES := \
    $(GCRYPT_CIPHERS) \
    $(GCRYPT_PUBKEY_CIPHERS) \
    $(GCRYPT_DIGESTS) \
    $(empty)

#
# libgcrypt-cipher
#

include $(CLEAR_VARS)

LOCAL_MODULE := libgcrypt-cipher
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(LIBGCRYPT_BASE_DIR)/mpi \
    $(LIBGCRYPT_BASE_DIR)/src \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)
LOCAL_SRC_FILES := \
    ac.c \
    bithelp.h \
    cipher.c \
    hash-common.c \
    hash-common.h \
    hmac-tests.c \
    md.c \
    primegen.c \
    pubkey.c \
    rmd.h \
    $(empty)
LOCAL_SRC_FILES += $(GCRYPT_MODULES:%=%.c)

include $(BUILD_STATIC_LIBRARY)

$(intermediates)/tiger.o: PRIVATE_CFLAGS := $(LOCAL_CFLAGS) -O1

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

