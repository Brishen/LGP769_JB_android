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

#
# libgcrypt-config
#

INSTALLED_LIBGCRYPT_CONFIG_TARGET := $(HOST_OUT_EXECUTABLES)/libgcrypt-config
$(INSTALLED_LIBGCRYPT_CONFIG_TARGET): PRIVATE_IS_HOST_MODULE := true
$(INSTALLED_LIBGCRYPT_CONFIG_TARGET): PRIVATE_MODULE = $(notdir $@)
$(INSTALLED_LIBGCRYPT_CONFIG_TARGET): $(LOCAL_PATH)/libgcrypt-config | $(ACP) gpg-error-config
	$(transform-prebuilt-to-target)

all-libgcrypt-targets: $(INSTALLED_LIBGCRYPT_CONFIG_TARGET)

#
# dumpsexp
#

include $(CLEAR_VARS)
LOCAL_MODULE := dumpsexp
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES :=  \
    dumpsexp.c \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(empty)
include $(BUILD_EXECUTABLE)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

#
# hmac256
#

include $(CLEAR_VARS)
LOCAL_MODULE := hmac256
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES :=  \
    hmac256.c \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    -DSTANDALONE \
    $(empty)
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(empty)
include $(BUILD_EXECUTABLE)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

#
# libgcrypt
#

include $(CLEAR_VARS)
LOCAL_MODULE := libgcrypt
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
    ath.h \
    ath.c \
    cipher.h \
    cipher-proto.h \
    fips.c \
    g10lib.h \
    global.c \
    hmac256.c \
    hmac256.h \
    hwfeatures.c \
    misc.c \
    missing-string.c \
    module.c \
    mpi.h \
    secmem.c \
    secmem.h \
    sexp.c \
    stdmem.c \
    stdmem.h \
    types.h \
    visibility.c \
    visibility.h \
    $(empty)
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(empty)
#   $(LOCAL_PATH)/../../libgpg-error-1.10/src \
    $(empty)
LOCAL_COPY_HEADERS := \
    gcrypt.h \
    gcrypt-module.h \
    $(empty)
LOCAL_SHARED_LIBRARIES := \
    libgpg-error \
    $(empty)
LOCAL_STATIC_LIBRARIES := \
    libgcrypt-cipher \
    libgcrypt-mpi \
    libgcrypt-random 

LOCAL_PRELINK_MODULE := false

include $(BUILD_SHARED_LIBRARY)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

ifeq ($(strip $(GCRYPT_USE_RANDOM_DAEMON)),true)

#
# gcryptrnd
#

include $(CLEAR_VARS)
LOCAL_MODULE := gcryptrnd
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT)/sbin
LOCAL_SRC_FILES :=  \
    gcryptrnd.c \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(empty)
include $(BUILD_EXECUTABLE)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

#
# getrandom
#

include $(CLEAR_VARS)
LOCAL_MODULE := getrandom
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES :=  \
    getrandom.c \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)
LOCAL_SHARED_LIBRARIES := \
    libgcrypt \
    $(empty)
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(empty)
include $(BUILD_EXECUTABLE)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

endif # end of GCRYPT_USE_RANDOM_DAEMON

