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
# libgcrypt-random
#

include $(CLEAR_VARS)

LOCAL_MODULE := libgcrypt-random
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(LIBGCRYPT_BASE_DIR)/src \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)
LOCAL_SRC_FILES := \
    rand-internal.h \
    random.c \
    random.h \
    random-csprng.c \
    random-fips.c \
    rndhw.c \
    $(empty)
ifeq ($(strip $(GCRYPT_USE_RANDOM_DAEMON)),true)
LOCAL_SRC_FILES += random-daemon.c
endif
LOCAL_SRC_FILES += rndlinux.c

include $(BUILD_STATIC_LIBRARY)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

