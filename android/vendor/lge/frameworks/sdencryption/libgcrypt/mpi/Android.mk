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

mpih_add1 := generic/mpih-add1.c
mpih_sub1 := generic/mpih-sub1.c
mpih_mul1 := generic/mpih-mul1.c
mpih_mul2 := generic/mpih-mul2.c
mpih_mul3 := generic/mpih-mul3.c
mpih_lshift := generic/mpih-lshift.c
mpih_rshift := generic/mpih-rshift.c
udiv :=
udiv_qrnnd :=

#
# libgcrypt-mpi
#

include $(CLEAR_VARS)

LOCAL_MODULE := libgcrypt-mpi
LOCAL_C_INCLUDES := \
    $(LIBGCRYPT_BASE_DIR)/ \
    $(LIBGCRYPT_BASE_DIR)/src \
    $(empty)
LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)
LOCAL_SRC_FILES := \
    ec.c \
    longlong.h \
    mpi-add.c \
    mpi-bit.c \
    mpi-cmp.c \
    mpi-div.c \
    mpi-gcd.c \
    mpi-internal.h \
    mpi-inline.h \
    mpi-inline.c \
    mpi-inv.c \
    mpi-mul.c \
    mpi-mod.c \
    mpi-pow.c \
    mpi-mpow.c \
    mpi-scan.c \
    mpicoder.c \
    mpih-div.c \
    mpih-mul.c \
    mpiutil.c \
    $(empty)
LOCAL_SRC_FILES += \
    $(mpih_add1) \
    $(mpih_sub1) \
    $(mpih_mul1) \
    $(mpih_mul2) \
    $(mpih_mul3) \
    $(mpih_lshift) \
    $(mpih_rshift) \
    $(udiv) \
    $(udiv_qrnnd) \
    $(empty)

# According to ARM development manual
# (http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0489c/Cihbjehg.html),
# the UMULL assembly instruction does not have 16-bit Thumb versions.
# Without enforing compilation in arm mode, macro umul_ppmm defined
# in longlong.h will cause build failure.
LOCAL_ARM_MODE := arm

include $(BUILD_STATIC_LIBRARY)

all-libgcrypt-targets: $(LOCAL_MODULE)
clean-all-libgcrypt-targets: clean-$(LOCAL_MODULE)

