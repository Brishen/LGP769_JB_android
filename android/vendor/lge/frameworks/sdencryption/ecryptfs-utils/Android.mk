LOCAL_PATH:= $(call my-dir)

## libecryptfs ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/libecryptfs/main.c \
    ./src/libecryptfs/cipher_list.c \
    ./src/libecryptfs/messaging.c \
    ./src/libecryptfs/packets.c \
    ./src/libecryptfs/netlink.c \
    ./src/libecryptfs/miscdev.c \
    ./src/libecryptfs/sysfs.c \
    ./src/libecryptfs/key_management.c \
    ./src/libecryptfs/decision_graph.c \
    ./src/libecryptfs/cmd_ln_parser.c \
    ./src/libecryptfs/module_mgr.c \
    ./src/libecryptfs/key_mod.c \
    ./src/libecryptfs/ecryptfs-stat.c \
    ./src/key_mod/ecryptfs_key_mod_passphrase.c \
    $(empty)


LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libgcrypt \
    libgpg-error \
    libkeyutils  \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= libecryptfs

LOCAL_PRELINK_MODULE := false

LOCAL_MODULE_CLASS := SHARED_LIBRARIES
include $(BUILD_SHARED_LIBRARY)

#
## libecryptfs_key_mod_passphrase ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/key_mod/ecryptfs_key_mod_passphrase.c \
    $(empty)


LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libgcrypt \
    libgpg-error \
    libkeyutils  \
    libecryptfs  \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= libecryptfs_key_mod_passphrase

LOCAL_PRELINK_MODULE := false

LOCAL_MODULE_CLASS := SHARED_LIBRARIES
include $(BUILD_SHARED_LIBRARY)

## ecryptfs_manager ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/manager.c \
    ./src/utils/io.c \
    ./src/utils/io.h \
    ./src/utils/gen_key.c \
    $(empty)


LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs_manager

include $(BUILD_EXECUTABLE)

## ecryptfs_wrap_passphrase ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/ecryptfs_wrap_passphrase.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs_wrap_passphrase

include $(BUILD_EXECUTABLE)


## ecryptfs_unwrap_passphrase ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/ecryptfs_unwrap_passphrase.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs_unwrap_passphrase

include $(BUILD_EXECUTABLE)


## ecryptfs_insert_wrapped_passphrase_into_keyring ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/ecryptfs_insert_wrapped_passphrase_into_keyring.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs_insert_wrapped_passphrase_into_keyring

include $(BUILD_EXECUTABLE)


## ecryptfs_rewrap_passphrase ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/ecryptfs_rewrap_passphrase.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs_rewrap_passphrase

include $(BUILD_EXECUTABLE)


## ecryptfs_add_passphrase ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/ecryptfs_add_passphrase.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs_add_passphrase

include $(BUILD_EXECUTABLE)


## ecryptfs-stat ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/ecryptfs-stat.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= ecryptfs-stat
include $(BUILD_EXECUTABLE)

## test ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/test.c \
    ./src/utils/io.c \
    ./src/utils/io.h \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= test
include $(BUILD_EXECUTABLE)


## mount.ecryptfs ##
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ./src/utils/mount.ecryptfs.c \
    ./src/utils/io.c \
    ./src/utils/io.h \
    ./src/utils/gen_key.c \
    ./src/utils/plaintext_decision_graph.c \
    $(empty)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/src/include \
    $(empty)

LOCAL_SHARED_LIBRARIES := \
    libecryptfs \
    libkeyutils  \
    libgcrypt \
    libgpg-error \
    libutils \
    libdl

LOCAL_CFLAGS := \
    -DHAVE_CONFIG_H \
    $(empty)

LOCAL_MODULE:= mount.ecryptfs

include $(BUILD_EXECUTABLE)
