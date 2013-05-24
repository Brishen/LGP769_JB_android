LOCAL_PATH:= $(call my-dir)

#+++ BRCM
# Relative path from <mydroid> to brcm base
BRCM_BT_INC_ROOT_PATH := $(LOCAL_PATH)/../../../../hardware/broadcom/bt
#--- BRCM

#
# libbtio
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	btio.c

LOCAL_CFLAGS:= \
	-DVERSION=\"4.93\" \

#+++ BRCM
ifeq ($(BT_ALT_STACK),true)
LOCAL_CFLAGS += -DBT_ALT_STACK
endif
#--- BRCM

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)/../lib \
	$(LOCAL_PATH)/../gdbus \
	$(call include-path-for, glib) \

#+++ BRCM
ifeq ($(BRCM_BT_USE_BTL_IF),true)
LOCAL_C_INCLUDES += \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/dtun/include \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/dtun/dtunc_bz4 \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/include \

LOCAL_CFLAGS += -DBRCM_BT_USE_BTL_IF -DBT_USE_BTL_IF
endif
#--- BRCM

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libglib \
	libbluetooth \

LOCAL_MODULE:=libbtio

LOCAL_MODULE_TAGS:=optional

include $(BUILD_SHARED_LIBRARY)
