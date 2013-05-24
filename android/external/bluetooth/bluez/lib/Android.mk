LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	bluetooth.c \
	sdp.c \
	hci.c \
	uuid.c \

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)/bluetooth \

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog \

LOCAL_MODULE:=libbluetooth

LOCAL_CFLAGS+=-O3

#+++ BRCM
ifeq ($(BT_ALT_STACK),true)
LOCAL_CFLAGS += -DBT_ALT_STACK
endif
#--- BRCM

include $(BUILD_SHARED_LIBRARY)
