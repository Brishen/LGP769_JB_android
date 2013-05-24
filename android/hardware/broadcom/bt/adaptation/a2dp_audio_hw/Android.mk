LOCAL_PATH:= $(call my-dir)

#
# liba2dp
# This is linked to Audioflinger

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	android_audio_hw.c \
	liba2dp_brcm.c \

LOCAL_SHARED_LIBRARIES := \
	libcutils

LOCAL_SHARED_LIBRARIES += \
	libpower

LOCAL_MODULE := audio.a2dp.default
LOCAL_MODULE_PATH := $(TARGET_OUT_SHARED_LIBRARIES)/hw

ifeq ($(BRCM_A2DP_DEFAULT_SAMPLERATE),48K)
	LOCAL_CFLAGS += -DBRCM_A2DP_DEFAULT_SAMPLERATE_48000
else
	LOCAL_CFLAGS += -DBRCM_A2DP_DEFAULT_SAMPLERATE_44100
endif

LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
