##################################################################3
#Add libdl static library

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

#LOCAL_LDFLAGS := -Wl,--exclude-libs=libgcc.a

LOCAL_SRC_FILES:= libdl.c

LOCAL_CFLAGS := -DLIBC_STATIC

LOCAL_MODULE:= libdl

ifeq ($(TARGET_ARCH),sh)
# for SuperH, additional code is necessary to handle .ctors section.
GEN_SOBEGIN := $(TARGET_OUT_STATIC_LIBRARIES)/sobegin.o
$(GEN_SOBEGIN): $(LOCAL_PATH)/arch-sh/sobegin.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) -o $@ -c $<

GEN_SOEND := $(TARGET_OUT_STATIC_LIBRARIES)/soend.o
$(GEN_SOEND): $(LOCAL_PATH)/arch-sh/soend.S
	@mkdir -p $(dir $@)
	$(TARGET_CC) -o $@ -c $<

LOCAL_ADDITIONAL_DEPENDENCIES := $(GEN_SOBEGIN) $(GEN_SOEND)
endif
include $(BUILD_STATIC_LIBRARY)
# [120116 jinkwon.jung@lge.com U0] Add BNR_MODE [END]
#################################################################