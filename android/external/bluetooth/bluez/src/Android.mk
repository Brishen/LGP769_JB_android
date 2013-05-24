LOCAL_PATH:= $(call my-dir)

#+++ BRCM
# Relative path from current dir to vendor brcm
BRCM_BT_SRC_ROOT_PATH := ../../../../hardware/broadcom/bt

# Relative path from <mydroid> to brcm base
BRCM_BT_INC_ROOT_PATH := $(LOCAL_PATH)/../../../../hardware/broadcom/bt
#--- BRCM

#
# libbluetoothd
#

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	android_bluez.c \
	adapter.c \
	agent.c \
	dbus-common.c \
	device.c \
	eir.c \
	error.c \
	event.c \
	glib-helper.c \
	log.c \
	main.c \
	manager.c \
	oob.c \
	oui.c \
	plugin.c \
	rfkill.c \
	sdpd-request.c \
	sdpd-service.c \
	sdpd-server.c \
	sdpd-database.c \
	sdp-xml.c \
	storage.c \
	textfile.c \
	attrib-server.c \
	../attrib/att.c \
	../attrib/client.c \
	../attrib/gatt.c \
	../attrib/gattrib.c \
	../attrib/utils.c \

LOCAL_CFLAGS:= \
	-DVERSION=\"4.93\" \
	-DSTORAGEDIR=\"/data/misc/bluetoothd\" \
	-DCONFIGDIR=\"/etc/bluetooth\" \
	-DSERVICEDIR=\"/system/bin\" \
	-DPLUGINDIR=\"/system/lib/bluez-plugin\" \
	-DANDROID_SET_AID_AND_CAP \
	-DANDROID_EXPAND_NAME \
	-DOUIFILE=\"/data/misc/bluetoothd/ouifile\" \

ifeq ($(BOARD_HAVE_BLUETOOTH_BCM),true)
LOCAL_CFLAGS += \
	-DBOARD_HAVE_BLUETOOTH_BCM
endif

#+++ BRCM
ifeq ($(BT_ALT_STACK),true)
LOCAL_CFLAGS += -DBT_ALT_STACK
endif
#--- BRCM

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)/../attrib \
	$(LOCAL_PATH)/../btio \
	$(LOCAL_PATH)/../lib \
	$(LOCAL_PATH)/../gdbus \
	$(LOCAL_PATH)/../plugins \
	$(call include-path-for, glib) \
	$(call include-path-for, glib)/glib \
	$(call include-path-for, dbus)

#+++ BRCM
ifeq ($(BRCM_BT_USE_BTL_IF),true)
LOCAL_SRC_FILES += \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_clnt.c \
        $(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_sdp.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_device.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_obex.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_hcid.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_pan.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/dtun/dtunc_bz4/dtun_hl.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/btl-if/client/blz20_abort_socket.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/btl-if/client/blz20_wrapper.c  \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/btl-if/client/btl_ifc_wrapper.c \
	$(BRCM_BT_SRC_ROOT_PATH)/adaptation/btl-if/client/btl_ifc.c

LOCAL_C_INCLUDES += \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/dtun/include \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/dtun/dtunc_bz4 \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/btl-if/client \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/btl-if/include \
	$(BRCM_BT_INC_ROOT_PATH)/adaptation/include \
	./system/core/libcutils

LOCAL_CFLAGS += -DBRCM_BT_USE_BTL_IF -DBT_USE_BTL_IF
endif
#--- BRCM

LOCAL_SHARED_LIBRARIES := \
	libdl \
	libbluetooth \
	libbtio \
	libdbus \
	libcutils \
	libglib \

LOCAL_STATIC_LIBRARIES := \
	libbuiltinplugin \
	libgdbus_static

#+++ BRCM
LOCAL_STATIC_LIBRARIES += \
	libxml2
#--- BRCM

LOCAL_MODULE:=libbluetoothd

include $(BUILD_SHARED_LIBRARY)

#
# bluetoothd
#

include $(CLEAR_VARS)

LOCAL_SHARED_LIBRARIES := \
	libbluetoothd

LOCAL_MODULE:=bluetoothd

include $(BUILD_EXECUTABLE)
