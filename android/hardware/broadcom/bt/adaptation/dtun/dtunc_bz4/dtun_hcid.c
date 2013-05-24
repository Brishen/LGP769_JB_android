/************************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2, as published by
 *  the Free Software Foundation (the "GPL").
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  A copy of the GPL is available at http://www.broadcom.com/licenses/GPLv2.php,
 *  or by writing to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *  Boston, MA  02111-1307, USA.
 *
 ************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>
#include <gmain.h>

#include "adapter.h"
#include "event.h"
#include "hcid.h"
#include "textfile.h"
#include "manager.h"
#include "device.h"
#include "storage.h"
#include "error.h"
#include "glib-helper.h"
#include "dbus-common.h"
#include "agent.h"

#include "textfile.h"
#include "error.h"
#include "dtun_device.h"
#include "dtun_clnt.h"
#include "dtun_sdp.h"
#include "dtun_pan.h"
#include "dtun_hl.h"

#include <cutils/properties.h>

/* some local debug macros */
#ifdef DTUN_STANDALONE
#define info(format, ...) fprintf (stdout, format, ## __VA_ARGS__)
#define debug(format, ...) fprintf (stdout, format, ## __VA_ARGS__)
#define error(format, ...) fprintf (stderr, format, ## __VA_ARGS__)
#else
#define LOG_TAG "DTUN_HCID4"
#include "utils/Log.h"
#define info(format, ...) ALOGI (format, ## __VA_ARGS__)
#define debug(format, ...) ALOGD (format, ## __VA_ARGS__)
#define error(format, ...) ALOGE (format, ## __VA_ARGS__)
#endif

#define PRINTFUNC() debug("\t\t%s()\n", __FUNCTION__);

//+++ BRCM_LOCAL
#define DTUN_CHECK_INVALID_COD      TRUE
//--- BRCM_LOCAL

//LG_BTUI : get device name [s]
#define DTUN_DEFAULT_DEV_NAME_FROM_PROPERTY
//LG_BTUI : get device name [e]
#define CHECK_AND_WRITE_DEVICE_TYPE(p_bd_addr, is_le_only) { \
    /* TODO: We need to handle DUMO. Better would be do this in auth_comp */ \
    device_type_t device_type; \
    device_type = read_device_type(&sba, p_bd_addr);  \
    if (device_type == DEVICE_TYPE_UNKNOWN) { \
        info("%s: device_type not stored. Storing now", __FUNCTION__); \
        write_device_type(&sba, p_bd_addr, \
            (is_le_only == true)   ?  DEVICE_TYPE_LE : DEVICE_TYPE_BREDR); \
    } \
}

gboolean get_adapter_and_device(bdaddr_t *src, bdaddr_t *dst,
                    struct btd_adapter **adapter,
                    struct btd_device **device,
                    gboolean create);

extern void dtun_pin_reply( tDTUN_ID id,  pin_code_reply_cp *pr, uint8_t is_le_only);
extern void dtun_ssp_confirm_reply(bdaddr_t *dba, boolean confirm, boolean is_le_only);

extern void dtun_sig_opc_enable(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_opc_open(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_opc_progress(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_opc_object_received(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_opc_object_pushed(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_opc_close(tDTUN_DEVICE_SIGNAL *p_data);

extern void dtun_sig_ops_progress(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_ops_object_received(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_ops_open(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_ops_access_request(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_ops_close(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_op_create_vcard(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_op_owner_vcard_not_set(tDTUN_DEVICE_SIGNAL *p_data);
extern void dtun_sig_op_store_vcard(tDTUN_DEVICE_SIGNAL *p_data);

extern void dtun_sig_dm_local_oob_keys(tDTUN_DEVICE_SIGNAL *msg);

extern void device_fetch_remote_di_info (struct btd_device *device,
    tDTUN_SIG_DM_FETCH_REMOTE_DI_INFO *di_info);
extern void device_fetch_remote_di_rec (struct btd_device *device,
    tDTUN_SIG_DM_FETCH_REMOTE_DI_REC *di_rec);

extern int obex_dbus_init(DBusConnection *in_conn);
extern int sdp_dbus_init(DBusConnection *in_conn);

extern uuid_t *sdp_uuid128_create(uuid_t *u, const void *val);
extern void services_changed_with_empty_uuids(struct btd_device *device);

typedef enum {
    AVDTP_STATE_IDLE,
    AVDTP_STATE_CONFIGURED,
    AVDTP_STATE_OPEN,
    AVDTP_STATE_STREAMING,
    AVDTP_STATE_CLOSING,
    AVDTP_STATE_ABORTING,
} avdtp_state_t;


struct pending_request {
    DBusConnection *conn;
    DBusMessage *msg;
    unsigned int id;
};

struct sink {
    struct audio_device *dev;
    unsigned int cb_id;
    avdtp_state_t state;
    struct pending_request *connect;
    struct pending_request *disconnect;
    DBusConnection *conn;
};

struct pending_get_scn {
    DBusConnection *conn;
    DBusMessage *msg;
    uint16_t uuid16;
};

static GMainLoop *event_loop;
static struct btd_adapter *adapter;
static DBusConnection *sig_connection = NULL;

static unsigned char dtun_pending_get_services_flg = 0;
static bdaddr_t      dtun_pending_get_services_adr;
static bdaddr_t      dtun_pending_fetch_remote_di_addr = { {0} };

static bdaddr_t sba = { {0x11, 0x22, 0x33, 0x44, 0x55, 0x66} };

struct sink *sink_init(struct audio_device *dev);


#define AUDIO_SINK_INTERFACE "org.bluez.AudioSink"

#define GENERIC_AUDIO_UUID  "00001203-0000-1000-8000-00805F9B34FB"

#define HSP_HS_UUID     "00001108-0000-1000-8000-00805F9B34FB"
#define HSP_AG_UUID     "00001112-0000-1000-8000-00805F9B34FB"

#define HFP_HS_UUID     "0000111E-0000-1000-8000-00805F9B34FB"
#define HFP_AG_UUID     "0000111F-0000-1000-8000-00805F9B34FB"

#define ADVANCED_AUDIO_UUID "0000110D-0000-1000-8000-00805F9B34FB"

#define A2DP_SOURCE_UUID    "0000110A-0000-1000-8000-00805F9B34FB"
#define A2DP_SINK_UUID      "0000110B-0000-1000-8000-00805F9B34FB"

#define AVRCP_REMOTE_UUID   "0000110E-0000-1000-8000-00805F9B34FB"
#define AVRCP_TARGET_UUID   "0000110C-0000-1000-8000-00805F9B34FB"

#define HID_SERVICE_UUID "00001124-0000-1000-8000-00805f9b34fb"

#define PANU_UUID   "00001115-0000-1000-8000-00805f9b34fb"
#define NAP_UUID    "00001116-0000-1000-8000-00805f9b34fb"
#define GN_UUID     "00001117-0000-1000-8000-00805f9b34fb"

#define SERIAL_PORT_UUID    "00001101-0000-1000-8000-00805F9B34FB"
#define DIALUP_NET_UUID     "00001103-0000-1000-8000-00805F9B34FB"

#define SYNC_UUID "00001104-0000-1000-8000-00805F9B34FB"
#define OPP_UUID "00001105-0000-1000-8000-00805F9B34FB"

#define FILE_TRANSFER_UUID "00001106-0000-1000-8000-00805F9B34FB"

#define CTP_UUID "00001109-0000-1000-8000-00805F9B34FB"
#define ICP_UUID "00001110-0000-1000-8000-00805F9B34FB"

#define BPP_UUID "00001122-0000-1000-8000-00805F9B34FB"

#define FAX_UUID "00001111-0000-1000-8000-00805F9B34FB"
#define LAP_UUID "00001102-0000-1000-8000-00805F9B34FB"

#define BIP_UUID "0000111A-0000-1000-8000-00805F9B34FB"
#define PBAP_UUID "00001130-0000-1000-8000-00805F9B34FB"

#define VIDEO_DIST_UUID "00001305-0000-1000-8000-00805F9B34FB"
#define SIM_ACC_UUID "0000112D-0000-1000-8000-00805F9B34FB"

//MAP related uuids
#define MAP_UUID "00001134-0000-1000-8000-00805F9B34FB"
#define MSE_UUID "00001132-0000-1000-8000-00805F9B34FB"
#define MNS_UUID "00001133-0000-1000-8000-00805F9B34FB"

//HDP related uuids
#define HDP_UUID        "00001400-0000-1000-8000-00805F9B34FB"
#define HDP_SOURCE_UUID "00001401-0000-1000-8000-00805F9B34FB"
#define HDP_SINK_UUID   "00001402-0000-1000-8000-00805F9B34FB"

//GATT related UUIDs
#define GATT_UUID   "00001801-0000-1000-8000-00805F9B34FB"
#define GAP_UUID    "00001800-0000-1000-8000-00805F9B34FB"
#define IMMEDIATE_ALERT_UUID  "00001802-0000-1000-8000-00805F9B34FB"
#define LINKLOSS_UUID         "00001803-0000-1000-8000-00805F9B34FB"
#define TX_POWER_UUID         "00001804-0000-1000-8000-00805F9B34FB"
#define TEST_SERVER_UUID      "00009000-0000-1000-8000-00805F9B34FB"

//undesirable service
#define IMAGING_RESPONDER_UUID  "0000111B-0000-1000-8000-00805F9B34FB"
#define PBAP_PSE_UUID           "0000112f-0000-1000-8000-00805F9B34FB"
#define MAP_SERVER_UUID         "00001132-0000-1000-8000-00805F9B34FB"


#define COD_SERVICE_MASK                     0xFFE000
#define COD_SERVICE_LIMITED_DISCOVERABILITY  0x002000
#define COD_SERVICE_POSITIONING              0x010000
#define COD_SERVICE_NETWORKING               0x020000
#define COD_SERVICE_RENDER                   0x040000
#define COD_SERVICE_CAPTURE                  0x080000
#define COD_SERVICE_OBJECT_TRANSFER          0x100000
#define COD_SERVICE_AUDIO                    0x200000
#define COD_SERVICE_TELEPHONY                0x400000
#define COD_SERVICE_INFORMATION              0x800000

#define COD_MAJOR_CLS_MASK               0x1F00

#define COD_MAJOR_CLS_MISC               0x0000
#define COD_MAJOR_CLS_COMPUTER           0x0100
#define COD_MAJOR_CLS_PHONE              0x0200
#define COD_MAJOR_CLS_NETWORKING         0x0300
#define COD_MAJOR_CLS_AUDIO_VIDEO        0x0400
#define COD_MAJOR_CLS_PERIPHERAL         0x0500
#define COD_MAJOR_CLS_IMAGING            0x0600
#define COD_MAJOR_CLS_WEARABLE           0x0700
#define COD_MAJOR_CLS_TOY                0x0800
#define COD_MAJOR_CLS_HEALTH             0x0900
#define COD_MAJOR_CLS_UNCATEGORIZED      0x1F00

#define COD_AUDIO_VIDEO_HIFI_AUDIO       0x0428
#define COD_AUDIO_VIDEO_HEADPHONES       0x0418
#define COD_AUDIO_VIDEO_LOUDSPEAKER      0x0414
#define COD_AUDIO_VIDEO_CAR_AUDIO        0x0420

/* NOTE: This table should match Service IDs defined in bta_api.h */
const char *dtunc_uuid_table[] =
{
    PNP_UUID,
    SERIAL_PORT_UUID,
    DIALUP_NET_UUID,
    FAX_UUID,           /* Fax profile. */
    LAP_UUID,          /* LAN access profile. */
    HSP_HS_UUID,          /* Headset profile. */
    HFP_HS_UUID,          /* Hands-free profile. */
    OPP_UUID,          /* Object push  */
    FILE_TRANSFER_UUID, /* File transfer */
    CTP_UUID,           /* Cordless Terminal */
    ICP_UUID,          /* Intercom Terminal */
    SYNC_UUID,          /* Synchronization */
    BPP_UUID,          /* Basic printing profile */
    BIP_UUID,          /* Basic Imaging profile */
    PANU_UUID,          /* PAN User */
    NAP_UUID,          /* PAN Network access point */
    GN_UUID,         /* PAN Group Ad-hoc networks */
    SIM_ACC_UUID,          /* SIM Access profile */
    A2DP_SINK_UUID,          /* Advanced audio distribution */
    AVRCP_REMOTE_UUID,          /* A/V remote control */
    HID_SERVICE_UUID,          /* HID */
    VIDEO_DIST_UUID,          /* Video distribution */
    PBAP_UUID,          /* PhoneBook Access - server */
    HSP_AG_UUID,          /* HSP HS role */
    HFP_AG_UUID,          /* HFP HS role */
    MAP_UUID,        /* Message Access Profile */
    MAP_UUID,        /* Message Access Profile - Message Notification Service */
    HDP_SOURCE_UUID, /* HDP */
    HDP_SINK_UUID,
    PBAP_UUID        /* PhoneBook Access - client */
};

const char * dtunc_uuid_exclusion_list[] =
{
    IMAGING_RESPONDER_UUID,
    PBAP_PSE_UUID,
    MAP_SERVER_UUID,
    NULL
};

#define DTUN_NUM_UUIDS_IN_TABLE  30

boolean dtun_auth_on = false;
tDTUN_SIG_DM_AUTHORIZE_REQ_INFO dtun_cur_authorize_req_info;

#define MAX_EXPOSED_SDP_HANDLES 32
#define FREE_EXPOSED_HANDLE 0xFFFFFFFF
#define ASSIGNED_EXPOSED_HANDLE 0xFFFFFFFE

uint32_t sdp_handles[MAX_EXPOSED_SDP_HANDLES]; //SDP handles

//+++ BRCM_LOCAL : [CASE#437592] Fix ASCII validation error(ASCII Control character or extended ASCII). Without the fix remote device name will be over-written to just dots only when RNR completed.
static int invalid_utf8_pos = 0;
//--- BRCM LOCAL

static const char *state2str(avdtp_state_t state)
{
        switch (state) {
        case AVDTP_STATE_IDLE:
                return "disconnected";
        case AVDTP_STATE_CONFIGURED:
                return "connecting";
        case AVDTP_STATE_OPEN:
                return "connected";
        case AVDTP_STATE_STREAMING:
                return "playing";
        default:
                error("Invalid sink state %d", state);
                return NULL;
        }
};

static int dtun_stricmp(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL){
        return -1;
    }

    for (; *str1 != '\0' && *str2 != '\0' && tolower(*str1) == tolower(*str2); str1++, str2++);
    if (*str1 == '\0')
        return *str2 == '\0'? 0 : -1;
    else if (*str2 == '\0')
        return 1;
    else
        return tolower(*str1) < tolower(*str2)? -1 : 1;
}

/*******************************************************************************
**
** Function          DTUN DM CLIENT TEST  (DBUS SERVER SIDE)
**
*/
void dtun_read_dev_info(const bdaddr_t *src_ba, const bdaddr_t *dest_ba, uint8_t *p_device_type, uint32_t *p_addr_type)
{
    *p_device_type  =  read_device_type(src_ba, dest_ba);
    if ( (*p_device_type == DEVICE_TYPE_UNKNOWN) || (*p_device_type > DEVICE_TYPE_DUALMODE ))
    {
        *p_device_type = DEVICE_TYPE_BREDR;
    }
    read_address_type(src_ba,dest_ba, p_addr_type);
    debug("%s dtun_read_dev_info device_type=0x%x addr_type=0x%x",__FUNCTION__,   *p_device_type, *p_addr_type);
}
void dtun_add_ble_dev_info( const bdaddr_t *dest_ba , uint8_t device_type, uint32_t addr_type)
{
    tDTUN_DEVICE_METHOD method;
    debug("dtun_add_ble_dev_info  dev_type=0x%x addr_type=0x%x", device_type, addr_type);
    memcpy(method.add_ble_dev.info.bd_addr.b, dest_ba->b, 6);
    method.add_ble_dev.info.device_type = device_type;
    method.add_ble_dev.info.addr_type = addr_type;
    method.add_ble_dev.info.key_mask = 0;
    method.add_ble_dev.hdr.id = DTUN_METHOD_DM_BLE_ADD_DEV;
    method.add_ble_dev.hdr.len = sizeof(tDTUN_METHOD_DM_ADD_BLE_DEV_INFO);
    dtun_client_call_method(&method);
}

void dtun_add_ble_device_do_append(char * key,char * value, uint8_t *p_device_type, gboolean *is_paired_device)
{
    tDTUN_DEVICE_METHOD method;
    uint32_t            addr_type;
    int                 length = 0;
    PRINTFUNC();
    str2ba(key,&method.add_ble_dev.info.bd_addr);

    //get device type
    method.add_ble_dev.info.device_type =
    *p_device_type                      =  read_device_type(&sba, &method.add_ble_dev.info.bd_addr);

    if ( (*p_device_type == DEVICE_TYPE_UNKNOWN) || (*p_device_type > DEVICE_TYPE_DUALMODE ))
    {
        *p_device_type = DEVICE_TYPE_BREDR;
        return;
    }
    else if (*p_device_type != DEVICE_TYPE_LE)
    {
        return;
    }
    //read address type from the store
    read_address_type(&sba, &method.add_ble_dev.info.bd_addr, &addr_type );

    method.add_ble_dev.info.addr_type = addr_type;
    //get the keys if available

    method.add_ble_dev.info.key_mask = 0;

    //enc key
    if ( !read_ble_link_key(&sba, &method.add_ble_dev.info.bd_addr,
                            DTUN_LE_KEY_PENC,
                            &length,
                            (unsigned char *)(method.add_ble_dev.info.enc_key_info.ltk)) )
    {
        if ( length != 0 )
        {
            method.add_ble_dev.info.key_mask |= DTUN_LE_KEY_PENC;
        }
    }

    //pid key
    length = 0;
    if ( !read_ble_link_key(&sba, &method.add_ble_dev.info.bd_addr,
                            DTUN_LE_KEY_PID,
                            &length,
                            (unsigned char *)(method.add_ble_dev.info.devid_key_info.pid_key)) )
    {
        if ( length != 0 )
        {

            method.add_ble_dev.info.key_mask |= DTUN_LE_KEY_PID;
        }
    }


    //pcsrk key
    length = 0;
    if ( !read_ble_link_key(&sba, &method.add_ble_dev.info.bd_addr,
                            DTUN_LE_KEY_PCSRK,
                            &length,
                            (unsigned char *)&(method.add_ble_dev.info.pcsrk_key_info.counter)) )
    {
        if ( length != 0 )
        {

            method.add_ble_dev.info.key_mask |= DTUN_LE_KEY_PCSRK;
        }
    }

    //lenc key
    length = 0;
    if ( !read_ble_link_key(&sba, &method.add_ble_dev.info.bd_addr,
                            DTUN_LE_KEY_LENC,
                            &length,
                            (unsigned char *)&(method.add_ble_dev.info.lenc_key_info.div)) )
    {
        if ( length != 0 )
        {

            method.add_ble_dev.info.key_mask |= DTUN_LE_KEY_LENC;
        }
    }


    //lcsrk
    length = 0;
    if ( !read_ble_link_key(&sba, &method.add_ble_dev.info.bd_addr,
                            DTUN_LE_KEY_LCSRK,
                            &length,
                            (unsigned char *)&(method.add_ble_dev.info.lcsrk_key_info.counter)) )
    {
        if ( length != 0 )
        {

            method.add_ble_dev.info.key_mask |= DTUN_LE_KEY_LCSRK;
        }
    }

    if ( method.add_ble_dev.info.key_mask != 0)
    {
        debug("%s method.add_ble_dev.info.key_mask=0x%x",__FUNCTION__,  method.add_ble_dev.info.key_mask);
        *is_paired_device = TRUE;
    }
    else
    {
        debug("%s method.add_ble_dev.info.key_mask=0x%x",__FUNCTION__,  method.add_ble_dev.info.key_mask);
        *is_paired_device = FALSE;
        return;
    }
    method.add_ble_dev.hdr.id = DTUN_METHOD_DM_BLE_ADD_DEV;
    method.add_ble_dev.hdr.len = sizeof(tDTUN_METHOD_DM_ADD_BLE_DEV_INFO);
    dtun_client_call_method(&method);

}


void dtun_add_devices_do_append(char *key, char *value)
{
    tDTUN_DEVICE_METHOD method;
    char tmp[3], *str = value;
    int i;

    PRINTFUNC();

    info( "key = %s value = %s" , key, value );

    str2ba(key, &method.add_dev.info.bd_addr);

    memset(tmp, 0, sizeof(tmp));
    for (i = 0; i < 16; i++) {
        memcpy(tmp, str + (i * 2), 2);
        method.add_dev.info.key[i] = (uint8_t) strtol(tmp, NULL, 16);
    }

    memcpy(tmp, str + 33, 2);
    method.add_dev.info.key_type = (uint8_t) strtol(tmp, NULL, 10);

    method.add_dev.hdr.id = DTUN_METHOD_DM_ADD_DEV;
    method.add_dev.hdr.len = sizeof(tDTUN_METHOD_DM_ADD_DEV_INFO);
    dtun_client_call_method(&method);

}

void dtun_init_device_uuid(struct btd_device *device, char *str_uuid)
{
    bdaddr_t bdaddr;
    struct audio_device *audio_dev;

    info("Adding uuid %s", str_uuid);

//+++ BRCM_LOCAL
    /* original
    if (strcmp(str_uuid, A2DP_SINK_UUID) == 0) {
     */
    if (strncasecmp(str_uuid, A2DP_SINK_UUID, sizeof(A2DP_SINK_UUID)) == 0) {
//--- BRCM_LOCAL
        info("Calling sink_init");
        device_get_address(device, &bdaddr);
        audio_dev = manager_get_device(sig_connection, &sba, &bdaddr, TRUE);
        if (audio_dev != NULL) {
            audio_dev->sink = sink_init(audio_dev);
        }
        else {
            error("Couldn't get device pointer, just return...");
        }
    }
    else if (dtun_stricmp(str_uuid, HDP_SOURCE_UUID) == 0) {
        info("Calling hdp_device_register");
        if (!hl_device_register(sig_connection, device)) {
            error("Couldn't register hdp device interface, just return...");
        }
    }
}

void dtun_remove_hdp_device(struct btd_device *device){
    hl_device_unregister(device);

}

int dtunops_setup(void)
{
    info("%s", __FUNCTION__);
    //Register any bluez device driver here before the adapter initialized
    pan_register_device_driver(sig_connection);

    btd_manager_register_adapter(0);

    adapter = manager_find_adapter_by_id(0);
    if (!adapter) {
        error("Getting device data failed: hci0");
        return -1;
    }

    pan_dbus_init(adapter);
    hl_dbus_init(sig_connection);

    btd_adapter_start(adapter);

    obex_dbus_init(sig_connection);
    sdp_dbus_init(sig_connection);

    //Sync adapter COD by starting the DTUN get_class request
    // dtunops_get_class(0); // TBD: Wenbin: This function is removed in 4.93

//TODO: adapter_update_ssp_mode(adapter, mode);
    return 0;
}

void dtunops_cleanup(void)
{
    info("%s", __FUNCTION__);
}

int dtunops_set_powered(int index, gboolean powered)
{
    tDTUN_DEVICE_METHOD method;

    error("dtunops_set_powered called powered = %d", powered);

    if (!powered) {
        method.set_mode.hdr.id = DTUN_METHOD_DM_SET_MODE;
        method.set_mode.hdr.len = 1; // no payload
        method.set_mode.mode  =  MODE_OFF;
        dtun_client_call_method(&method);
        adapter_mode_changed(adapter, SCAN_DISABLED);

        // inform btld of powered off , so that btld does cleanup(sockets,etc)
        // when app doesnt properly cleanup
        method.set_mode.hdr.id = DTUN_METHOD_DM_POWERED_OFF;
        method.set_mode.hdr.len = 1; // no payload
        method.set_mode.mode  =  MODE_OFF;
        dtun_client_call_method(&method);
    }
    else {
        error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    }

    return 0;
}

// TBD: Wenbin: 4.93 added argument discoverable. Need handle it
int dtunops_set_discoverable(int index, gboolean discoverable)
{
    tDTUN_DEVICE_METHOD method;

    error("dtun_hcid - %s: index = %d, discoverable = %d", __FUNCTION__, index, discoverable);

    method.set_mode.hdr.id = DTUN_METHOD_DM_SET_MODE;
    method.set_mode.hdr.len = 1; // no payload
    method.set_mode.mode  =  (discoverable ? MODE_DISCOVERABLE : MODE_CONNECTABLE);

    dtun_client_call_method(&method);

    adapter_mode_changed(adapter, (discoverable ? (SCAN_PAGE|SCAN_INQUIRY) : (SCAN_PAGE) ));

    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_set_pairable(int index, gboolean pairable)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    error("dtun_hcid - %s: index = %d, pairable = %d", __FUNCTION__, index, pairable);
    return 0;
}

int dtunops_set_limited_discoverable(int index, gboolean limited)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

int dtunops_start_discovery(int index)
{
    dtun_client_call_id_only(DTUN_METHOD_DM_START_DISCOVERY);
    return 0;
}

int dtunops_stop_discovery(int index)
{
    dtun_client_call_id_only(DTUN_METHOD_DM_CANCEL_DISCOVERY);
    return 0;
}

int dtunops_resolve_name(int index, bdaddr_t *bdaddr)
{
    tDTUN_DEVICE_METHOD method;
    read_local_name_rp rp;

    info("%s: bdaddr = [%02x:%02x:%02x:%02x:%02x:%02x]\n", __FUNCTION__,
         bdaddr->b[0], bdaddr->b[1], bdaddr->b[2],
         bdaddr->b[3], bdaddr->b[4], bdaddr->b[5]);

    method.resolve_name.hdr.id = DTUN_METHOD_DM_RESOLVE_NAME;
    method.resolve_name.hdr.len = 6;

    memcpy(method.resolve_name.bd_addr.b, bdaddr->b, 6);

    dtun_client_call_method(&method);
    return 0;
}

int dtunops_cancel_resolve_name(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

int dtunops_set_name(int index, const char *name)
{
    tDTUN_DEVICE_METHOD method;

    method.set_name.hdr.id = DTUN_METHOD_DM_SET_NAME;
    method.set_name.hdr.len = DTUN_MAX_DEV_NAME_LEN;
    strncpy( method.set_name.name, name, DTUN_MAX_DEV_NAME_LEN);

    dtun_client_call_method(&method);

    adapter_update_local_name(adapter, name);
    sched_yield();

    return 0;
}

int dtunops_set_dev_class(int index, uint8_t major, uint8_t minor)
{
    tDTUN_DEVICE_METHOD method;

    method.set_class.hdr.id = DTUN_METHOD_DM_SET_CLASS;
    method.set_class.hdr.len = sizeof(uint32_t);
    method.set_class.major = major;
    method.set_class.minor = minor;
    dtun_client_call_method(&method);

    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_set_fast_connectable(int index, gboolean enable)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    error("dtun_hcid - %s: index = %d, enable = %d", __FUNCTION__, index, enable);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_read_clock(int index, bdaddr_t *bdaddr, int which, int timeout,
                       uint32_t *clock, uint16_t *accuracy)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

int dtunops_read_bdaddr(int index, bdaddr_t *bdaddr)
{
    memcpy(bdaddr->b, sba.b, 6);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_block_device(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_unblock_device(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_get_conn_list(int index, GSList **conns)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_read_local_features(int index, uint8_t *features)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_disconnect(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_remove_bonding(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_pincode_reply(int index, bdaddr_t *bdaddr, const char *pin, size_t pin_len)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_confirm_reply(int index, bdaddr_t *bdaddr, gboolean success)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_passkey_reply(int index, bdaddr_t *bdaddr, uint32_t passkey)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_enable_le(int index)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_encrypt_link(int index, bdaddr_t *bdaddr, bt_hci_result_t cb, gpointer user_data)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_set_did(int index, uint16_t vendor, uint16_t product, uint16_t version)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_add_uuid(int index, uuid_t *uuid, uint8_t svc_hint)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_remove_uuid(int index, uuid_t *uuid)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_disable_cod_cache(int index)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_restore_powered(int index)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_load_keys(int index, GSList *keys, gboolean debug_keys)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_set_io_capability(int index, uint8_t io_capability)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_create_bonding(int index, bdaddr_t *bdaddr, uint8_t io_cap)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_cancel_bonding(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_read_local_oob_data(int index)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_add_remote_oob_data(int index, bdaddr_t *bdaddr, uint8_t *hash,
                                uint8_t *randomizer)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_remove_remote_oob_data(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_set_link_timeout(int index, bdaddr_t *bdaddr, uint32_t num_slots)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

// TBD: Wenbin: 4.93 new method
int dtunops_retry_authentication(int index, bdaddr_t *bdaddr)
{
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
    return 0;
}

static struct btd_adapter_ops dtun_ops = {
    .setup = dtunops_setup,
    .cleanup = dtunops_cleanup,
    .set_powered = dtunops_set_powered,
    .set_discoverable = dtunops_set_discoverable,
    .set_pairable = dtunops_set_pairable,
    .set_limited_discoverable = dtunops_set_limited_discoverable,
    .start_discovery = dtunops_start_discovery,
    .stop_discovery = dtunops_stop_discovery,
    .resolve_name = dtunops_resolve_name,
    .cancel_resolve_name = dtunops_cancel_resolve_name,
    .set_name = dtunops_set_name,
    .set_dev_class = dtunops_set_dev_class,
    .set_fast_connectable = dtunops_set_fast_connectable,
    .read_clock = dtunops_read_clock,
    .read_bdaddr = dtunops_read_bdaddr,
    .block_device = dtunops_block_device,
    .unblock_device = dtunops_unblock_device,
    .get_conn_list = dtunops_get_conn_list,
    .read_local_features = dtunops_read_local_features,
    .disconnect = dtunops_disconnect,
    .remove_bonding = dtunops_remove_bonding,
    .pincode_reply = dtunops_pincode_reply,
    .confirm_reply = dtunops_confirm_reply,
    .passkey_reply = dtunops_passkey_reply,
    .enable_le = dtunops_enable_le,
    .encrypt_link = dtunops_encrypt_link,
    .set_did = dtunops_set_did,
    .add_uuid = dtunops_add_uuid,
    .remove_uuid = dtunops_remove_uuid,
    .disable_cod_cache = dtunops_disable_cod_cache,
    .restore_powered = dtunops_restore_powered,
    .load_keys = dtunops_load_keys,
    .set_io_capability = dtunops_set_io_capability,
    .create_bonding = dtunops_create_bonding,
    .cancel_bonding = dtunops_cancel_bonding,
    .read_local_oob_data = dtunops_read_local_oob_data,
    .add_remote_oob_data = dtunops_add_remote_oob_data,
    .remove_remote_oob_data = dtunops_remove_remote_oob_data,
    .set_link_timeout = dtunops_set_link_timeout,
    .retry_authentication = dtunops_retry_authentication,


    // .read_name = dtunops_read_name,
    // .set_connectable = dtunops_set_connectable,
};

void dtun_dm_sig_local_info(tDTUN_DEVICE_SIGNAL *msg)
{
    tDTUN_DEVICE_METHOD method;
    char str[DTUN_MAX_DEV_NAME_LEN + 1];
    char *str_ptr = str;
    int retval;
    int i;

    PRINTFUNC();

    memcpy( &sba, msg->local_info.bdaddr.b, 6 );

    btd_register_adapter_ops(&dtun_ops, FALSE);
    adapter_ops_setup();

    retval = read_local_name(&sba, str);

    /* the Customer needs to modify this to put the customized phone name */
    if( retval < 0 )
//LG_BTUI : get device name [s]
#ifdef DTUN_DEFAULT_DEV_NAME_FROM_PROPERTY
//                                                                     
    {
        char country[DTUN_MAX_DEV_NAME_LEN];
        property_get("ro.build.target_country", country, DTUN_DEFAULT_DEV_NAME);  
        property_get("ro.product.model", str, DTUN_DEFAULT_DEV_NAME);
        if(!strcmp(str,"LG-P768"))
        {
            if(!strcmp(country,"MX"))
            {
                strcat(str,"g");
            }
            else if(!strcmp(country,"BR"))
            {	
                strcat(str,"f");
            }
        }		  
    }
//                                               
	//property_get("ro.product.model", str, DTUN_DEFAULT_DEV_NAME);
#else
        strcpy( str, DTUN_DEFAULT_DEV_NAME );
#endif
//LG_BTUI : get device name [e]

    method.set_name.hdr.id = DTUN_METHOD_DM_SET_NAME;
    method.set_name.hdr.len = DTUN_MAX_DEV_NAME_LEN;
    strncpy( method.set_name.name, str, DTUN_MAX_DEV_NAME_LEN);
    method.set_name.name[DTUN_MAX_DEV_NAME_LEN] = 0;

    dtun_client_call_method(&method);

    str[DTUN_MAX_DEV_NAME_LEN] = 0;
    adapter_update_local_name(adapter, str);
    sched_yield();

    for (i = 0; i < MAX_EXPOSED_SDP_HANDLES; i++)
        sdp_handles[i] = FREE_EXPOSED_HANDLE; //SDP handles
}

void dtun_dm_sig_discovery_started(tDTUN_DEVICE_SIGNAL *msg)
{
    /* send start discovery started signal in dbus srv */
    PRINTFUNC();

    adapter_set_state(adapter, STATE_DISCOV);
}

/* send  discovery complete signal in dbus srv */
void dtun_dm_sig_discovery_complete(tDTUN_DEVICE_SIGNAL *msg)
{
    PRINTFUNC();

    adapter_set_state(adapter, STATE_IDLE);
}
/* Unicode macros and utf8_validate() from GLib Owen Taylor, Havoc
 * Pennington, and Tom Tromey are the authors and authorized relicense.
 */

/** computes length and mask of a unicode character
 * @param Char the char
 * @param Mask the mask variable to assign to
 * @param Len the length variable to assign to
 */
#define UTF8_COMPUTE(Char, Mask, Len)                         \
  if (Char < 128)                                 \
    {                                         \
      Len = 1;                                    \
      Mask = 0x7f;                                \
    }                                         \
  else if ((Char & 0xe0) == 0xc0)                         \
    {                                         \
      Len = 2;                                    \
      Mask = 0x1f;                                \
    }                                         \
  else if ((Char & 0xf0) == 0xe0)                         \
    {                                         \
      Len = 3;                                    \
      Mask = 0x0f;                                \
    }                                         \
  else if ((Char & 0xf8) == 0xf0)                         \
    {                                         \
      Len = 4;                                    \
      Mask = 0x07;                                \
    }                                         \
  else if ((Char & 0xfc) == 0xf8)                         \
    {                                         \
      Len = 5;                                    \
      Mask = 0x03;                                \
    }                                         \
  else if ((Char & 0xfe) == 0xfc)                         \
    {                                         \
      Len = 6;                                    \
      Mask = 0x01;                                \
    }                                         \
  else                                                                        \
    {                                                                         \
      Len = 0;                                                               \
      Mask = 0;                                                               \
    }

/**
 * computes length of a unicode character in UTF-8
 * @param Char the char
 */
#define UTF8_LENGTH(Char)              \
  ((Char) < 0x80 ? 1 :                 \
   ((Char) < 0x800 ? 2 :               \
    ((Char) < 0x10000 ? 3 :            \
     ((Char) < 0x200000 ? 4 :          \
      ((Char) < 0x4000000 ? 5 : 6)))))

/**
 * Gets a UTF-8 value.
 *
 * @param Result variable for extracted unicode char.
 * @param Chars the bytes to decode
 * @param Count counter variable
 * @param Mask mask for this char
 * @param Len length for this char in bytes
 */
#define UTF8_GET(Result, Chars, Count, Mask, Len)                 \
  (Result) = (Chars)[0] & (Mask);                         \
  for ((Count) = 1; (Count) < (Len); ++(Count))                   \
    {                                         \
      if (((Chars)[(Count)] & 0xc0) != 0x80)                      \
    {                                     \
      (Result) = -1;                              \
      break;                                  \
    }                                     \
      (Result) <<= 6;                                 \
      (Result) |= ((Chars)[(Count)] & 0x3f);                      \
    }

/**
 * Check whether a unicode char is in a valid range.
 *
 * @param Char the character
 */
#define UNICODE_VALID(Char)                   \
    ((Char) < 0x110000 &&                     \
     (((Char) & 0xFFFFF800) != 0xD800) &&     \
     ((Char) < 0xFDD0 || (Char) > 0xFDEF) &&  \
     ((Char) & 0xFFFF) != 0xFFFF)



gboolean utf8_validate  (const char *str,
                             int               start,
                             int               len)
{
  const unsigned char *p;
  const unsigned char *end;

  p = str + start;
  end = p + len;

  while (p < end)
    {
      int i, mask, char_len;
      unsigned int result;

      /* nul bytes considered invalid */
      if (*p == '\0')
        break;

      /* Special-case ASCII; this makes us go a lot faster in
       * D-Bus profiles where we are typically validating
       * function names and such. We have to know that
       * all following checks will pass for ASCII though,
       * comments follow ...
       */
      if (*p < 128)
        {
          ++p;
          continue;
        }

      UTF8_COMPUTE (*p, mask, char_len);

      if (char_len == 0)  /* ASCII: char_len == 1 */
        break;

      /* check that the expected number of bytes exists in the remaining length */
//+++ BRCM_LOCAL : [CASE#437592] Fix ASCII validation error(ASCII Control character or extended ASCII). Without the fix remote device name will be over-written to just dots only when RNR completed.
#if 0	// original
      if (end - p < char_len) /* ASCII: p < end and char_len == 1 */
        break;
#else
      if (end - p < char_len) /* ASCII: p < end and char_len == 1 */
        {
          invalid_utf8_pos = (int)((unsigned char*)p - ((unsigned char*)str + start));
          error("utf8_validate : str = 0x%x, p = 0x%x, char_len =  %d", str, p, char_len);
          break;
        }
#endif
//--- BRCM_LOCAL

      UTF8_GET (result, p, i, mask, char_len);

      /* Check for overlong UTF-8 */
      if (UTF8_LENGTH (result) != char_len) /* ASCII: UTF8_LENGTH == 1 */
        break;
#if 0
      /* The UNICODE_VALID check below will catch this */
      if (_DBUS_UNLIKELY (result == (dbus_unichar_t)-1)) /* ASCII: result = ascii value */
        break;
#endif

      if (!UNICODE_VALID (result)) /* ASCII: always valid */
        break;

      /* UNICODE_VALID should have caught it */
      //assert(result != -1);

      p += char_len;
    }

  /* See that we covered the entire length if a length was
   * passed in
   */
  return p == end;
}


static inline void copy_device_name(char* dest, const char* src)
{
    int len = strlen(src);
    if(len > DTUN_MAX_DEV_NAME_LEN)
        len = DTUN_MAX_DEV_NAME_LEN;
//+++ BRCM_LOCAL : [CASE#437592] Fix ASCII validation error(ASCII Control character or extended ASCII). Without the fix remote device name will be over-written to just dots only when RNR completed.
    invalid_utf8_pos = 0;
//--- BRCM_LOCAL
    gboolean bValidUtf8 = utf8_validate(src, 0, len);
    int i;
    for(i = 0; i < len; i++)
    {
//+++ BRCM_LOCAL : [CASE#437592] Fix ASCII validation error(ASCII Control character or extended ASCII). Without the fix remote device name will be over-written to just dots only when RNR completed.
#if 0
        if(src[i] <= 31 || src[i] == 127 || (!bValidUtf8 && (unsigned char)src[i] >= 128))
#else
        if(src[i] <= 31 || src[i] == 127 || (!bValidUtf8 && (unsigned char)src[i] >= 128) && (i >= invalid_utf8_pos))
#endif
//--- BRCM_LOCAL
            dest[i] = '.';
        else dest[i] = src[i];
    }
    dest[i] = 0;
}


void dtun_dm_sig_rmt_name(tDTUN_DEVICE_SIGNAL *msg)
{
    char name[DTUN_MAX_DEV_NAME_LEN+1];
    char old_name[DTUN_MAX_DEV_NAME_LEN+1];
    char src[18];
    char dst[18];

    PRINTFUNC();

    ba2str(&sba, src);
    ba2str(&msg->rmt_name.info.bd_addr, dst);
    copy_device_name(name, msg->rmt_name.info.bd_name);

//+++ BRCM_LOCAL : [CASE#506591]
// Sometimes new name is same as old name.
// But UI had been not updated.
    /* original
    if (read_device_name(src, dst, old_name) == 0) {
        if (strcmp(name, old_name) == 0) {
            return;
        }
    }
     */
//--- BRCM_LOCAL

    write_device_name(&sba, &msg->rmt_name.info.bd_addr, name);
    btd_event_remote_name(&sba, &msg->rmt_name.info.bd_addr, 0, name);
}

void dtun_dm_sig_device_found(tDTUN_DEVICE_SIGNAL *msg)
{
    char bdaddr_str[18];
    uint32_t cod = 0;

    ba2str(&msg->device_found.info.bd, bdaddr_str);

    /* If COD is 0, then set it to 0x001F00 Unclassified COD */
    cod = msg->device_found.info.cod;
    if (cod == 0) {
        cod = 0x1F << 8; // Unclassified device
    }

    info("\t*** Found device [%s] class = [%x] device_type = %x addr_type = %x ***\n\n",
         bdaddr_str, cod, msg->device_found.info.device_type,
         msg->device_found.info.addr_type);

    //write device type
    write_device_type(&sba, &msg->device_found.info.bd, msg->device_found.info.device_type);

    btd_event_device_found(&sba, &msg->device_found.info.bd, cod,
                           msg->device_found.info.rssi,
                           msg->device_found.info.device_type,
                           msg->device_found.info.addr_type,
           (msg->device_found.info.eir_present != 0 ? msg->device_found.info.eir : NULL));
}

void dtun_dm_sig_pin_req(tDTUN_DEVICE_SIGNAL *msg)
{
    PRINTFUNC();
    if(! msg->pin_req.info.cod)
    {
        // When trying to pair with a device whose information is not stored in stack...
        read_remote_class( &sba, &msg->authorize_req.info.bd_addr, &msg->pin_req.info.cod);
    }
    else
    {
        write_remote_class(&sba, &msg->pin_req.info.bdaddr, msg->pin_req.info.cod);
    }
    //write device type
    CHECK_AND_WRITE_DEVICE_TYPE(&(msg->pin_req.info.bdaddr), msg->pin_req.info.is_le_only);
    btd_event_request_pin(&sba, &msg->pin_req.info.bdaddr);
}



static void dtun_auth_cb(DBusError *derr, void *user_data)
{
    tDTUN_DEVICE_METHOD method;
    tDTUN_SIG_DM_AUTHORIZE_REQ_INFO *pending_info = (tDTUN_SIG_DM_AUTHORIZE_REQ_INFO *) user_data;

    PRINTFUNC();

    dtun_auth_on = FALSE;

    memcpy( &method.authorize_rsp.info.bd_addr, &pending_info->bd_addr, 6);
    method.authorize_rsp.info.service = pending_info->service;


    if (derr && dbus_error_is_set(derr)) {
        method.authorize_rsp.info.response = 2;
    }
    else {
        /* Handling of AuthorizeService for 2.0 devices. This shall
         * ensure that once the user checks the 'Always Accept' for 2.0
         * devices, this request shall not be prompted again
         */
        boolean trusted = FALSE;
        char peer_address[18];
        char service[32];

        ba2str(&pending_info->bd_addr, peer_address);
        info("dtun_auth_cb: read_trust: address %s", peer_address);

        if (get_service_from_uuid(dtunc_uuid_table[pending_info->service], service)) {
             trusted = read_trust(&sba, peer_address, service);
        }

        info("dtun_auth_cb: read_trust: service:%s trust_value:%d",service, trusted);

        if (trusted)
        {
//+++ BRCM_LOCAL : missing autho when trusted, so there is no popup.(CSP:468393).
            method.authorize_rsp.info.response = 1;
			      info("dtun_auth_cb: method.authorize_rsp.info.response = %d", method.authorize_rsp.info.response);
/* Broadcom original
            method.authorize_rsp.info.response = 0;
			      info("dtun_auth_cb: method.authorize_rsp.info.response = %d", method.authorize_rsp.info.response);
*/
//--- BRCM_LOCAL
        }
        else
            method.authorize_rsp.info.response = 1;
    }

    method.authorize_rsp.hdr.id = DTUN_METHOD_DM_AUTHORIZE_RSP;
    method.authorize_rsp.hdr.len = sizeof(tDTUN_METHOD_DM_AUTHORIZE_RSP_INFO);
    dtun_client_call_method(&method);

}


void dtun_dm_sig_authorize_req(tDTUN_DEVICE_SIGNAL *msg)
{
    int err;
    DBusError derr;
    uint32_t cur_cod;
    struct btd_adapter *tadapter;
    struct btd_device *device;
    char tmpName[DTUN_MAX_DEV_NAME_LEN+1];

        PRINTFUNC();

    read_remote_class( &sba, &msg->authorize_req.info.bd_addr, &cur_cod );

    info( "current cod = %x, received cod = %x", cur_cod, msg->authorize_req.info.cod );

#if defined (DTUN_CHECK_INVALID_COD) && (DTUN_CHECK_INVALID_COD == TRUE)
    if(msg->authorize_req.info.cod != 0)
    {
        write_remote_class(&sba, &msg->authorize_req.info.bd_addr, msg->authorize_req.info.cod);
    }
#else
    write_remote_class(&sba, &msg->authorize_req.info.bd_addr, msg->authorize_req.info.cod);
#endif

    if( msg->authorize_req.info.bd_name[0] )
    {
        memcpy(tmpName, msg->rmt_name.info.bd_name, DTUN_MAX_DEV_NAME_LEN);
        tmpName[DTUN_MAX_DEV_NAME_LEN] = '\0';
        //remove all invalid utf8 char if any
        copy_device_name(msg->rmt_name.info.bd_name, tmpName);

        write_device_name(&sba, &msg->authorize_req.info.bd_addr, msg->authorize_req.info.bd_name);
        if (get_adapter_and_device(&sba, &msg->authorize_req.info.bd_addr, &tadapter, &device, FALSE) && (device != NULL))
            device_set_name(device, msg->authorize_req.info.bd_name);
    }

    /* in the case were dtun_auth_cb gets called from here, this needs to be intialized */

    if( dtun_auth_on )
    {
          err = -1;
    }
    else
    {
        dtun_auth_on = TRUE;
        memcpy( &dtun_cur_authorize_req_info, &msg->authorize_req.info,
                sizeof( tDTUN_SIG_DM_AUTHORIZE_REQ_INFO)  );

//+++ BRCM_LOCAL
        /* original
        if ( (strcmp(dtunc_uuid_table[msg->authorize_req.info.service], SIM_ACC_UUID) == 0) &&
         */
        if ( (strncasecmp(dtunc_uuid_table[msg->authorize_req.info.service], SIM_ACC_UUID, sizeof(SIM_ACC_UUID)) == 0) &&
//--- BRCM_LOCAL
              device_is_weak_linkkey(device))
        {
            err = btd_request_authorization(&sba, &msg->authorize_req.info.bd_addr,
                                            "sap_weak_linkkey",  dtun_auth_cb,
                                            &dtun_cur_authorize_req_info);
        }
        else
        {
            err = btd_request_authorization(&sba, &msg->authorize_req.info.bd_addr,
                                            dtunc_uuid_table[msg->authorize_req.info.service], dtun_auth_cb,
                                            &dtun_cur_authorize_req_info);
        }
    }

    if (err < 0) {
        debug("Authorization denied(%d): %s", err,strerror(-err));
        dbus_error_init(&derr);

        dbus_set_error_const(&derr, "org.bluez.Error.Failed", strerror(-err));

        dtun_auth_cb(&derr, &msg->authorize_req.info);

        return;
    }



}


void dtun_dm_sig_link_down(tDTUN_DEVICE_SIGNAL *msg)
{
    PRINTFUNC();

    struct btd_adapter *tadapter;
    struct btd_device *device;

    //  uint16_t handle;

    if (!get_adapter_and_device(&sba, &msg->link_down.info.bd_addr, &tadapter, &device, FALSE))
        return;

    if (device == NULL) {
        error("dtun_dm_sig_link_down: No device object found!");
        return;
    }

    //  handle = device_get_conn_handle(device);

    info( "dtun_dm_sig_link_down device = %p reason = %d", device, msg->link_down.info.reason );

    btd_event_disconn_complete(&sba, &msg->link_down.info.bd_addr);

    // BLTH01242132: PA
        if( msg->link_down.info.reason == 5 ) //If reason code is authentication failure
            device_check_bonding_failed( device, msg->link_down.info.reason );

//+++ BRCM_LOCAL : When the auth is timed out on sending a file via OPP, It can't process next authorization request.
  if ( dtun_auth_on )
  {
  	info("dtun_dm_sig_link_down: It should initialize [dtun_autho_on] for next authorization request!");
  	dtun_auth_on = false;
  }
//--- BRCM_LOCAL :   
}

void dtun_dm_sig_link_up(tDTUN_DEVICE_SIGNAL *msg)
{

    PRINTFUNC();

    btd_event_conn_complete(&sba, &msg->link_up.info.bd_addr);
}

uint32_t dtun_add_sdp_record(DBusMessage *msg)
{
    tDTUN_DEVICE_METHOD method;
    uuid_t uuid;
    const char *name;
    uint16_t channel;
    uint32_t *uuid_p;
    uint32_t uuid_net[4];   // network order
    uint64_t uuid_host[2];  // host
    int i;

    if (!dbus_message_get_args(msg, NULL,
            DBUS_TYPE_STRING, &name,
            DBUS_TYPE_UINT64, &uuid_host[0],
            DBUS_TYPE_UINT64, &uuid_host[1],
            DBUS_TYPE_UINT16, &channel,
            DBUS_TYPE_INVALID))
        return 0xFFFFFFFF;

    for( i=0; i<MAX_EXPOSED_SDP_HANDLES; i++ )
    {
        if( sdp_handles[i] == FREE_EXPOSED_HANDLE ) //Found a free handle
        {
            sdp_handles[i] = ASSIGNED_EXPOSED_HANDLE;
         break;
        }
    }

    if( i==MAX_EXPOSED_SDP_HANDLES )
        return 0xFFFFFFFE;

    uuid_p = (uint32_t *)uuid_host;
    uuid_net[1] = htonl(*uuid_p++);
    uuid_net[0] = htonl(*uuid_p++);
    uuid_net[3] = htonl(*uuid_p++);
    uuid_net[2] = htonl(*uuid_p++);

    sdp_uuid128_create(&uuid, (void *)uuid_net);

    method.add_sdp_rec.hdr.id = DTUN_METHOD_DM_ADD_SDP_REC;
    method.add_sdp_rec.hdr.len = sizeof( tDTUN_METHOD_DM_ADD_SDP_REC_INFO);
    method.add_sdp_rec.info.exposed_handle = i;
    memcpy( &method.add_sdp_rec.info.uuid, &uuid.value.uuid128.data, 16 );
    method.add_sdp_rec.info.channel = channel;

    strncpy(&method.add_sdp_rec.info.name, name, DTUN_MAX_DEV_NAME_LEN);
    method.add_sdp_rec.info.name[DTUN_MAX_DEV_NAME_LEN] = 0;

    dtun_client_call_method(&method);
    return (i);
}

void dtun_dm_sig_sdp_handle(tDTUN_DEVICE_SIGNAL *msg)
{

    info( "dtun_dm_sig_sdp_rec_handle: handle = 0x%x", msg->sdp_handle.handle);

    sdp_handles[msg->sdp_handle.exposed_handle] = msg->sdp_handle.handle;
}

void dtun_del_sdp_record(uint32_t handle)
{
    tDTUN_DEVICE_METHOD method;

    if( handle >= 32 )
        return;

    if( (sdp_handles[handle] == FREE_EXPOSED_HANDLE) ||
         (sdp_handles[handle] == ASSIGNED_EXPOSED_HANDLE) )
        return;

    method.del_sdp_rec.hdr.id = DTUN_METHOD_DM_DEL_SDP_REC;
    method.del_sdp_rec.hdr.len = 4;
    method.del_sdp_rec.handle = sdp_handles[handle];
    dtun_client_call_method(&method);
    sdp_handles[handle] = FREE_EXPOSED_HANDLE;
    return;
}

void dtun_dm_sig_auth_comp(tDTUN_DEVICE_SIGNAL *msg)
{
    uint8_t st;
    evt_link_key_notify lk_ev;
    device_type_t device_type;        //ble/bredr/dumo

    device_type = read_device_type(&sba, &msg->auth_comp.info.bd_addr);

    info("dtun_dm_sig_auth_comp status: %d device_type = 0x%x", msg->auth_comp.info.success, device_type );
    info("dtun_dm_sig_auth_comp bd_addr = %02x:%02x:%02x:%02x:%02x:%02x:",
        msg->auth_comp.info.bd_addr.b[0],msg->auth_comp.info.bd_addr.b[1],msg->auth_comp.info.bd_addr.b[2],
        msg->auth_comp.info.bd_addr.b[3],msg->auth_comp.info.bd_addr.b[4],msg->auth_comp.info.bd_addr.b[5]);

    /*if it is a ble device and if link keys are exchanged then only set the state to Paired*/
    if (device_type == DEVICE_TYPE_LE) {
        struct btd_adapter *adapter;
        struct btd_device *device;

        // LE ONLY
        info("dtun_dm_sig_auth_comp le only status: %d ble_key_present=%d", msg->auth_comp.info.success,msg->auth_comp.info.ble_key_present);

        st = msg->auth_comp.info.success;
     	if(st==0 && !msg->auth_comp.info.ble_key_present)
     	{
     	    info("dtun_dm_sig_auth_comp. nothing is changed.");
     	}
     	else
     	{
            btd_event_bonding_complete(&sba,&msg->auth_comp.info.bd_addr, st);
        }

        if (msg->auth_comp.info.ble_key_present)
        {
            info("BLE pairing complete. Set device as bonded");
            if (get_adapter_and_device(&sba, &msg->auth_comp.info.bd_addr, &adapter, &device, FALSE) && (device != NULL))
                device_set_bonded(device, TRUE);

            if (device_is_temporary(device))
                device_set_temporary(device, FALSE);
        }

        if (msg->auth_comp.info.success > 0)
        {
            info("dtun_dm_sig_auth_comp fail_code=%d",msg->auth_comp.info.success );
            if (get_adapter_and_device(&sba, &msg->auth_comp.info.bd_addr, &adapter, &device, FALSE) && (device != NULL))
                device_remove_bonding(device);
            else
                info("dtun_dm_sig_auth_comp - can't get adapter/device");
        }
    }
    else {
        info("dtun_dm_sig_auth_comp bt. key_present: %d key_type: %d is_temp: %d",
            msg->auth_comp.info.key_present, msg->auth_comp.info.key_type, msg->auth_comp.info.is_temp);

        if ((msg->auth_comp.info.key_present) && (!msg->auth_comp.info.is_temp)) {
            memcpy( lk_ev.bdaddr.b, msg->auth_comp.info.bd_addr.b, 6 );
            memcpy( lk_ev.link_key, msg->auth_comp.info.key, 16 );
            lk_ev.key_type = msg->auth_comp.info.key_type;
            btd_event_link_key_notify(&sba, &msg->auth_comp.info.bd_addr, &msg->auth_comp.info.key, msg->auth_comp.info.key_type, msg->auth_comp.info.pin_len);
        }
        else
        {
            struct btd_adapter *adapter;
            struct btd_device *device;
            info("Temporary link key. Not storing");
            if (get_adapter_and_device(&sba, &msg->auth_comp.info.bd_addr, &adapter, &device, FALSE) && (device != NULL))
                device_set_temporary(device, TRUE);
        }

        st = msg->auth_comp.info.success;
        if (!st) {
            btd_event_conn_complete(&sba, &msg->auth_comp.info.bd_addr);
        }
        btd_event_bonding_complete(&sba, &msg->auth_comp.info.bd_addr, st);
    }
}

static void dtun_dm_io_cap_req (tDTUN_DEVICE_SIGNAL *msg)
{
    struct btd_adapter *adapter;
    struct btd_device *device;

    error("dtun_hcid: %s function not implemented...", __FUNCTION__);

    if (!get_adapter_and_device(&sba, &msg->io_cap_req.info.bd_addr,
         &adapter, &device, FALSE)) {
        error( "%s: get_adapter_and_device failed", __FUNCTION__);
        return;
    }

    info("dtun_dm_io_cap_req bd_addr = %02x:%02x:%02x:%02x:%02x:%02x:",
        msg->io_cap_req.info.bd_addr.b[0],msg->io_cap_req.info.bd_addr.b[1],msg->io_cap_req.info.bd_addr.b[2],
        msg->io_cap_req.info.bd_addr.b[3],msg->io_cap_req.info.bd_addr.b[4],msg->io_cap_req.info.bd_addr.b[5]);
    info("dtun_dm_io_cap_req: auth_req: 0x%x", msg->io_cap_req.info.loc_auth);

    // TBD: Wenbin: review this code later
    // device_set_loc_auth (device, msg->io_cap_req.info.loc_auth);
}

static void dtun_dm_io_cap_rsp (tDTUN_DEVICE_SIGNAL *msg)
{
    error("dtun_hcid: %s function not implemented...", __FUNCTION__);

    info("dtun_dm_io_cap_rsp bd_addr = %02x:%02x:%02x:%02x:%02x:%02x:",
        msg->io_cap_rsp.info.bd_addr.b[0],msg->io_cap_rsp.info.bd_addr.b[1],msg->io_cap_rsp.info.bd_addr.b[2],
        msg->io_cap_rsp.info.bd_addr.b[3],msg->io_cap_rsp.info.bd_addr.b[4],msg->io_cap_rsp.info.bd_addr.b[5]);
    info("dtun_dm_io_cap_rsp: io_cap: 0x%x auth_req: 0x%x", msg->io_cap_rsp.info.io_cap, msg->io_cap_rsp.info.auth_req);

    // TBD: Wenbin: review this code later
    // hcid_dbus_set_io_cap(&sba, &msg->io_cap_rsp.info.bd_addr, msg->io_cap_rsp.info.io_cap, msg->io_cap_rsp.info.auth_req);
}

static void dtun_dm_sig_ssp_cfm_req(tDTUN_DEVICE_SIGNAL *msg)
{
    unsigned long ssp_pin;
    unsigned long ssp_mode;

    PRINTFUNC();
    error("dtun_hcid: %s function not implemented...", __FUNCTION__);

// +++ BRCM_LOCAL
{
    struct btd_adapter *adapter;
    struct btd_device *device;

	if (!get_adapter_and_device(&sba, &msg->io_cap_req.info.bd_addr,&adapter, &device, FALSE))
	{
        error( "%s: get_adapter_and_device failed BRCM_LOCAL", __FUNCTION__);
    }
	else
	{
		if((msg->ssp_cfm_req.info.just_work == true)&&(msg->ssp_cfm_req.info.cod != 0))
		{
			btd_event_remote_class(&sba, &msg->ssp_cfm_req.info.bd_addr,msg->ssp_cfm_req.info.cod);
		}
	}
}
// --- BRCM_LOCAL
#if defined (DTUN_CHECK_INVALID_COD) && (DTUN_CHECK_INVALID_COD == TRUE)
    if (msg->ssp_cfm_req.info.cod != 0)
    {
        write_remote_class(&sba, &msg->ssp_cfm_req.info.bd_addr, msg->ssp_cfm_req.info.cod);
    }
#else
    write_remote_class(&sba, &msg->ssp_cfm_req.info.bd_addr, msg->ssp_cfm_req.info.cod);
#endif


    ssp_pin = msg->ssp_cfm_req.info.num_value;

     info( "Just Works = %d", msg->ssp_cfm_req.info.just_work );
     if(msg->ssp_cfm_req.info.just_work == true)
         ssp_pin = 0x80000000; //This is used as Bluetooth.Error in the JAVA space

     if (!msg->ssp_cfm_req.info.is_le_only)
     {
         struct btd_adapter *adapter;
         struct btd_device *device;

         if (!get_adapter_and_device(&sba, &msg->io_cap_req.info.bd_addr,
              &adapter, &device, FALSE)) {
             error( "%s: get_adapter_and_device failed", __FUNCTION__);
         }
         else
         {
            info ("%s: loc_auth_req: %d, rmt_auth_req: %d", __FUNCTION__, msg->ssp_cfm_req.info.loc_auth_req, msg->ssp_cfm_req.info.rmt_auth_req);

            // TBD: Wenbin, review later
            // device_set_loc_auth(device, msg->ssp_cfm_req.info.loc_auth_req);
            // device_set_auth(device, msg->ssp_cfm_req.info.rmt_auth_req);
         }
     }

    //write device type
    CHECK_AND_WRITE_DEVICE_TYPE(&(msg->ssp_cfm_req.info.bd_addr), msg->ssp_cfm_req.info.is_le_only);

    /* If just works, auto-accept. This needs to be enhanced by verify local & remote auth_req & io_cap */
    if (msg->ssp_cfm_req.info.just_work)
    {
        debug("auto accept of confirmation");

        /* Wait 5 milliseconds before doing auto-accept */
        usleep(5000);
        dtun_ssp_confirm_reply(&msg->ssp_cfm_req.info.bd_addr, TRUE, msg->ssp_cfm_req.info.is_le_only);
    }
    else
    {
        btd_event_user_confirm(&sba,
                            &msg->ssp_cfm_req.info.bd_addr,
                            ssp_pin); /* Java side is 2 for just work */
    }

    return;

fail:
    dtun_ssp_confirm_reply(&msg->ssp_cfm_req.info.bd_addr, FALSE, msg->ssp_cfm_req.info.is_le_only);

}

static void dtun_dm_sig_ssp_key_notif(tDTUN_DEVICE_SIGNAL *msg)
{
    unsigned long ssp_passkey;

    PRINTFUNC();

#if defined (DTUN_CHECK_INVALID_COD) && (DTUN_CHECK_INVALID_COD == TRUE)
    if (msg->ssp_key_notif.info.cod != 0)
    {
    write_remote_class(&sba, &msg->ssp_key_notif.info.bd_addr, msg->ssp_key_notif.info.cod);
    }
#else
    write_remote_class(&sba, &msg->ssp_key_notif.info.bd_addr, msg->ssp_key_notif.info.cod);
#endif

    ssp_passkey = msg->ssp_key_notif.info.pass_key;

     info( "Just Works = false");

    btd_event_user_notify(&sba, &msg->ssp_key_notif.info.bd_addr, ssp_passkey);     /* Java side is 2 for just work */
}

/* return testmode state to callee */
static void dtun_dm_sig_testmode_state( tDTUN_DEVICE_SIGNAL *msg )
{
    info( "dtun_dm_sig_testmode_state( state: %d )", msg->testmode_state.state );
} /* dtun_dm_sig_testmode_state() */

static void dtun_dm_sig_fetch_remote_di_info (tDTUN_DEVICE_SIGNAL *msg)
{
    struct btd_adapter *adapter;
    struct btd_device *device;

    memcpy( &dtun_pending_fetch_remote_di_addr.b,
        &msg->fetch_remote_di_info.remote_addr.b, 6);

    if (!get_adapter_and_device(&sba, &msg->fetch_remote_di_info.remote_addr,
         &adapter, &device, FALSE)) {
        error( "%s: get_adapter_and_device failed", __FUNCTION__);
        return;
    }

    if (device == NULL) {
        error( "%s: No device pointer found for peer!", __FUNCTION__);
        return;
    }

    device_fetch_remote_di_info(device, &msg->fetch_remote_di_info);
}

static void dtun_dm_sig_fetch_remote_di_rec (tDTUN_DEVICE_SIGNAL *msg)
{
    struct btd_adapter *adapter;
    struct btd_device *device;

    if (!get_adapter_and_device(&sba, &dtun_pending_fetch_remote_di_addr,
         &adapter, &device, FALSE)) {
        error( "%s: get_adapter_and_device failed", __FUNCTION__);
        return;
    }

    if (device == NULL) {
        error( "%s: No device pointer found for peer!", __FUNCTION__);
        return;
    }

    device_fetch_remote_di_rec(device, &msg->fetch_remote_di_rec);
}

static void dtun_dm_sig_ble_penc_key(tDTUN_DEVICE_SIGNAL * msg)
{
    int err = 0;
    PRINTFUNC();
    //write the key
    err = write_ble_link_key(&sba, &(msg->ble_enc_key.enc_key_info.bd_addr), (unsigned char *)(msg->ble_enc_key.enc_key_info.ltk), DTUN_LE_KEY_PENC,
                            sizeof(tDTUN_BLE_ENC_KEY_INFO) - sizeof(msg->ble_enc_key.enc_key_info.bd_addr));
    if ( err < 0 )
    {
        error("%s: Error writing ble link key %d", __FUNCTION__, err);
    }
}


static void dtun_dm_sig_ble_pid_key(tDTUN_DEVICE_SIGNAL * msg)
{
    int err = 0;

    PRINTFUNC();
    //write the key
    err = write_ble_link_key(&sba, &(msg->ble_devid_key.devid_key_info.bd_addr), (unsigned char *)(msg->ble_devid_key.devid_key_info.pid_key), DTUN_LE_KEY_PID,
                            sizeof(tDTUN_BLE_DEVID_KEY_INFO) - sizeof(msg->ble_devid_key.devid_key_info.bd_addr));
    if ( err < 0 )
    {
        error("%s: Error writing ble link key %d", __FUNCTION__, err);
    }

}

static void dtun_dm_sig_ble_pcsrk_key(tDTUN_DEVICE_SIGNAL * msg)
{
    int err = 0;

    PRINTFUNC();
    //write the key
    err = write_ble_link_key(&sba, &(msg->ble_pcsrk_key.pcsrk_key_info.bd_addr), (unsigned char *)&(msg->ble_pcsrk_key.pcsrk_key_info.counter), DTUN_LE_KEY_PCSRK,
                            sizeof(tDTUN_BLE_PCSRK_KEY_INFO) - sizeof(msg->ble_pcsrk_key.pcsrk_key_info.bd_addr));
    if ( err < 0 )
    {
        error("%s: Error writing ble link key %d", __FUNCTION__, err);
    }

}

static void dtun_dm_sig_ble_lenc_key(tDTUN_DEVICE_SIGNAL * msg)
{
    int err = 0;

    PRINTFUNC();
    //write the key
    err = write_ble_link_key(&sba, &(msg->ble_lenc_key.lenc_key_info.bd_addr), (unsigned char *)&(msg->ble_lenc_key.lenc_key_info.div), DTUN_LE_KEY_LENC,
                            sizeof(tDTUN_BLE_LENC_KEY_INFO) - sizeof(msg->ble_lenc_key.lenc_key_info.bd_addr));
    if ( err < 0 )
    {
        error("%s: Error writing ble link key %d", __FUNCTION__, err);
    }

}

static void dtun_dm_sig_ble_lcsrk_key(tDTUN_DEVICE_SIGNAL * msg)
{
    int err = 0;

    PRINTFUNC();
    //write the key
    err = write_ble_link_key(&sba, &(msg->ble_lcsrk_key.lcsrk_key_info.bd_addr), (unsigned char *)&(msg->ble_lcsrk_key.lcsrk_key_info.counter), DTUN_LE_KEY_LCSRK,
                            sizeof(tDTUN_BLE_LCSRK_KEY_INFO) - sizeof(msg->ble_lcsrk_key.lcsrk_key_info.bd_addr));
    if ( err < 0 )
    {
        error("%s: Error writing ble link key %d", __FUNCTION__, err);
    }

}

void dtun_sig_dm_local_oob_keys(tDTUN_DEVICE_SIGNAL *msg)
{
    error("dtun_hcid: %s not implemented...", __FUNCTION__);
}


/*******************************************************************************
** GetRemoteServiceChannel hander and callback
*******************************************************************************/
uuid_t dtun_get_scn_uuid;
struct btd_device *dtun_get_scn_device = NULL;
void dtun_client_get_remote_svc_channel(struct btd_device *device, bdaddr_t rmt, uuid_t *search)
{
    tDTUN_DEVICE_METHOD method;

    memcpy( &dtun_get_scn_uuid, search, sizeof( uuid_t ) );
    dtun_get_scn_device = device;

    /* Send message to btld */
    method.get_scn.hdr.id = DTUN_METHOD_DM_GET_REMOTE_SERVICE_CHANNEL;
    method.get_scn.hdr.len = (sizeof(tDTUN_GET_SCN) - sizeof(tDTUN_HDR));

    /* figure out what type of UUID we have and set correct type parameter */
    switch(search->type)
    {
    case SDP_UUID16:
        method.get_scn.uuid1.type = DTUN_SDP_UUID16;
        method.get_scn.uuid1.value.uuid16 = search->value.uuid16;

        ALOGI("%s: starting discovery on uuid16 = 0x%02x",
             __FUNCTION__,
             search->value.uuid16);
        break;
    case SDP_UUID32:
        method.get_scn.uuid1.type = DTUN_SDP_UUID32;
//+++ BRCM_LOCAL
        /* original
        method.get_scn.uuid1.value.uuid16 = search->value.uuid32;
         */
        method.get_scn.uuid1.value.uuid32 = search->value.uuid32;
//--- BRCM_LOCAL

        ALOGI("%s: starting discovery on uuid32 = 0x%04x",
             __FUNCTION__,
             search->value.uuid32);
        break;
    case SDP_UUID128:
    default:
        method.get_scn.uuid1.type = DTUN_SDP_UUID128;
        memcpy(&method.get_scn.uuid1.value.uuid128.data, search->value.uuid128.data, 16);
        ALOGI("%s: starting discovery on uuid128 = %x %x %x %x", __FUNCTION__,
             search->value.uuid128.data[0],
             search->value.uuid128.data[1],
             search->value.uuid128.data[2],
             search->value.uuid128.data[3]);
        break;
    }

    memcpy(&method.get_scn.bdaddr.b, &rmt.b, 6);

    ALOGI("   bdaddr=%02X:%02X:%02X:%02X:%02X:%02X",
         method.get_scn.bdaddr.b[0],
         method.get_scn.bdaddr.b[1],
         method.get_scn.bdaddr.b[2],
         method.get_scn.bdaddr.b[3],
         method.get_scn.bdaddr.b[4],
         method.get_scn.bdaddr.b[5]);

    dtun_client_call_method(&method);

    return;
}


void dtun_dm_sig_rmt_service_channel(tDTUN_DEVICE_SIGNAL *msg)
{
    PRINTFUNC();

    ALOGI("%s: success=%i, service=%08X", __FUNCTION__, msg->rmt_scn.success, (unsigned int)msg->rmt_scn.services);

    if ((msg->rmt_scn.success >= 3) && (msg->rmt_scn.services) && dtun_get_scn_device )
    {
        device_add_rfcomm_record(dtun_get_scn_device, dtun_get_scn_uuid, (msg->rmt_scn.success  - 3) );
        btd_device_append_uuid(dtun_get_scn_device, bt_uuid2string(&dtun_get_scn_uuid));
        btd_device_commit_uuids( dtun_get_scn_device );
        //
        // parse the raw data and send response back to discover services
        //
#if 0
        if ( msg->rmt_scn.raw_data_size > 0 ) {
            sdp_list_t *seq;
            sdp_list_t *recs = NULL;
            int scanned, seqlen = 0, bytesleft = msg->rmt_scn.raw_data_size;
            uint8_t dataType;
            uint8_t * rsp = msg->rmt_services.raw_data;


            scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
            if (!scanned || !seqlen) {
                discover_services_reply(-EHOSTDOWN,NULL);
            }
            else
            {
                rsp += scanned;
                bytesleft -= scanned;

                do {
                    sdp_record_t *rec;
                    int recsize;

                    recsize = 0;
                    //dump the buffer
                    rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
                    if (!rec) {
                        break;
                    }

                    if (!recsize) {
                        sdp_record_free(rec);
                        break;
                    }

                    scanned += recsize;
                    rsp += recsize;
                    bytesleft -= recsize;

                    recs = sdp_list_append(recs, rec);

                } while (scanned < (ssize_t) msg->rmt_services.raw_data_size && bytesleft > 0);
                discover_services_reply(0,recs);
            }

        }

#endif

    }
    else
    {
#if 0
        /* discovery unsuccessful */
            error( "discovery unsuccessful!" );
            discover_services_reply(-EHOSTDOWN,NULL);
#endif
    }

       dtun_get_scn_device = NULL;

//TODO: Store the service channel
}

/*******************************************************************************
** GetRemoteServices handler and callback
*******************************************************************************/


void dtun_client_get_remote_services(bdaddr_t rmt)
{
    tDTUN_DEVICE_METHOD method;

    ALOGI("%s...", __FUNCTION__);

    /* Send message to btld */
    method.rmt_dev.hdr.id = DTUN_METHOD_DM_GET_REMOTE_SERVICES;
    method.rmt_dev.hdr.len = (sizeof(tDTUN_METHOD_RMT_DEV) - sizeof(tDTUN_HDR));
    memcpy( &method.rmt_dev.bdaddr.b, &rmt.b, 6);

    /* get device type */
    method.rmt_dev.device_type = read_device_type(&sba, &(method.rmt_dev.bdaddr));

    dtun_pending_get_services_flg = TRUE;
    memcpy( &dtun_pending_get_services_adr.b, &rmt.b, 6);

    dtun_client_call_method(&method);

    return;
}

void dtun_client_get_all_remote_services(bdaddr_t rmt)
{
    tDTUN_DEVICE_METHOD method;

    PRINTFUNC();

    /* Send message to btld */
    method.rmt_dev.hdr.id = DTUN_METHOD_DM_GET_ALL_REMOTE_SERVICES;
    method.rmt_dev.hdr.len = (sizeof(tDTUN_METHOD_RMT_DEV) - sizeof(tDTUN_HDR));
    memcpy( &method.rmt_dev.bdaddr.b, &rmt.b, 6);
    ALOGI("%s: Get all remote services on ", __FUNCTION__);
    dtun_pending_get_services_flg = TRUE;
    memcpy( &dtun_pending_get_services_adr.b, &rmt.b, 6);

    dtun_client_call_method(&method);

    return;
}


void dtun_fetch_remote_di_info (bdaddr_t remote_addr)
{
    tDTUN_DEVICE_METHOD method;

    /* Send message to btld */
    method.fetch_remote_di_info.hdr.id = DTUN_METHOD_DM_FETCH_REMOTE_DI_INFO;
    method.fetch_remote_di_info.hdr.len =
        (sizeof(tDTUN_METHOD_DM_FETCH_REMOTE_DI_INFO) - sizeof(tDTUN_HDR));
    memcpy(&method.fetch_remote_di_info.remote_addr.b, &remote_addr.b, 6);
    dtun_client_call_method(&method);
}

static DBusMessage *sink_connect(DBusConnection *conn,
                                DBusMessage *msg, void *data)
{
        struct audio_device *dev = data;
        struct sink *sink = dev->sink;
        struct pending_request *pending;
        tDTUN_DEVICE_METHOD method;
        const char *address;
        DBusMessage *reply;

//+++ BRCM_LOCAL : CASE 515536
        if( sink == NULL )
        {
            error("sink_connect() dev->sink is NULL !!!");
            return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
                                               "%s", strerror(EBUSY));
        }
//--- BRCM_LOCAL        
 
        if (sink->connect || sink->disconnect)
                return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
                                                "%s", strerror(EBUSY));


        if (sink->state >= AVDTP_STATE_OPEN) {
                g_dbus_emit_signal(dev->conn, dev->path,
                                                AUDIO_SINK_INTERFACE,
                                                "Connected",
                                                DBUS_TYPE_INVALID);
                reply = dbus_message_new_method_return(msg);
                return reply;
        }

        pending = g_new0(struct pending_request, 1);
        pending->conn = dbus_connection_ref(conn);
        pending->msg = dbus_message_ref(msg);
        sink->connect = pending;

        memcpy(method.av_open.bdaddr.b, &dev->dst, 6);

       method.av_open.hdr.id = DTUN_METHOD_AM_AV_OPEN;
       method.av_open.hdr.len = 6;
        dtun_client_call_method(&method);

        debug("stream creation in progress");

        return NULL;
}

static DBusMessage *sink_disconnect(DBusConnection *conn,
                                        DBusMessage *msg, void *data)
{

        struct audio_device *device = data;
        struct sink *sink = device->sink;
        struct pending_request *pending;
        int err;
        tDTUN_DEVICE_METHOD method;

        if (sink->connect || sink->disconnect)
                return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
                                                "%s", strerror(EBUSY));

        if (sink->state < AVDTP_STATE_OPEN) {
                DBusMessage *reply = dbus_message_new_method_return(msg);
                if (!reply)
                        return NULL;
                return reply;
        }

        memcpy(method.av_disc.bdaddr.b, &device->dst, 6);

       method.av_open.hdr.id = DTUN_METHOD_AM_AV_DISC;
       method.av_open.hdr.len = 6;
        dtun_client_call_method(&method);

        pending = g_new0(struct pending_request, 1);
        pending->conn = dbus_connection_ref(conn);
        pending->msg = dbus_message_ref(msg);
        sink->disconnect = pending;

        return NULL;

}

static DBusMessage *sink_get_properties(DBusConnection *conn,
                                        DBusMessage *msg, void *data)
{
        struct audio_device *device = data;
        struct sink *sink = device->sink;
        DBusMessage *reply;
        DBusMessageIter iter;
        DBusMessageIter dict;
        const char *state;
        gboolean value;

        reply = dbus_message_new_method_return(msg);
        if (!reply)
                return NULL;

        dbus_message_iter_init_append(reply, &iter);

        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                        DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                        DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
                        DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

        /* Playing */
        value = (sink->state == AVDTP_STATE_STREAMING);
        dict_append_entry(&dict, "Playing", DBUS_TYPE_BOOLEAN, &value);

        /* Connected */
        value = (sink->state >= AVDTP_STATE_CONFIGURED);
        dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

        /* State */
        state = state2str(sink->state);
        if (state)
                dict_append_entry(&dict, "State", DBUS_TYPE_STRING, &state);

        dbus_message_iter_close_container(&iter, &dict);

        return reply;
}

static DBusMessage *sink_is_connected(DBusConnection *conn,
                                        DBusMessage *msg,
                                        void *data)
{
        struct audio_device *device = data;
        struct sink *sink = device->sink;
        DBusMessage *reply;
        dbus_bool_t connected;

        reply = dbus_message_new_method_return(msg);
        if (!reply)
                return NULL;

        connected = (sink->state >= AVDTP_STATE_CONFIGURED);

        dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
                                        DBUS_TYPE_INVALID);

        return reply;
}

static DBusMessage *sink_configure_cp_type(DBusConnection *conn,
                                           DBusMessage *msg,
                                           void *data)
{
    DBusMessageIter iter;
    DBusMessage *reply;
    uint32_t cp_type;
    tDTUN_DEVICE_METHOD method;

    if (!dbus_message_iter_init(msg, &iter))
       return NULL; //invalid_args(msg);
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
       return NULL; //invalid_args(msg);
    dbus_message_iter_get_basic(&iter, &cp_type);

    memset(&method.av_configure_cp_type, 0, sizeof(tDTUN_METHOD_AM_AV_CONFIGURE_CP_TYPE));

    method.av_configure_cp_type.hdr.id = DTUN_METHOD_AM_AV_CONFIGURE_CP_TYPE;
    method.av_configure_cp_type.hdr.len = sizeof(uint32_t);
    method.av_configure_cp_type.cp_type = cp_type;

    debug("sink_configure_cp_type: type:%d", cp_type);

    dtun_client_call_method(&method);

    return NULL;
}

static GDBusMethodTable sink_methods[] = {
        { "Connect",            "",     "",     sink_connect,
                                                G_DBUS_METHOD_FLAG_ASYNC },
        { "Disconnect",         "",     "",     sink_disconnect,
                                                G_DBUS_METHOD_FLAG_ASYNC },
        { "IsConnected",        "",     "b",    sink_is_connected,
                                                G_DBUS_METHOD_FLAG_DEPRECATED },
        { "GetProperties",      "",     "a{sv}",sink_get_properties },
        { "ConfigureCPType",    "u",    "",     sink_configure_cp_type,
                                                G_DBUS_METHOD_FLAG_ASYNC},
        { NULL, NULL, NULL, NULL }
};

static GDBusSignalTable sink_signals[] = {
        { "Connected",                  "",     G_DBUS_SIGNAL_FLAG_DEPRECATED },
        { "Disconnected",               "",     G_DBUS_SIGNAL_FLAG_DEPRECATED },
        { "Playing",                    "",     G_DBUS_SIGNAL_FLAG_DEPRECATED },
        { "Stopped",                    "",     G_DBUS_SIGNAL_FLAG_DEPRECATED },
        { "PropertyChanged",            "sv"    },
        { NULL, NULL }
};


static void pending_request_free(struct pending_request *pending)
{
        if (pending->conn)
                dbus_connection_unref(pending->conn);
        if (pending->msg)
                dbus_message_unref(pending->msg);
        g_free(pending);
}


static void sink_free(struct audio_device *dev)
{
        struct sink *sink = dev->sink;

        if (sink->connect)
                pending_request_free(sink->connect);

        if (sink->disconnect)
                pending_request_free(sink->disconnect);

#if 0
        if (sink->cb_id)
                avdtp_stream_remove_cb(sink->session, sink->stream,
                                        sink->cb_id);

        if (sink->dc_id)
                device_remove_disconnect_watch(dev->btd_dev, sink->dc_id);

        if (sink->session)
                avdtp_unref(sink->session);

        if (sink->retry_id)
                g_source_remove(sink->retry_id);

#endif
        g_free(sink);
        dev->sink = NULL;
}

void sink_unregister( struct audio_device *dev )
{
    g_dbus_unregister_interface(dev->conn, dev->path,
        AUDIO_SINK_INTERFACE);
}

static void path_unregister(void *data)
{
        struct audio_device *dev = data;

        debug("Unregistered interface %s on path %s",
                AUDIO_SINK_INTERFACE, dev->path);

        sink_free(dev);
}

struct sink *sink_init(struct audio_device *dev)
{
        struct sink *sink;

        ALOGI("sink_init");
        if (!g_dbus_register_interface(dev->conn, dev->path,
                                        AUDIO_SINK_INTERFACE,
                                        sink_methods, sink_signals, NULL,
                                        dev, path_unregister))
                return NULL;

        debug("Registered interface %s on path %s",
                AUDIO_SINK_INTERFACE, dev->path);

        sink = g_new0(struct sink, 1);

        sink->dev = dev;

        return sink;
}

void dtun_dm_sig_rmt_services(tDTUN_DEVICE_SIGNAL *msg)
{
    DBusMessage *reply;
    uint32_t service_mask;
    boolean success;
    uint32_t i, j;
    boolean found;
    struct btd_adapter *tadapter;
    struct btd_device *device;
    char * uuid_str = NULL;
    uuid_t  svc_uuid;
    tDTUN_GATT_ID  * pgatt_id;
    PRINTFUNC();


    if (dtun_pending_get_services_flg == FALSE)
    {
        ALOGI("%s: callback cancelled", __FUNCTION__);
        return;
    }

    service_mask = (uint32_t)msg->rmt_services.services;
    success = msg->rmt_services.success;


    //if data came across try and parse the raw data
    if (success && (get_adapter_and_device(&sba, &dtun_pending_get_services_adr, &tadapter, &device, FALSE)) && (device != NULL))
    {
        ALOGI("%s got adapter and device raw_data_size = 0x%x", __FUNCTION__, msg->rmt_services.raw_data_size);
        // Fixed SDP issue discovered while working on HDP
        // this can happen only in case of sdp results.  In case of BLE we are guaranteed
        // to get raw data because we don't do SDP.
        for (i = 0; i < DTUN_NUM_UUIDS_IN_TABLE ; i++)
        {
            if (service_mask & (1<<i))
            {
                ALOGI("Adding UUID %s", dtunc_uuid_table[i]);
                btd_device_append_uuid(device, dtunc_uuid_table[i]);
            }
        }

        if ( msg->rmt_services.raw_data_size != 0 )
        {
            if (device != NULL)
            {
                printf("%s raw_data_size = 0x%x\r\n", __FUNCTION__, msg->rmt_services.raw_data_size);

                if ( msg->rmt_services.device_type == DEVICE_TYPE_LE ) {

                    ALOGI("%s Got ble device type sizeof(gattid) = 0x%x\r\n", __FUNCTION__, sizeof(tDTUN_GATT_ID));

                    for ( i = 0; i < (msg->rmt_services.raw_data_size/sizeof(tDTUN_GATT_ID)); i ++ ) {

                        pgatt_id = (tDTUN_GATT_ID *)( msg->rmt_services.raw_data+ (sizeof(tDTUN_GATT_ID)*i));

                        printf("%s gatt uuid = 0x%x, uuid len = %d\r\n", __FUNCTION__, pgatt_id->uuid.uu.uuid16, pgatt_id->uuid.len);
                        switch ( pgatt_id->uuid.len )
                        {
                            case DTUN_LEN_UUID_16:
                                svc_uuid.type = SDP_UUID16;
                                svc_uuid.value.uuid16 = pgatt_id->uuid.uu.uuid16;
                                break;
                            case DTUN_LEN_UUID_32:
                                svc_uuid.type = SDP_UUID32;
                                svc_uuid.value.uuid32 = pgatt_id->uuid.uu.uuid32;
                                break;
                            case DTUN_LEN_UUID_128:
                                svc_uuid.type = SDP_UUID128;
                                memcpy(svc_uuid.value.uuid128.data, pgatt_id->uuid.uu.uuid128, DTUN_MAX_UUID_SIZE);
                                break;
                        }
                        uuid_str = bt_uuid2string(&svc_uuid);
                        printf("%s String uuid %s\r\n", __FUNCTION__, uuid_str);
                        btd_device_append_uuid(device, uuid_str);
                        g_free(uuid_str);
                        uuid_str = NULL;

                    }

                   // btd_device_commit_uuids( device );

                    //
                    //TODO: create xml to send discover services reply back.
                    //
                }
                else {
                    if ( msg->rmt_services.raw_data_size > 0 && success ) {
                        sdp_list_t *seq;
                        sdp_list_t *recs = NULL;
                        int scanned, seqlen = 0, bytesleft = msg->rmt_services.raw_data_size;
                        uint8_t dataType;
                        uint8_t * rsp = msg->rmt_services.raw_data;

                        scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
                        if (!scanned || !seqlen) {
                            discover_services_reply(-EHOSTDOWN,NULL);
                            ALOGI("%s sdp_extract_seqtype failed ", __FUNCTION__);
                            fflush(stdout);
                        }
                        else
                        {

                            rsp += scanned;
                            bytesleft -= scanned;

                            do {
                                sdp_record_t *rec;
                                int recsize;

                                recsize = 0;
                                //dump the buffer
                                rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
                                if (!rec) {

                                    break;
                                }

                                if (!recsize) {
                                    sdp_record_free(rec);
                                    break;
                                }

                                scanned += recsize;
                                rsp += recsize;
                                bytesleft -= recsize;

                                recs = sdp_list_append(recs, rec);
                                //convert uuid to string

                                //extract uuid from the record and add it to
                                uuid_str = bt_uuid2string(&(rec->svclass));
                                //
                                //check to see if it is in exclusion list and dont send event
                                //
                                j = 0;
                                found = false;
                                while (dtunc_uuid_exclusion_list[j] != NULL ) {
                                    if ( !dtun_stricmp(dtunc_uuid_exclusion_list[j], uuid_str)) {
                                        found = true;
                                    }
                                    j++;
                                }
                                if ( !found ) {
                                    ALOGI( "Adding UUID %s\r\n", uuid_str );

                                    btd_device_append_uuid(device, uuid_str);
                                }
                                g_free(uuid_str);
                                uuid_str = NULL;

                            } while (scanned < (ssize_t) msg->rmt_services.raw_data_size && bytesleft > 0);
                            discover_services_reply(0,recs);
                        }

                    }
                }
            }
        }
        btd_device_commit_uuids( device );
    }
    else if (msg->rmt_services.ignore_err == TRUE) {
        error( "No device pointer found for peer! Ignore Error = true. Ignoring error..." );
        return;
    }
    else {
        discover_services_reply(-EHOSTDOWN,NULL);
        error( "No Services found" );
        if (get_adapter_and_device(&sba, &dtun_pending_get_services_adr, &tadapter, &device, FALSE) && (device != NULL))
        {
            ALOGI("%s get_adapter_and_device OK ", __FUNCTION__);
            services_changed_with_empty_uuids(device);
        }
        else
        {
            error("%s, No device pointer found for peer!", __FUNCTION__);
        }
    }

    dtun_pending_get_services_flg = FALSE;
}


static void dtun_am_sig_av_event(tDTUN_DEVICE_SIGNAL *msg)
{
    char dev_path[64];
    const char *dpath = dev_path;
    DBusMessage *reply = NULL;
    struct audio_device *pdev;
    struct pending_request *pending = NULL;
    char err_msg[32];
    DBusMessage *orig_msg = NULL;
    boolean new_bonding = false;
    avdtp_state_t old_state;
    gboolean value;
    const char *state_str;

    debug("dtun_am_sig_av_event with event=%d\n", msg->av_event.info.event);

    if (msg->av_event.info.event == 2) { /* BTA_AV_OPEN_EVT */
        err_msg[0] = 0;
        switch (msg->av_event.info.status) {
        case 1:
            strcpy(err_msg, "Generic failure");
            break;
        case 2:
            strcpy(err_msg, "Service not found");
            break;
        case 3:
            strcpy(err_msg, "Stream connection failed");
            break;
        case 4:
            strcpy(err_msg, "No resources");
            break;
        case 5:
            strcpy(err_msg, "Role change failure");
            break;
        }

        pdev = manager_find_device(NULL, &sba, &msg->av_event.info.peer_addr, NULL, FALSE);
        if (!pdev) {
            info("new bonding\n");
            new_bonding = true;
        }
        else {
            info("pending\n");
            pending = pdev->sink->connect;
            if (pending) {
                orig_msg = pending->msg;
                info("orig_msg = %p\n", orig_msg);
                pdev->sink->connect = NULL;
            }
        }

        debug( "2.  before err msg chk (%s)\n", err_msg);
        //  printf( "msg->av_event.info.path = %s\n", msg->av_event.info.path );

        if (err_msg[0]) {

            if (pending) {
                if (orig_msg) {
                    DBusMessage *reply =  btd_error_failed(orig_msg, err_msg);
            //dbus_message_unref(orig_msg);
                    g_dbus_send_message(pending->conn, reply);
                }
                pending_request_free(pending);
            }
            return;
        }

        if (new_bonding) {
            struct btd_device *device;
            struct btd_adapter *tadapter;
            if (!get_adapter_and_device(&sba, &msg->av_event.info.peer_addr, &tadapter, &device, FALSE))
                return;

            if (device == NULL) {
                debug("Try new bonding, but it couldn't get device pointer");
                return;
            }

            btd_device_append_uuid(device, A2DP_SINK_UUID);
            btd_device_commit_uuids(device);
            pdev = manager_find_device(NULL, &sba, &msg->av_event.info.peer_addr, NULL, FALSE);
        }

        {
            old_state = pdev->sink->state;
            pdev->sink->state = AVDTP_STATE_OPEN;
            if (pending) {
                int busywait;
                debug( "Answering Pending Req\n" );
                //busy wait added to separate the 2 dbus transactions
#if 0 /* TBD, why is needed??? */
                for (busywait = 0; busywait < 10000; busywait++);
#endif
                reply = dbus_message_new_method_return(pending->msg);
                if (!reply)
                    return;
                dbus_connection_send(pending->conn, reply, NULL);
                dbus_message_unref(reply);
                pending_request_free(pending);
                pdev->sink->connect = NULL;
            }
            if (old_state <= AVDTP_STATE_OPEN) {
                value = TRUE;
                state_str = "connected";

                g_dbus_emit_signal(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                   "Connected", DBUS_TYPE_INVALID);
                emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                      "Connected", DBUS_TYPE_BOOLEAN, &value);
                emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                      "State", DBUS_TYPE_STRING, &state_str);
                debug("Stream successfully created");
            }
            else if (old_state == AVDTP_STATE_STREAMING) {
                value = FALSE;
                state_str = "connected";

                g_dbus_emit_signal(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                   "Stopped", DBUS_TYPE_INVALID);
                emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                      "Playing", DBUS_TYPE_BOOLEAN, &value);
                emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                      "State", DBUS_TYPE_STRING, &state_str);
                debug("Stream stopped");
            }
        }
    }  /* event==2 */
    else if (msg->av_event.info.event == 3) {
        value = FALSE;
        state_str = "disconnected";

        pdev = manager_find_device(NULL, &sba, &msg->av_event.info.peer_addr, NULL, FALSE);
        if (pdev) {
            if (pdev->sink == NULL) {
                debug("a2dp close: audio sink is removed ");
                return;
            }
            pdev->sink->state = AVDTP_STATE_IDLE;
            if (pending = pdev->sink->disconnect) { //Assignment on purpose
                reply = dbus_message_new_method_return(pending->msg);
                if (!reply)
                    return;
                dbus_connection_send(pending->conn, reply, NULL);
                dbus_message_unref(reply);
                pending_request_free(pending);
                pdev->sink->disconnect = NULL;
            }
            /* sanity - clear the connect event on disconnect */
            pdev->sink->connect = NULL;
            g_dbus_emit_signal(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                               "Disconnected", DBUS_TYPE_INVALID);
            emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                  "Connected", DBUS_TYPE_BOOLEAN, &value);
            emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                  "State", DBUS_TYPE_STRING, &state_str);

            debug("Stream successfully disconnected");
        }
        else
            debug("Stream was already removed ");
    } /* event==3 */
    else if (msg->av_event.info.event == 4) {
        pdev = manager_find_device(NULL, &sba, &msg->av_event.info.peer_addr, NULL, FALSE);
        if (pdev) {
            value = TRUE;
            state_str = "playing";
//+++ BRCM_LOCAL : [CASE#506625]
// If the same state("playing") is send, Media player pause to play.
            if (pdev->sink->state == AVDTP_STATE_STREAMING)
            {
                debug("[%s(%d)] Ignore same state!!!", __FUNCTION__, __LINE__);
                return;
            }
//--- BRCM_LOCAL
            pdev->sink->state = AVDTP_STATE_STREAMING;
            g_dbus_emit_signal(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                               "Playing", DBUS_TYPE_INVALID);
            emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                  "Playing", DBUS_TYPE_BOOLEAN, &value);
            emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                  "State", DBUS_TYPE_STRING, &state_str);
        }
    } /* even==4 */
    else if(msg->av_event.info.event == 15) {
        pdev = manager_find_device(NULL, &sba, &msg->av_event.info.peer_addr, NULL, FALSE);
        if (pdev) {
            value = FALSE;
            state_str = "connected";

            if (pdev->sink->state > AVDTP_STATE_OPEN) {
                g_dbus_emit_signal(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                   "Stopped", DBUS_TYPE_INVALID);
                emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                      "Playing", DBUS_TYPE_BOOLEAN, &value);
                emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                      "State", DBUS_TYPE_STRING, &state_str);
            }
            pdev->sink->state = AVDTP_STATE_OPEN;
            debug("Stream suspended");
        }
    } /* event==15 */
    else if(msg->av_event.info.event == DTUN_AV_EVENT_USE_CP) {
        ALOGE("%s: av_event.info.event == DTUN_AV_EVENT_USE_CP", __FUNCTION__);
        pdev = manager_find_device(NULL, &sba, &msg->av_event.info.peer_addr, NULL, FALSE);
        if (pdev) {
            value = msg->av_event.info.status;

            ALOGE("%s: emit_property, UseCP = %d", __FUNCTION__, value);

            emit_property_changed(pdev->conn, pdev->path, AUDIO_SINK_INTERFACE,
                                  "UseCP", DBUS_TYPE_BOOLEAN, &value);
        }
    }
} /* dtun_am_sig_av_event() */


static void dtun_ag_sig_second_conn_status(tDTUN_DEVICE_SIGNAL *msg)
{
    // hcid_dbus_notify_second_connection(&sba, &msg->ag_conn_up.peer_addr, msg->ag_conn_up.status);
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
}


static void dtun_ag_sig_slc_up(tDTUN_DEVICE_SIGNAL *msg)
{
    // hcid_dbus_notify_slc_up(&sba, &msg->ag_slc_up.peer_addr);
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
}

static void dtun_sig_cbc_level(tDTUN_DEVICE_SIGNAL *msg)
{
    // hcid_dbus_notify_cbc_level(&sba, &msg->cbc_level.peer_addr, msg->cbc_level.batterylevel);
    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
}

static void dtun_sig_wbs_config(tDTUN_DEVICE_SIGNAL *msg)
{
    debug("dtun_sig_wbs_config");
    btd_event_wbs_config(&sba, msg->wbs_config.wbs);
}

/**
 * Callback to DTUN method get_class
 * This method initializes the COD stored in the adapter object
 */
void dtun_dm_sig_get_class (tDTUN_DEVICE_SIGNAL *msg)
{
    // TBD: Wenbin...
    // uint32_t cod = msg->get_class.cod;
    // adapter_set_cod(adapter,cod,TRUE);

    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
}


/**
 * Callback to DTUN method set_class
 * This method completes the adapter set_class call
 */
void dtun_dm_sig_set_class (tDTUN_DEVICE_SIGNAL *msg)
{
    // TBD: Wenbin...
    // uint8_t status = msg->set_class.status;
    // adapter_set_class_complete(&sba,status);

    error("dtun_hcid: %s unimplemented!!!", __FUNCTION__);
}


/*******************************************************************************
 ** HID Host call-backs and event notifications
 *******************************************************************************/

static void dtun_sig_hh_connection(tDTUN_DEVICE_SIGNAL *p_data)
{
    struct btd_adapter *adapter;
    struct btd_device *device;
    char srcaddr[18], dstaddr[18];

    ba2str(&sba, srcaddr);
    ba2str(&p_data->hh_connection.bdaddr, dstaddr);

    info("%s: src = %s, dst = %s, status = 0x%04x",
         __FUNCTION__, srcaddr, dstaddr, p_data->hh_connection.status);

    if (!get_adapter_and_device(&sba, &p_data->hh_connection.bdaddr, &adapter, &device, FALSE)) {
        error("%s: get_adapter_and_device failed", __FUNCTION__);
        return;
    }
    if(device != NULL)
        device_input_conn_status(device, (uint32_t) p_data->hh_connection.status);
}


static void dtun_sig_hh_vup(tDTUN_DEVICE_SIGNAL *p_data)
{
    struct btd_adapter *adapter;
    struct btd_device *device;
    char srcaddr[18], dstaddr[18];

    ba2str(&sba, srcaddr);
    ba2str(&p_data->hh_connection.bdaddr, dstaddr);

    info("%s: src = %s, dst = %s, status = 0x%04x",
         __FUNCTION__, srcaddr, dstaddr, p_data->hh_connection.status);

    if (!get_adapter_and_device(&sba, &p_data->hh_connection.bdaddr, &adapter, &device, FALSE)) {
        error("%s: get_adapter_and_device failed", __FUNCTION__);
        return;
    }

    adapter_remove_device(sig_connection, adapter, device, TRUE);
}


static void dtun_sig_hh_hid_info(tDTUN_DEVICE_SIGNAL *p_data)
{
    int      i;
    char     srcaddr[18], dstaddr[18];
    char*    hidinfo;
    char*    p;
    char*    dsc_list;
    uint16_t dl_len = p_data->hh_hid_info.dl_len;
    size_t   size;

    ba2str(&sba, srcaddr);
    ba2str(&p_data->hh_hid_info.bdaddr, dstaddr);

    info("%s: src = %s, dst = %s, attr_mask = 0x%04x, sub_class = 0x%02x, app_id = %d, dl_len = %d",
         __FUNCTION__, srcaddr, dstaddr, p_data->hh_hid_info.attr_mask,
         p_data->hh_hid_info.sub_class, p_data->hh_hid_info.app_id,
         p_data->hh_hid_info.dl_len);

    info("%s: vendor_id = 0x%04x, product_id = 0x%04x, version = 0x%04x, ctry_code = 0x%02x",
         __FUNCTION__, p_data->hh_hid_info.vendor_id, p_data->hh_hid_info.product_id,
         p_data->hh_hid_info.version, p_data->hh_hid_info.ctry_code);

    if (dl_len == 0) {
        error("%s: Oops, dl_len = 0", __FUNCTION__);
        return;
    }

    /* Total HID info string length is:
     * 4 + 1 for attr_mask
     * 2 + 1 for sub_class
     * 2 + 1 for app_id
     * 4 + 1 for vendor_id
     * 4 + 1 for product_id
     * 4 + 1 for version
     * 2 + 1 for ctry_code
     * 4 + 1 for dl_len
     * dl_len * 2 for dsc_list
     * 1 for the end '\0'
     */
    size = 5 + 3 + 3 + 5 + 5 + 5 + 3 + 5 + 2 * dl_len + 1;
    hidinfo = (char *) malloc(size);
    if (hidinfo == NULL) {
        error("%s: Oops, failed to allocate %d byte buffer for HID info string",
              __FUNCTION__, size);
        return;
    }

    sprintf(hidinfo, "%04X %02X %02X %04X %04X %04X %02X %04X ",
            p_data->hh_hid_info.attr_mask,
            p_data->hh_hid_info.sub_class,
            p_data->hh_hid_info.app_id,
            p_data->hh_hid_info.vendor_id,
            p_data->hh_hid_info.product_id,
            p_data->hh_hid_info.version,
            p_data->hh_hid_info.ctry_code,
            p_data->hh_hid_info.dl_len);

    i = 0;
    p = &hidinfo[strlen(hidinfo)];
    dsc_list = p_data->hh_hid_info.dsc_list;
    while ((i + 16) <= dl_len) {
        sprintf(p, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                dsc_list[i],    dsc_list[i+1],  dsc_list[i+2],  dsc_list[i+3],
                dsc_list[i+4],  dsc_list[i+5],  dsc_list[i+6],  dsc_list[i+7],
                dsc_list[i+8],  dsc_list[i+9],  dsc_list[i+10], dsc_list[i+11],
                dsc_list[i+12], dsc_list[i+13], dsc_list[i+14], dsc_list[i+15]);
        p += 32;
        i += 16;
    }
    if ((i + 8) <= dl_len) {
        sprintf(p, "%02X%02X%02X%02X%02X%02X%02X%02X",
                dsc_list[i],   dsc_list[i+1], dsc_list[i+2], dsc_list[i+3],
                dsc_list[i+4], dsc_list[i+5], dsc_list[i+6], dsc_list[i+7]);
        p += 16;
        i += 8;
    }
    if ((i + 4) <= dl_len) {
        sprintf(p, "%02X%02X%02X%02X",
                dsc_list[i], dsc_list[i+1], dsc_list[i+2], dsc_list[i+3]);
        p += 8;
        i += 4;
    }
    if ((i + 3) == dl_len) {
        sprintf(p, "%02X%02X%02X", dsc_list[i], dsc_list[i+1], dsc_list[i+2]);
        p += 6;
    }
    else if ((i + 2) == dl_len) {
        sprintf(p, "%02X%02X", dsc_list[i], dsc_list[i+1]);
        p += 4;
    }
    else if ((i + 1) == dl_len) {
        sprintf(p, "%02X", dsc_list[i]);
        p += 2;
    }
    *p = '\0';

    write_hid_info(&sba, &p_data->hh_hid_info.bdaddr, hidinfo);

    free(hidinfo);
}


/* signal callback table */
const tDTUN_SIGNAL dtun_signal_tbl[] =
{
    /* DM signals */
    dtun_dm_sig_local_info,
    dtun_dm_sig_discovery_started,
    dtun_dm_sig_discovery_complete,
    dtun_dm_sig_device_found,
    dtun_dm_sig_set_class,
    dtun_dm_sig_get_class,
    dtun_dm_sig_rmt_name,
    dtun_dm_sig_rmt_service_channel,
    dtun_dm_sig_rmt_services,           /* DTUN_SIG_DM_RMT_SERVICES */
    dtun_dm_sig_pin_req,
    dtun_dm_sig_authorize_req,
    dtun_dm_sig_auth_comp,
    dtun_dm_io_cap_req,
    dtun_dm_io_cap_rsp,
    dtun_dm_sig_link_down,
    dtun_dm_sig_ssp_cfm_req,
    dtun_dm_sig_ssp_key_notif,
    dtun_dm_sig_link_up,
    dtun_dm_sig_sdp_handle,
    dtun_dm_sig_testmode_state,
    dtun_dm_sig_fetch_remote_di_info,
    dtun_dm_sig_fetch_remote_di_rec,
    dtun_dm_sig_ble_penc_key,
    dtun_dm_sig_ble_pid_key,
    dtun_dm_sig_ble_pcsrk_key,
    dtun_dm_sig_ble_lenc_key,
    dtun_dm_sig_ble_lcsrk_key,

    /* OOB support */
    dtun_sig_dm_local_oob_keys,

    /* AV signals */
    dtun_am_sig_av_event,
    /* Dual HF signal */
    dtun_ag_sig_second_conn_status,
    dtun_ag_sig_slc_up,
    /* OPC signals */

    dtun_sig_cbc_level,
    dtun_sig_opc_enable,             /* DTUN_SIG_OPC_ENABLE */
    dtun_sig_opc_open,               /* DTUN_SIG_OPC_OPEN */
    dtun_sig_opc_progress,           /* DTUN_SIG_OPC_PROGRESS */
    dtun_sig_opc_object_received,    /* DTUN_SIG_OPC_OBJECT_RECEIVED */
    dtun_sig_opc_object_pushed,      /* DTUN_SIG_OPC_OBJECT_PUSHED */
    dtun_sig_opc_close,              /* DTUN_SIG_OPC_CLOSE */

    /* OPS signals */
    dtun_sig_ops_progress,           /* DTUN_SIG_OPS_PROGRESS */
    dtun_sig_ops_object_received,    /* DTUN_SIG_OPS_OBJECT_RECEIVED */
    dtun_sig_ops_open,               /* DTUN_SIG_OPS_OPEN */
    dtun_sig_ops_access_request,     /* DTUN_SIG_OPS_ACCESS_REQUEST */
    dtun_sig_ops_close,              /* DTUN_SIG_OPS_CLOSE */
    dtun_sig_op_create_vcard,        /* DTUN_SIG_OP_CREATE_VCARD */
    dtun_sig_op_owner_vcard_not_set, /* DTUN_SIG_OP_OWNER_VCARD_NOT_SET */
    dtun_sig_op_store_vcard,         /* DTUN_SIG_OP_STORE_VCARD */

    /* SDP Signals */
    dtun_sig_sdp_add_record,         /* DTUN_SIG_ADD_SDP_RECORD */
    dtun_sig_sdp_remove_record,      /* DTUN_SIG_REMOVE_SDP_RECORD */

    /* HH Signals */
    dtun_sig_hh_connection,          /* DTUN_SIG_HH_CONNECTION */
    dtun_sig_hh_vup,                 /* DTUN_SIG_HH_VUP */
    dtun_sig_hh_hid_info,            /* DTUN_SIG_HH_HID_INFO */

    /* PAN Signals */
    dtun_sig_pan_state_changed,       /*DTUN_SIG_PAN_STATE_CHANGED*/

    /* HDP Signals */
    dtun_sig_hl_app_create,          /* DTUN_SIG_HDP_APP_CREATE*/
    dtun_sig_hl_app_destroy,         /* DTUN_SIG_HDP_APP_DESTROY*/
    dtun_sig_hl_channel_create,      /* DTUN_SIG_HDP_CHANNEL_CREATE*/
    dtun_sig_hl_channel_destroy,     /* DTUN_SIG_HDP_CHANNEL_DESTROY*/
    dtun_sig_hl_channel_acquire,     /* DTUN_SIG_HDP_CHANNEL_ACQUIRE*/
    dtun_sig_hl_channel_release,     /* DTUN_SIG_HDP_CHANNEL_RELEASE*/
    dtun_sig_hl_channel_connected,    /* DTUN_SIG_HDP_CHANNEL_CONNECTED */
    dtun_sig_wbs_config,             /* DTUN_SIG_WBS_CONFIG */
};

void dtun_process_started(void)
{
     /* get dbus connection in dtun thread context */
     //sig_connection = dbus_bus_get( DBUS_BUS_SYSTEM, NULL );
}

void dtun_pin_reply( tDTUN_ID id,  pin_code_reply_cp *pr, uint8_t is_le_only)
{
    tDTUN_DEVICE_METHOD method;

    method.pin_reply.hdr.id = id;

    if( id == DTUN_METHOD_DM_PIN_REPLY )
    {
        method.pin_reply.hdr.len = (sizeof( tDTUN_METHOD_DM_PIN_REPLY) - sizeof(tDTUN_HDR));

        method.pin_reply.pin_len = pr->pin_len;
        memcpy(method.pin_reply.bdaddr.b, pr->bdaddr.b, 6);
        memcpy(method.pin_reply.pin_code, pr->pin_code, pr->pin_len);
    }
    else
    {
        method.pin_reply.hdr.len = (sizeof( tDTUN_METHOD_DM_PIN_NEG_REPLY) - sizeof(tDTUN_HDR));

        method.pin_reply.pin_len = 0;
        memcpy(method.pin_reply.bdaddr.b, pr->bdaddr.b, 6);
    }
    method.pin_reply.is_le_only = is_le_only;

    dtun_client_call_method(&method);
}


void dtun_ssp_confirm_reply(bdaddr_t *dba, boolean accepted, boolean is_le_only)
{
    tDTUN_DEVICE_METHOD method;

    info("#### dtun_ssp_confirm_reply() accepted = %d ####\n", (int)accepted);

    method.ssp_confirm.hdr.id = DTUN_METHOD_DM_SSP_CONFIRM;
    method.ssp_confirm.hdr.len = sizeof(tDTUN_METHOD_SSP_CONFIRM) - sizeof(tDTUN_HDR);
    memcpy(method.ssp_confirm.bd_addr.b, dba, 6);
    method.ssp_confirm.accepted = accepted;
    method.ssp_confirm.is_le_only = is_le_only;
    dtun_client_call_method(&method);
}


void hcid_termination_handler(int sig, siginfo_t *siginfo, void *context)
{
    info("%s: ## bluetoothd terminate (%d) ##\n", __FUNCTION__, sig);

    /* stopped from init process */
    if ((sig == SIGUSR1) || (sig == SIGINT)) {
        /* make sure we started yet */
        if (event_loop) {
            g_main_loop_quit(event_loop);
        }
        else {
            /* stop any connection attempts */
            dtun_client_stop(DTUN_INTERFACE);
            exit(0);
        }
    }
}


int hcid_register_termination_handler(void)
{
    struct sigaction act;

    error("%s: ...", __FUNCTION__);

    memset (&act, '\0', sizeof(act));

    /* Use the sa_sigaction field because the handles has two additional parameters */
    act.sa_sigaction = &hcid_termination_handler;

    /* The SA_SIGINFO flag tells sigaction() to use the sa_sigaction field, not sa_handler. */
    act.sa_flags = SA_SIGINFO;

    if (sigaction(SIGUSR1, &act, NULL) < 0) {
        error ("sigaction : %s (%d)", strerror(errno), errno);
        return 1;
    }

    if (sigaction(SIGINT, &act, NULL) < 0) {
        error ("sigaction : %s (%d)", strerror(errno), errno);
        return 1;
    }

    return 0;
}


int property_is_active(char *property)
{
#define PROPERTY_VALUE_MAX  92

    char value[PROPERTY_VALUE_MAX];

    /* default if not set it 0 */
    property_get(property, value, "0");

    ALOGI("property_is_active : %s=%s\n", property, value);

    if (strcmp(value, "1") == 0) {
        return 1;
    }
    return 0;
}


// Property name for the bluetoothd process PID
#define BRCM_PROPERTY_BLUETOOTHD_PID "service.brcm.bt.bluetoothd_pid"

static void set_property_bluetoothd_pid(void)
{
    int   ret;
    char  value[PROPERTY_VALUE_MAX];
    pid_t pid;

    pid = getpid();
    sprintf(value, "%d", pid);

    ret = property_set(BRCM_PROPERTY_BLUETOOTHD_PID, value);

    if (ret == 0) {
        ALOGV("%s: %s = %s", __FUNCTION__, BRCM_PROPERTY_BLUETOOTHD_PID, value);
    }
    else {
        ALOGE("%s: OOPS, failed to set: %s = %s, ret = %d", __FUNCTION__, BRCM_PROPERTY_BLUETOOTHD_PID, value, ret);
    }
}


void dtun_client_main(void)
{
    int retval;

    info("HCID DTUN client starting\n");

    hcid_register_termination_handler();

    /* start dbus tunnel on DTUN subsystem */
    dtun_start_interface(DTUN_INTERFACE, &dtun_signal_tbl, dtun_process_started);

    sig_connection = dbus_bus_get( DBUS_BUS_SYSTEM, NULL );

    agent_init();
    retval = connect_dbus();

    dtun_client_call_id_only(DTUN_METHOD_DM_GET_LOCAL_INFO);

    set_property_bluetoothd_pid();

    register_server_service();

    /* Loading plugins has to be done after D-Bus has been setup since
     * the plugins might wanna expose some paths on the bus. However the
     * best order of how to init various subsystems of the Bluetooth
     * daemon needs to be re-worked. */
    plugin_init(NULL, NULL, NULL);

    event_loop = g_main_loop_new(NULL, false);

    error("hcid main loop starting\n");
    info("hcid main loop starting\n");

    retval = property_set(DTUN_PROPERTY_HCID_ACTIVE, "1");
    if (retval)
       info("property set failed(%d)\n", retval);

    g_main_loop_run(event_loop);
    debug("dtun_client_main() calling dbus_connection_flush");

    dbus_connection_flush(sig_connection);
    debug("dtun_client_main() dbus_connection_flush ret");
    info("main loop exiting...\n");

    btd_adapter_stop(adapter);

    obex_dbus_exit ();
    sdp_dbus_exit();
    pan_dbus_exit();

    plugin_cleanup();

    /* stop dbus tunnel */
    dtun_client_stop(DTUN_INTERFACE);

    // hcid_dbus_unregister();

    disconnect_dbus();

    g_main_loop_unref(event_loop);

    info("main loop exited......\n");

    retval = property_set(DTUN_PROPERTY_HCID_ACTIVE, "0");
    if (retval)
        info("property set failed(%d)\n", retval);

    usleep(200000);
    while (property_is_active(DTUN_PROPERTY_HCID_ACTIVE)) {
        info("hcid property write failed...retrying\n");
        usleep(200000);
        retval = property_set(DTUN_PROPERTY_HCID_ACTIVE, "0");
        if (retval)
            info("property set failed(%d)\n", retval);
    }

    while (1) {
        usleep(200000);
    }
}
