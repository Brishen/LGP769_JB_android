/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2009-2012  Broadcom Corporation
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define DEVICE_INTERFACE	"org.bluez.Device"

//+++ BRCM_LOCAL
#define BT_USE_PAIREDPLUS
//--- BRCM_LOCAL

//+++ BRCM
#ifdef BT_ALT_STACK
// These are duplicated in two more places
// TODO: Consolidate
#define PANU_UUID           "00001115-0000-1000-8000-00805f9b34fb"
#define NAP_UUID            "00001116-0000-1000-8000-00805f9b34fb"
#define GN_UUID             "00001117-0000-1000-8000-00805f9b34fb"

#define SERIAL_PORT_UUID    "00001101-0000-1000-8000-00805F9B34FB"
#define DIALUP_NET_UUID     "00001103-0000-1000-8000-00805F9B34FB"

#define SYNC_UUID "00001104-0000-1000-8000-00805F9B34FB"
#define OPP_UUID  "00001105-0000-1000-8000-00805F9B34FB"

#define FILE_TRANSFER_UUID  "00001106-0000-1000-8000-00805F9B34FB"

#define CTP_UUID  "00001109-0000-1000-8000-00805F9B34FB"
#define ICP_UUID  "00001110-0000-1000-8000-00805F9B34FB"

#define BPP_UUID  "00001122-0000-1000-8000-00805F9B34FB"

#define FAX_UUID  "00001111-0000-1000-8000-00805F9B34FB"
#define LAP_UUID  "00001102-0000-1000-8000-00805F9B34FB"

#define BIP_UUID  "0000111A-0000-1000-8000-00805F9B34FB"
#define PBAP_UUID "00001130-0000-1000-8000-00805F9B34FB"

#define VIDEO_DIST_UUID "00001305-0000-1000-8000-00805F9B34FB"
#define SIM_ACC_UUID    "0000112D-0000-1000-8000-00805F9B34FB"

//MAP related uuids
#define MAP_UUID "00001134-0000-1000-8000-00805F9B34FB"
#define MSE_UUID "00001132-0000-1000-8000-00805F9B34FB"
#define MNS_UUID "00001133-0000-1000-8000-00805F9B34FB"
#define HID_UUID "00001124-0000-1000-8000-00805f9b34fb"
#endif //BT_ALT_STACK
//--- BRCM
struct btd_device;

typedef enum {
	AUTH_TYPE_PINCODE,
	AUTH_TYPE_PASSKEY,
	AUTH_TYPE_CONFIRM,
	AUTH_TYPE_NOTIFY,
	AUTH_TYPE_AUTO,
	AUTH_TYPE_PAIRING_CONSENT,
} auth_type_t;

typedef enum {
	DEVICE_TYPE_UNKNOWN,
	DEVICE_TYPE_BREDR,
	DEVICE_TYPE_LE,
	DEVICE_TYPE_DUALMODE
} device_type_t;

struct btd_device *device_create(DBusConnection *conn,
				struct btd_adapter *adapter,
				const gchar *address, device_type_t type);
void device_set_name(struct btd_device *device, const char *name);
void device_get_name(struct btd_device *device, char *name, size_t len);
device_type_t device_get_type(struct btd_device *device);
void device_remove(struct btd_device *device, gboolean remove_stored);
gint device_address_cmp(struct btd_device *device, const gchar *address);
int device_browse_primary(struct btd_device *device, DBusConnection *conn,
				DBusMessage *msg, gboolean secure);
int device_browse_sdp(struct btd_device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search, gboolean reverse);
void device_probe_drivers(struct btd_device *device, GSList *profiles);
const sdp_record_t *btd_device_get_record(struct btd_device *device,
						const char *uuid);
GSList *btd_device_get_primaries(struct btd_device *device);
void device_register_services(DBusConnection *conn, struct btd_device *device,
						GSList *prim_list, int psm);
GSList *device_services_from_record(struct btd_device *device,
							GSList *profiles);
void btd_device_add_uuid(struct btd_device *device, const char *uuid);
struct btd_adapter *device_get_adapter(struct btd_device *device);
void device_get_address(struct btd_device *device, bdaddr_t *bdaddr);
const gchar *device_get_path(struct btd_device *device);
struct agent *device_get_agent(struct btd_device *device);
gboolean device_is_busy(struct btd_device *device);
gboolean device_is_temporary(struct btd_device *device);
gboolean device_is_paired(struct btd_device *device);
gboolean device_is_trusted(struct btd_device *device);
void device_set_paired(struct btd_device *device, gboolean paired);
void device_set_temporary(struct btd_device *device, gboolean temporary);
void device_set_type(struct btd_device *device, device_type_t type);
void device_set_bonded(struct btd_device *device, gboolean bonded);
gboolean device_is_connected(struct btd_device *device);
DBusMessage *device_create_bonding(struct btd_device *device,
				DBusConnection *conn, DBusMessage *msg,
				const char *agent_path, uint8_t capability);
void device_remove_bonding(struct btd_device *device);
void device_bonding_complete(struct btd_device *device, uint8_t status);
void device_simple_pairing_complete(struct btd_device *device, uint8_t status);
gboolean device_is_creating(struct btd_device *device, const char *sender);
gboolean device_is_bonding(struct btd_device *device, const char *sender);
void device_cancel_bonding(struct btd_device *device, uint8_t status);
int device_request_authentication(struct btd_device *device, auth_type_t type,
				uint32_t passkey, void *cb);
void device_cancel_authentication(struct btd_device *device, gboolean aborted);
gboolean device_is_authenticating(struct btd_device *device);
gboolean device_is_authorizing(struct btd_device *device);
void device_set_authorizing(struct btd_device *device, gboolean auth);
void device_add_connection(struct btd_device *device, DBusConnection *conn);
void device_remove_connection(struct btd_device *device, DBusConnection *conn);
void device_request_disconnect(struct btd_device *device, DBusMessage *msg);

typedef void (*disconnect_watch) (struct btd_device *device, gboolean removal,
					void *user_data);

guint device_add_disconnect_watch(struct btd_device *device,
				disconnect_watch watch, void *user_data,
				GDestroyNotify destroy);
void device_remove_disconnect_watch(struct btd_device *device, guint id);
void device_set_class(struct btd_device *device, uint32_t value);

#define BTD_UUIDS(args...) ((const char *[]) { args, NULL } )

struct btd_device_driver {
	const char *name;
	const char **uuids;
	int (*probe) (struct btd_device *device, GSList *uuids);
	void (*remove) (struct btd_device *device);
};

int btd_register_device_driver(struct btd_device_driver *driver);
void btd_unregister_device_driver(struct btd_device_driver *driver);

struct btd_device *btd_device_ref(struct btd_device *device);
void btd_device_unref(struct btd_device *device);
//+++ BRCM
#ifdef BT_ALT_STACK
gboolean device_is_weak_linkkey(struct btd_device *device);
uint8_t device_authr_is_le_only(struct btd_device *device);
void device_input_conn_status(struct btd_device *device, uint32_t status);
void device_check_bonding_failed( struct btd_device *device, uint8_t status);
#endif //BT_ALT_STACK
//--- BRCM
