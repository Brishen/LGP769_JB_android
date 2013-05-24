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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "textfile.h"

#include "att.h"
#include "hcid.h"
#include "adapter.h"
#include "device.h"
#include "dbus-common.h"
#include "event.h"
#include "error.h"
#include "glib-helper.h"
#include "gattrib.h"
#include "gatt.h"
#include "agent.h"
#include "sdp-xml.h"
#include "storage.h"
#include "btio.h"
#include "../attrib/client.h"
//+++ BRCM
#ifdef BT_ALT_STACK
#include "dtun_clnt.h"

#define BT_CLASS_MASK       0x1FFC

extern void dtun_device_check_remove_audio(struct btd_device *device);
extern void dtun_init_device_uuid( struct btd_device *device, char *str_uuid);
extern void dtun_client_get_remote_svc_channel(struct btd_device *device, bdaddr_t rmt, uuid_t *search);
extern void dtun_client_get_remote_services(bdaddr_t rmt);
extern void dtun_client_get_all_remote_services(bdaddr_t rmt);
extern void dtun_read_dev_info(const bdaddr_t *src_ba, const bdaddr_t *dest_ba, uint8_t *p_device_type, uint32_t *p_addr_type);
extern void dtun_add_ble_dev_info( const bdaddr_t *dest_ba , uint8_t device_type, uint32_t addr_type);
//+++ BRCM_LOCAL : CSP#538367 due to holding device information,re-fetching SDP records could get failed
extern void panu_remove(struct btd_device *device);
//--- BRCM_LOCAL 
#endif

#define LOG_TAG "DEVICE"
#include "utils/Log.h"
#define info(format, ...)  ALOGI (format, ## __VA_ARGS__)
#define debug(format, ...) ALOGD (format, ## __VA_ARGS__)
#define DBG(format, ...)   ALOGD (format, ## __VA_ARGS__)
#define error(format, ...) ALOGE (format, ## __VA_ARGS__)
//--- BRCM

#define DISCONNECT_TIMER	2
#define DISCOVERY_TIMER		2

/* When all services should trust a remote device */
#define GLOBAL_TRUST "[all]"

struct btd_disconnect_data {
	guint id;
	disconnect_watch watch;
	void *user_data;
	GDestroyNotify destroy;
};

struct bonding_req {
	DBusConnection *conn;
	DBusMessage *msg;
	GIOChannel *io;
	guint listener_id;
	struct btd_device *device;
};

struct authentication_req {
	auth_type_t type;
	void *cb;
	struct agent *agent;
	struct btd_device *device;
//+++ BRCM
#ifdef BT_ALT_STACK
	uint8_t is_le_only;		/* indicates if the device is le only */
#endif
//--- BRCM
};

struct browse_req {
	DBusConnection *conn;
	DBusMessage *msg;
	GAttrib *attrib;
	struct btd_device *device;
	GSList *match_uuids;
	GSList *profiles_added;
	GSList *profiles_removed;
	sdp_list_t *records;
	int search_uuid;
	int reconnect_attempt;
	guint listener_id;
};

struct btd_device {
	bdaddr_t	bdaddr;
	device_type_t	type;
	gchar		*path;
	char		name[MAX_NAME_LENGTH + 1];
	char		*alias;
	struct btd_adapter	*adapter;
	GSList		*uuids;
	GSList		*services;		/* Primary services path */
	GSList		*primaries;		/* List of primary services */
	GSList		*drivers;		/* List of device drivers */
	GSList		*watches;		/* List of disconnect_data */
	gboolean	temporary;
	struct agent	*agent;
	guint		disconn_timer;
	guint		discov_timer;
	struct browse_req *browse;		/* service discover request */
	struct bonding_req *bonding;
	struct authentication_req *authr;	/* authentication request */
	GSList		*disconnects;		/* disconnects message */

	gboolean	connected;

	sdp_list_t	*tmp_records;

	gboolean	trusted;
	gboolean	paired;
	gboolean	blocked;
	gboolean	bonded;

	gboolean	authorizing;
	gint		ref;
};

static uint16_t uuid_list[] = {
	L2CAP_UUID,
	PNP_INFO_SVCLASS_ID,
	PUBLIC_BROWSE_GROUP,
	0
};

static GSList *device_drivers = NULL;

//+++ BRCM
#ifdef BT_ALT_STACK
static DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg, int err)
{
	const char *desc = strerror(err);
	DBusMessage *derr;
	if (!conn || !msg)
		return DBUS_HANDLER_RESULT_HANDLED;
	derr = btd_error_failed(msg,desc);
	if (!derr)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	g_dbus_send_message(conn, derr);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static uint16_t read_device_cod(bdaddr_t *local, bdaddr_t *remote)
{
	uint32_t cod;
	if (read_remote_class(local, remote, &cod) != 0) {
		cod = 0;
	}
	return (uint16_t) (cod & BT_CLASS_MASK);
}
#endif
//--- BRCM

static void browse_request_free(struct browse_req *req)
{
	if (req->listener_id)
		g_dbus_remove_watch(req->conn, req->listener_id);
	if (req->msg)
		dbus_message_unref(req->msg);
	if (req->conn)
		dbus_connection_unref(req->conn);
	if (req->device)
		btd_device_unref(req->device);
	g_slist_foreach(req->profiles_added, (GFunc) g_free, NULL);
	g_slist_free(req->profiles_added);
	g_slist_free(req->profiles_removed);
	if (req->records)
		sdp_list_free(req->records, (sdp_free_func_t) sdp_record_free);

	if (req->attrib)
		g_attrib_unref(req->attrib);

	g_free(req);
}

static void browse_request_cancel(struct browse_req *req)
{
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src;

	if (device_is_creating(device, NULL))
		device_set_temporary(device, TRUE);

	adapter_get_address(adapter, &src);

	bt_cancel_discovery(&src, &device->bdaddr);

	device->browse = NULL;
	browse_request_free(req);
}

static void device_free(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	struct agent *agent = adapter_get_agent(adapter);

	if (device->agent)
		agent_free(device->agent);

	if (agent && (agent_is_busy(agent, device) ||
				agent_is_busy(agent, device->authr)))
		agent_cancel(agent);

	g_slist_foreach(device->services, (GFunc) g_free, NULL);
	g_slist_free(device->services);

	g_slist_foreach(device->uuids, (GFunc) g_free, NULL);
	g_slist_free(device->uuids);

	g_slist_foreach(device->primaries, (GFunc) g_free, NULL);
	g_slist_free(device->primaries);

	if (device->tmp_records)
		sdp_list_free(device->tmp_records,
					(sdp_free_func_t) sdp_record_free);

	if (device->disconn_timer)
		g_source_remove(device->disconn_timer);

	if (device->discov_timer)
		g_source_remove(device->discov_timer);

	DBG("%p", device);

	g_free(device->authr);
	g_free(device->path);
	g_free(device->alias);
	g_free(device);
}

gboolean device_is_paired(struct btd_device *device)
{
	return device->paired;
}

gboolean device_is_trusted(struct btd_device *device)
{
	return device->trusted;
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device->adapter;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t src;
	char name[MAX_NAME_LENGTH + 1], srcaddr[18], dstaddr[18];
	char **str;
	const char *ptr;
	dbus_bool_t boolean;
	uint32_t class;
//+++ BRCM
#ifdef BT_ALT_STACK
	dbus_uint32_t dev_type;
#endif
//--- BRCM
	int i;
	GSList *l;

	ba2str(&device->bdaddr, dstaddr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Address */
	ptr = dstaddr;
	dict_append_entry(&dict, "Address", DBUS_TYPE_STRING, &ptr);

	/* Name */
	ptr = NULL;
	memset(name, 0, sizeof(name));
	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);

	ptr = device->name;
	dict_append_entry(&dict, "Name", DBUS_TYPE_STRING, &ptr);

#ifdef ANDROID
	/* Alias (Android doesn't fallback to name or address) */
	if (device->alias != NULL) {
		ptr = device->alias;
		dict_append_entry(&dict, "Alias", DBUS_TYPE_STRING, &ptr);
	}
#else
	/* Alias (fallback to name or address) */
	if (device->alias != NULL)
		ptr = device->alias;
	else if (strlen(ptr) == 0) {
		g_strdelimit(dstaddr, ":", '-');
		ptr = dstaddr;
	}

	dict_append_entry(&dict, "Alias", DBUS_TYPE_STRING, &ptr);
#endif

	/* Class */
	if (read_remote_class(&src, &device->bdaddr, &class) == 0) {
		const char *icon = class_to_icon(class);

		dict_append_entry(&dict, "Class", DBUS_TYPE_UINT32, &class);

		if (icon)
			dict_append_entry(&dict, "Icon",
						DBUS_TYPE_STRING, &icon);
	}

	/* Paired */
	boolean = device_is_paired(device);
	dict_append_entry(&dict, "Paired", DBUS_TYPE_BOOLEAN, &boolean);

	/* Trusted */
	boolean = device_is_trusted(device);
	dict_append_entry(&dict, "Trusted", DBUS_TYPE_BOOLEAN, &boolean);

	/* Blocked */
	boolean = device->blocked;
	dict_append_entry(&dict, "Blocked", DBUS_TYPE_BOOLEAN, &boolean);

	/* Connected */
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN,
							&device->connected);

	/* UUIDs */
	str = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		str[i] = l->data;
	dict_append_array(&dict, "UUIDs", DBUS_TYPE_STRING, &str, i);
	g_free(str);

	/* Services */
	str = g_new0(char *, g_slist_length(device->services) + 1);
	for (i = 0, l = device->services; l; l = l->next, i++)
		str[i] = l->data;
	dict_append_array(&dict, "Services", DBUS_TYPE_OBJECT_PATH, &str, i);
	g_free(str);

	/* Adapter */
	ptr = adapter_get_path(adapter);
	dict_append_entry(&dict, "Adapter", DBUS_TYPE_OBJECT_PATH, &ptr);

//+++ BRCM
#ifdef BT_ALT_STACK
	/* Device type */
	dev_type = read_device_type(&src, &device->bdaddr);
	dict_append_entry(&dict, "DeviceType", DBUS_TYPE_UINT32, &dev_type);
#endif
//--- BRCM

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_alias(DBusConnection *conn, DBusMessage *msg,
					const char *alias, void *data)
{
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;
	int err;

	/* No change */
	if ((device->alias == NULL && g_str_equal(alias, "")) ||
			g_strcmp0(device->alias, alias) == 0)
		return dbus_message_new_method_return(msg);

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	/* Remove alias if empty string */
	err = write_device_alias(srcaddr, dstaddr,
			g_str_equal(alias, "") ? NULL : alias);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	g_free(device->alias);
	device->alias = g_str_equal(alias, "") ? NULL : g_strdup(alias);

	emit_property_changed(conn, dbus_message_get_path(msg),
				DEVICE_INTERFACE, "Alias",
				DBUS_TYPE_STRING, &alias);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_trust(DBusConnection *conn, DBusMessage *msg,
					gboolean value, void *data)
{
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;
	int err;

	if (device->trusted == value)
		return dbus_message_new_method_return(msg);

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	err = write_trust(srcaddr, dstaddr, GLOBAL_TRUST, value);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	device->trusted = value;

//+++ BRCM
//+++ BRCM_LOCAL : can not change connection access(Always ask/ automatic) when this code is removed (CSP 468393).
//#ifndef BT_ALT_STACK
	emit_property_changed(conn, dbus_message_get_path(msg),
				DEVICE_INTERFACE, "Trusted",
				DBUS_TYPE_BOOLEAN, &value);
//#endif
//--- BRCM_LOCAL
//--- BRCM

	return dbus_message_new_method_return(msg);
}

static void driver_remove(struct btd_device_driver *driver,
						struct btd_device *device)
{
//+++ BRCM
	/* Google original
	driver->remove(device);
	*/
//--- BRCM

	device->drivers = g_slist_remove(device->drivers, driver);
}

static gboolean do_disconnect(gpointer user_data)
{
	struct btd_device *device = user_data;
//+++ BRCM
#ifdef BT_ALT_STACK
	tDTUN_DEVICE_METHOD method;
	if (device->disconn_timer)
		g_source_remove(device->disconn_timer);

	device->disconn_timer = 0;

	method.disc_rmt_dev.hdr.id = DTUN_METHOD_DM_DISC_RMT_DEV;
	method.disc_rmt_dev.hdr.len = 6; // no payload
	memcpy(&method.disc_rmt_dev.bdaddr, device->bdaddr.b, 6);

	dtun_client_call_method(&method);

	return TRUE;
#else

	device->disconn_timer = 0;

	btd_adapter_disconnect_device(device->adapter, &device->bdaddr);

	return FALSE;
#endif
//--- BRCM
}

static int device_block(DBusConnection *conn, struct btd_device *device)
{
	int err;
	bdaddr_t src;

	if (device->blocked)
		return 0;

//+++ BRCM
#ifdef BT_ALT_STACK
	err = 0;
	tDTUN_DEVICE_METHOD method;
	method.block_dev.hdr.id = DTUN_METHOD_DM_BLOCK_DEV;
	method.block_dev.hdr.len = sizeof(tDTUN_METHOD_DM_BLOCK_DEV) - sizeof(tDTUN_HDR);
	method.block_dev.block = 1;
	memcpy(&method.block_dev.bdaddr, device->bdaddr.b, 6);
	dtun_client_call_method(&method);

	if (device->connected)
		do_disconnect(device);

	g_slist_foreach(device->drivers, (GFunc) driver_remove, device);
#else
	if (device->connected)
		do_disconnect(device);

	g_slist_foreach(device->drivers, (GFunc) driver_remove, device);

	err = btd_adapter_block_address(device->adapter, &device->bdaddr);
	if (err < 0)
		return err;
#endif
//--- BRCM

	device->blocked = TRUE;

	adapter_get_address(device->adapter, &src);

	err = write_blocked(&src, &device->bdaddr, TRUE);
	if (err < 0)
		error("write_blocked(): %s (%d)", strerror(-err), -err);

	device_set_temporary(device, FALSE);

	emit_property_changed(conn, device->path, DEVICE_INTERFACE, "Blocked",
					DBUS_TYPE_BOOLEAN, &device->blocked);

	return 0;
}

static int device_unblock(DBusConnection *conn, struct btd_device *device,
							gboolean silent)
{
	int err;
	bdaddr_t src;

	if (!device->blocked)
		return 0;

//+++ BRCM
#ifdef BT_ALT_STACK
	/* Block list support for BTLA*/
	err = 0;
	tDTUN_DEVICE_METHOD method;
	method.block_dev.hdr.id = DTUN_METHOD_DM_BLOCK_DEV;
	method.block_dev.hdr.len = sizeof(tDTUN_METHOD_DM_BLOCK_DEV) - sizeof(tDTUN_HDR);
	method.block_dev.block = 0;
	memcpy(&method.block_dev.bdaddr, device->bdaddr.b, 6);
	dtun_client_call_method(&method);
#else
	err = btd_adapter_unblock_address(device->adapter, &device->bdaddr);
	if (err < 0)
		return err;
#endif
//--- BRCM

	device->blocked = FALSE;

	adapter_get_address(device->adapter, &src);

	err = write_blocked(&src, &device->bdaddr, FALSE);
	if (err < 0)
		error("write_blocked(): %s (%d)", strerror(-err), -err);

	if (!silent) {
		emit_property_changed(conn, device->path,
					DEVICE_INTERFACE, "Blocked",
					DBUS_TYPE_BOOLEAN, &device->blocked);
		device_probe_drivers(device, device->uuids);
	}

	return 0;
}

static DBusMessage *set_blocked(DBusConnection *conn, DBusMessage *msg,
						gboolean value, void *data)
{
	struct btd_device *device = data;
	int err;

	if (value)
		err = device_block(conn, device);
	else
		err = device_unblock(conn, device, FALSE);

	switch (-err) {
	case 0:
		return dbus_message_new_method_return(msg);
	case EINVAL:
		return btd_error_failed(msg, "Kernel lacks blacklist support");
	default:
		return btd_error_failed(msg, strerror(-err));
	}
}

//+++ BRCM
static DBusMessage *set_service_trust(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessageIter iter;

	const char *service;
	gboolean trust;
	struct btd_device *device = data;
	struct btd_adapter *adapter = device->adapter;

	char srcaddr[18], dstaddr[18];
	bdaddr_t src;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &service);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
		return btd_error_invalid_args(msg);
	dbus_message_iter_get_basic(&iter, &trust);

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	info("set_service_trust: setting service trust for service: %s to val:%d",
							service, trust);
	write_trust(srcaddr, dstaddr, service, trust);
	return dbus_message_new_method_return(msg);
}
//--- BRCM

static DBusMessage *set_property(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Trusted", property)) {
		dbus_bool_t value;
		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return btd_error_invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &value);

		return set_trust(conn, msg, value, data);
	} else if (g_str_equal("Alias", property)) {
		const char *alias;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return btd_error_invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &alias);

		return set_alias(conn, msg, alias, data);
	} else if (g_str_equal("Blocked", property)) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &value);

		return set_blocked(conn, msg, value, data);
	}

	return btd_error_invalid_args(msg);
}

static void discover_services_req_exit(DBusConnection *conn, void *user_data)
{
	struct browse_req *req = user_data;

	DBG("DiscoverServices requestor exited");

	browse_request_cancel(req);
}

//+++ BRCM
#ifdef BT_ALT_STACK
DBusMessage *g_browse_req = NULL;
DBusConnection *g_browse_conn = NULL;
#endif
//--- BRCM

static DBusMessage *discover_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	const char *pattern;
	int err;

	if (device->browse)
		return btd_error_in_progress(msg);

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	if (strlen(pattern) == 0) {
		err = device_browse_sdp(device, conn, msg, NULL, FALSE);
		if (err < 0)
			goto fail;
//+++ BRCM
#ifdef BT_ALT_STACK
	} else if (strcmp("GET_ALL_SERVICES", pattern) == 0) {

		dtun_client_get_all_remote_services(device->bdaddr);
		if (msg) {
			if (g_browse_req)
				dbus_message_unref(g_browse_req);
			g_browse_req = dbus_message_ref(msg);
		}
		if (conn) {
			if (g_browse_conn)
				dbus_connection_unref(g_browse_conn);
			g_browse_conn = dbus_connection_ref(conn);
		}
#endif
//--- BRCM
	} else {
		uuid_t uuid;

		if (bt_string2uuid(&uuid, pattern) < 0)
			return btd_error_invalid_args(msg);

		sdp_uuid128_to_uuid(&uuid);

		err = device_browse_sdp(device, conn, msg, &uuid, FALSE);
		if (err < 0)
			goto fail;
	}

//+++ BRCM
/* Google original
	return NULL;
*/
	//Although, btld don't care about this return, reply it as success immediately to cleanup the reply recorder in dbus daemon
	debug("replying DiscoverServices as success");
	boolean success = 1;
	DBusMessage* reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &success, DBUS_TYPE_INVALID);
	return reply;
//--- BRCM

fail:
	return btd_error_failed(msg, strerror(-err));
}

static const char *browse_request_get_requestor(struct browse_req *req)
{
	if (!req->msg)
		return NULL;

	return dbus_message_get_sender(req->msg);
}

static void iter_append_record(DBusMessageIter *dict, uint32_t handle,
							const char *record)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT32, &handle);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &record);

	dbus_message_iter_close_container(dict, &entry);
}

//+++ BRCM
#ifdef BT_ALT_STACK
void discover_services_reply(int err, sdp_list_t *recs)
{
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	sdp_list_t *seq;

	if (err) {
		const char *err_if;

		if (err == -EHOSTDOWN)
			err_if = ERROR_INTERFACE ".ConnectionAttemptFailed";
		else
			err_if = ERROR_INTERFACE ".Failed";

		//workaround to start discovery with null
		//browse message request and connection
		if (g_browse_req) {
			reply = dbus_message_new_error(g_browse_req, err_if,
								strerror(-err));
			g_dbus_send_message(g_browse_conn, reply);
		} else {
			//debug("g_browse_req == NULL - skipping response for error case");
		}
		g_browse_req = NULL;
		g_browse_conn = NULL;
		return;
	}

	fflush(stdout);
	if (!g_browse_req) {
		//debug("g_browse_req == NULL - skipping response for success case");
		return;
	}
	reply = dbus_message_new_method_return(g_browse_req);
	if (!reply)
		return;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_UINT32_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		GString *result;

		if (!rec)
			break;

		result = g_string_new(NULL);

		convert_sdp_record_to_xml(rec, result,
				(void *) g_string_append);

		if (result->len)
			iter_append_record(&dict, rec->handle, result->str);

		g_string_free(result, TRUE);
	}

	dbus_message_iter_close_container(&iter, &dict);

	g_dbus_send_message(g_browse_conn, reply);

	if (g_browse_req) {
		dbus_message_unref(g_browse_req);
		g_browse_req = NULL;
	}
	if (g_browse_conn) {
		dbus_connection_unref(g_browse_conn);
		g_browse_conn = NULL;
	}
}
#else
static void discover_services_reply(struct browse_req *req, int err,
							sdp_list_t *recs)
{
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	sdp_list_t *seq;

	if (err) {
		const char *err_if;

		if (err == -EHOSTDOWN)
			err_if = ERROR_INTERFACE ".ConnectionAttemptFailed";
		else
			err_if = ERROR_INTERFACE ".Failed";

		reply = dbus_message_new_error(req->msg, err_if,
							strerror(-err));
		g_dbus_send_message(req->conn, reply);
		return;
	}

	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		return;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_UINT32_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		GString *result;

		if (!rec)
			break;

		result = g_string_new(NULL);

		convert_sdp_record_to_xml(rec, result,
				(void *) g_string_append);

		if (result->len)
			iter_append_record(&dict, rec->handle, result->str);

		g_string_free(result, TRUE);
	}

	dbus_message_iter_close_container(&iter, &dict);

	g_dbus_send_message(req->conn, reply);
}
#endif
//--- BRCM

static DBusMessage *cancel_discover(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	const char *sender = dbus_message_get_sender(msg);
	const char *requestor;

	if (!device->browse)
		return btd_error_does_not_exist(msg);

	if (!dbus_message_is_method_call(device->browse->msg, DEVICE_INTERFACE,
					"DiscoverServices"))
		return btd_error_not_authorized(msg);

	requestor = browse_request_get_requestor(device->browse);

	/* only the discover requestor can cancel the inquiry process */
	if (!requestor || !g_str_equal(requestor, sender))
		return btd_error_not_authorized(msg);

//+++ BRCM
#ifdef BT_ALT_STACK
	discover_services_reply(-ECANCELED, NULL);
#else
	discover_services_reply(device->browse, -ECANCELED, NULL);
#endif
//--- BRCM

	browse_request_cancel(device->browse);

	return dbus_message_new_method_return(msg);
}

static void bonding_request_cancel(struct bonding_req *bonding)
{
	struct btd_device *device = bonding->device;
	struct btd_adapter *adapter = device->adapter;

	adapter_cancel_bonding(adapter, &device->bdaddr);
}

void device_request_disconnect(struct btd_device *device, DBusMessage *msg)
{
	DBusConnection *conn = get_dbus_connection();

	if (device->bonding)
		bonding_request_cancel(device->bonding);

	if (device->browse) {
//+++ BRCM
#ifdef BT_ALT_STACK
		discover_services_reply(-ECANCELED, NULL);
#else
		discover_services_reply(device->browse, -ECANCELED, NULL);
#endif
//--- BRCM
		browse_request_cancel(device->browse);
	}

	if (msg)
		device->disconnects = g_slist_append(device->disconnects,
						dbus_message_ref(msg));

	if (device->disconn_timer)
		return;

	while (device->watches) {
		struct btd_disconnect_data *data = device->watches->data;

		if (data->watch)
			/* temporary is set if device is going to be removed */
			data->watch(device, device->temporary,
							data->user_data);

		/* Check if the watch has been removed by callback function */
		if (!g_slist_find(device->watches, data))
			continue;

		device->watches = g_slist_remove(device->watches, data);
		g_free(data);
	}

	device->disconn_timer = g_timeout_add_seconds(DISCONNECT_TIMER,
						do_disconnect, device);

	g_dbus_emit_signal(conn, device->path,
			DEVICE_INTERFACE, "DisconnectRequested",
			DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_device *device = user_data;

	if (!device->connected)
		return btd_error_not_connected(msg);

	device_request_disconnect(device, msg);

	return NULL;
}

static DBusMessage *get_service_attribute_value_reply(DBusMessage *msg, DBusConnection *conn,
							sdp_data_t *attr)
{
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;
	sdp_data_t *curr;
	sdp_list_t *ap = 0;
	for (; attr; attr = attr->next) {
		sdp_list_t *pds = 0;
		for (curr = attr->val.dataseq; curr; curr = curr->next)
			pds = sdp_list_append(pds, curr->val.dataseq);
		ap = sdp_list_append(ap, pds);
	}

	int ch = sdp_get_proto_port(ap, RFCOMM_UUID);
	sdp_list_foreach(ap, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(ap, NULL);
	ap = NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INT32, &ch, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *get_service_attribute_value(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_device *device = user_data;
	const sdp_record_t *rec;
	sdp_data_t *attr_data;
	const char *pattern;
	uint16_t attrId;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
					DBUS_TYPE_UINT16, &attrId,
					DBUS_TYPE_INVALID) == FALSE)
		goto fail;

	if (strlen(pattern) == 0)
		return btd_error_invalid_args(msg);

//+++ BRCM
#ifdef BT_ALT_STACK

	info("pattern = %s, id = %d", pattern, attrId);
	char hsp_pattern[] = "00001108-0000-1000-8000-00805f9b34fb";
	char hfp_pattern[] = "0000111e-0000-1000-8000-00805f9b34fb";
	int ch = 0xFF;

	/* Handsfree */
	if (attrId == 0x0004) {
		if (!strcmp(pattern, hfp_pattern))
			ch = 0x111E;
		else if (!strcmp(pattern, hsp_pattern))
			ch = 0x1108;
	}

	if (ch != 0xFF) {
		DBusMessage *reply = dbus_message_new_method_return(msg);
		if (!reply)
			goto fail;

		dbus_message_append_args(reply, DBUS_TYPE_INT32, &ch, DBUS_TYPE_INVALID);
		return reply;
	}

#endif //BT_ALT_STACK
//--- BRCM

	rec = btd_device_get_record(device, pattern);
	if (rec == NULL) {
		error("rec is NULL");
		goto fail;
	}

	attr_data = sdp_data_get(rec, attrId);

	if (attr_data == NULL) {
		error("attr in null");
		goto fail;
	}
	return get_service_attribute_value_reply(msg, conn, attr_data);
fail:
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
					"GetServiceAttribute Failed");
}

//+++ BRCM
static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
}

static DBusMessage *fetch_remote_di_info (DBusConnection *conn, DBusMessage *msg)
{
	char *remote_addr;
	bdaddr_t ba;
	error("fetch_remote_di_info");
	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &remote_addr,
			DBUS_TYPE_INVALID))
		return invalid_args(msg);

	str2ba(remote_addr, &ba);
	dtun_fetch_remote_di_info(ba);
	return dbus_message_new_method_return(msg);
}
//--- BRCM

static GDBusMethodTable device_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties	},
	{ "SetProperty",	"sv",	"",		set_property	},
	{ "DiscoverServices",	"s",	"a{us}",	discover_services,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CancelDiscovery",	"",	"",		cancel_discover	},
	{ "Disconnect",		"",	"",		disconnect,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "GetServiceAttributeValue",  "sq", "i",       get_service_attribute_value},
//+++ BRCM
	{ "FetchRemoteDiInfo",   "s", "", fetch_remote_di_info },
	{ "SetServiceTrust", "sb", "", set_service_trust },
//--- BRCM
	{ }
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "DisconnectRequested",	""	},
//+++ BRCM
	{ "RemoteDiInfoReceived",   "sqq" },
	{ "RemoteDiRecordReceived", "qqbqqqqqsss" },
//--- BRCM
	{ }
};

gboolean device_is_connected(struct btd_device *device)
{
	return device->connected;
}

void device_add_connection(struct btd_device *device, DBusConnection *conn)
{
	if (device->connected) {
		char addr[18];
		ba2str(&device->bdaddr, addr);
		error("Device %s is already connected", addr);
		return;
	}

	device->connected = TRUE;

	emit_property_changed(conn, device->path,
					DEVICE_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &device->connected);
}

void device_remove_connection(struct btd_device *device, DBusConnection *conn)
{
	if (!device->connected) {
		char addr[18];
		ba2str(&device->bdaddr, addr);
		error("Device %s isn't connected", addr);
		return;
	}

	device->connected = FALSE;

	if (device->disconn_timer > 0) {
		g_source_remove(device->disconn_timer);
		device->disconn_timer = 0;
	}

//+++ BRCM
//Remove this CSP#614457
//	if (device->discov_timer > 0) {
//		g_source_remove(device->discov_timer);
//		device->discov_timer = 0;
//	}
//--- BRCM

	while (device->disconnects) {
		DBusMessage *msg = device->disconnects->data;

		g_dbus_send_reply(conn, msg, DBUS_TYPE_INVALID);
		device->disconnects = g_slist_remove(device->disconnects, msg);
	}

	if (device_is_paired(device) && !device->bonded)
		device_set_paired(device, FALSE);

	emit_property_changed(conn, device->path,
					DEVICE_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &device->connected);
}

guint device_add_disconnect_watch(struct btd_device *device,
				disconnect_watch watch, void *user_data,
				GDestroyNotify destroy)
{
	struct btd_disconnect_data *data;
	static guint id = 0;

	data = g_new0(struct btd_disconnect_data, 1);
	data->id = ++id;
	data->watch = watch;
	data->user_data = user_data;
	data->destroy = destroy;

	device->watches = g_slist_append(device->watches, data);

	return data->id;
}

void device_remove_disconnect_watch(struct btd_device *device, guint id)
{
	GSList *l;

	for (l = device->watches; l; l = l->next) {
		struct btd_disconnect_data *data = l->data;

		if (data->id == id) {
			device->watches = g_slist_remove(device->watches,
							data);
			if (data->destroy)
				data->destroy(data->user_data);
			g_free(data);
			return;
		}
	}
}

struct btd_device *device_create(DBusConnection *conn,
				struct btd_adapter *adapter,
				const gchar *address, device_type_t type)
{
	gchar *address_up;
	struct btd_device *device;
	const gchar *adapter_path = adapter_get_path(adapter);
	bdaddr_t src;
	char srcaddr[18], alias[MAX_NAME_LENGTH + 1];

	device = g_try_malloc0(sizeof(struct btd_device));
	if (device == NULL)
		return NULL;

	address_up = g_ascii_strup(address, -1);
	device->path = g_strdup_printf("%s/dev_%s", adapter_path, address_up);
	g_strdelimit(device->path, ":", '_');
	g_free(address_up);

	DBG("Creating device %s", device->path);

	if (g_dbus_register_interface(conn, device->path, DEVICE_INTERFACE,
				device_methods, device_signals, NULL,
				device, device_free) == FALSE) {
		device_free(device);
		return NULL;
	}

	str2ba(address, &device->bdaddr);
	device->adapter = adapter;
	device->type = type;
	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
//+++ BRCM
#ifdef BT_ALT_STACK
	device->name[0] = 0;
#endif
//--- BRCM
	read_device_name(srcaddr, address, device->name);
	if (read_device_alias(srcaddr, address, alias, sizeof(alias)) == 0)
		device->alias = g_strdup(alias);
	device->trusted = read_trust(&src, address, GLOBAL_TRUST);

	if (read_blocked(&src, &device->bdaddr))
		device_block(conn, device);

//+++ BRCM
/* Google original
	if (read_link_key(&src, &device->bdaddr, NULL, NULL) == 0) {
*/
	if (read_link_key(&src, &device->bdaddr, NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_PENC,  NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_PID,   NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_PCSRK, NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_LENC,  NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_LCSRK, NULL, NULL) == 0)
	{
//--- BRCM
		device->paired = TRUE;
		device_set_bonded(device, TRUE);
	}

	return btd_device_ref(device);
}

void device_set_name(struct btd_device *device, const char *name)
{
	DBusConnection *conn = get_dbus_connection();

//+++ BRCM_LOCAL : [CASE#506591]
// Sometimes new name is same as old name.
// But UI had been not updated.
    /* google original
	if (strncmp(name, device->name, MAX_NAME_LENGTH) == 0)
		return;
     */
//--- BRCM_LOCAL

	strncpy(device->name, name, MAX_NAME_LENGTH);

	emit_property_changed(conn, device->path,
				DEVICE_INTERFACE, "Name",
				DBUS_TYPE_STRING, &name);

	if (device->alias != NULL)
		return;

	emit_property_changed(conn, device->path,
				DEVICE_INTERFACE, "Alias",
				DBUS_TYPE_STRING, &name);
}

void device_get_name(struct btd_device *device, char *name, size_t len)
{
	strncpy(name, device->name, len);
}

device_type_t device_get_type(struct btd_device *device)
{
	return device->type;
}

void device_remove_bonding(struct btd_device *device)
{
	char filename[PATH_MAX + 1];
	char srcaddr[18], dstaddr[18];
	bdaddr_t bdaddr;
//+++ BRCM
	char addr_and_type[24];
//--- BRCM

	adapter_get_address(device->adapter, &bdaddr);
	ba2str(&bdaddr, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

//+++ BRCM
#ifdef BT_ALT_STACK
	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr,
			"hidinfo");
	textfile_casedel(filename, dstaddr);
	if(device->type == DEVICE_TYPE_LE)
		create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "blelinkkeys");
	else
		create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "linkkeys");
#else
	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr,
			"linkkeys");
#endif

#ifdef BT_ALT_STACK

	tDTUN_DEVICE_METHOD method;
	memcpy(&method.bond.bdaddr, &device->bdaddr, 6);
	method.bond.hdr.id = DTUN_METHOD_DM_REMOVE_BONDING;
	method.bond.hdr.len = sizeof(tDTUN_BOND) - sizeof(tDTUN_HDR);
	method.bond.cod = read_device_cod(&bdaddr, &device->bdaddr);

	dtun_client_call_method(&method);

//+++ BRCM_LOCAL : CSP#538367 due to holding device information,re-fetching SDP records could get failed
    {
        panu_remove(device);
	    DBG("%p: ref=%d panu_ clear", device, device->ref);
    }
//--- BRCM_LOCAL 

	dtun_device_check_remove_audio(device);
	dtun_remove_hdp_device(device);
	/* Delete the link key from storage */
	if (device->type != DEVICE_TYPE_LE)
	textfile_casedel(filename, dstaddr);
	else
	{
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_PENC);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_PID);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_PCSRK);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_LENC);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_LCSRK);
		textfile_casedel(filename, addr_and_type);
	}
	device_set_bonded(device, FALSE);
#else
	/* Delete the link key from storage */
	textfile_casedel(filename, dstaddr);
	device_set_bonded(device, FALSE);

	btd_adapter_remove_bonding(device->adapter, &device->bdaddr);
#endif
//--- BRCM
}

static void device_remove_stored(struct btd_device *device)
{
	bdaddr_t src;
	char addr[18];
	DBusConnection *conn = get_dbus_connection();

	adapter_get_address(device->adapter, &src);
	ba2str(&device->bdaddr, addr);

//+++ BRCM
	// Always removed stored device irrespective of the
	// nature of bonding
/* Google original
	if (device->paired)
*/
//--- BRCM
	device_remove_bonding(device);
	delete_entry(&src, "profiles", addr);
	delete_entry(&src, "trusts", addr);
//+++ BRCM
/* Google original
	delete_entry(&src, "types", addr);
*/
//--- BRCM
	delete_entry(&src, "primary", addr);
	delete_all_records(&src, &device->bdaddr);
	delete_device_service(&src, &device->bdaddr);

	if (device->blocked)
		device_unblock(conn, device, TRUE);
}

void device_remove(struct btd_device *device, gboolean remove_stored)
{

	DBG("Removing device %s", device->path);

	if (device->agent)
		agent_free(device->agent);

	if (device->bonding) {
		uint8_t status;

		if (device->connected)
			status = HCI_OE_USER_ENDED_CONNECTION;
		else
			status = HCI_PAGE_TIMEOUT;

		device_cancel_bonding(device, status);
	}

	if (device->browse) {
//+++ BRCM
#ifdef BT_ALT_STACK
		discover_services_reply(-ECANCELED, NULL);
#else
		discover_services_reply(device->browse, -ECANCELED, NULL);
#endif
//--- BRCM
		browse_request_cancel(device->browse);
	}

	if (device->connected)
		do_disconnect(device);

	if (remove_stored)
		device_remove_stored(device);

	g_slist_foreach(device->drivers, (GFunc) driver_remove, device);
	g_slist_free(device->drivers);
	device->drivers = NULL;

	attrib_client_unregister(device);

//+++ BRCM
#ifdef BT_ALT_STACK
	while (device->ref) {
		btd_device_unref(device);
	}
#else
	btd_device_unref(device);
#endif
//--- BRCM
}

gint device_address_cmp(struct btd_device *device, const gchar *address)
{
	char addr[18];

	ba2str(&device->bdaddr, addr);
	return strcasecmp(addr, address);
}

static gboolean record_has_uuid(const sdp_record_t *rec,
				const char *profile_uuid)
{
	sdp_list_t *pat;

	for (pat = rec->pattern; pat != NULL; pat = pat->next) {
		char *uuid;
		int ret;

		uuid = bt_uuid2string(pat->data);
		if (!uuid)
			continue;

		ret = strcasecmp(uuid, profile_uuid);

		g_free(uuid);

		if (ret == 0)
			return TRUE;
	}

	return FALSE;
}

static GSList *device_match_pattern(struct btd_device *device,
					const char *match_uuid,
					GSList *profiles)
{
	GSList *l, *uuids = NULL;

	for (l = profiles; l; l = l->next) {
		char *profile_uuid = l->data;
		const sdp_record_t *rec;

		rec = btd_device_get_record(device, profile_uuid);
		if (!rec)
			continue;

		if (record_has_uuid(rec, match_uuid))
			uuids = g_slist_append(uuids, profile_uuid);
	}

	return uuids;
}

static GSList *device_match_driver(struct btd_device *device,
					struct btd_device_driver *driver,
					GSList *profiles)
{
	const char **uuid;
	GSList *uuids = NULL;

	for (uuid = driver->uuids; *uuid; uuid++) {
		GSList *match;

		/* skip duplicated uuids */
		if (g_slist_find_custom(uuids, *uuid,
				(GCompareFunc) strcasecmp))
			continue;

		/* match profile driver */
		match = g_slist_find_custom(profiles, *uuid,
					(GCompareFunc) strcasecmp);
		if (match) {
			uuids = g_slist_append(uuids, match->data);
			continue;
		}

		/* match pattern driver */
		match = device_match_pattern(device, *uuid, profiles);
		uuids = g_slist_concat(uuids, match);
	}

	return uuids;
}

//+++ BRCM
#ifdef BT_ALT_STACK
sdp_record_t * device_add_rfcomm_record( struct btd_device *device, uuid_t uuid, uint8_t channel)
{
	uuid_t root_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_list_t *svclass, *root, *proto;
	sdp_record_t *record;
	struct btd_adapter *adapter = device_get_adapter(device);
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);


	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto = sdp_list_append(NULL, sdp_list_append(NULL, &l2cap_uuid));

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto = sdp_list_append(proto, sdp_list_append(
			sdp_list_append(NULL, &rfcomm_uuid),
			sdp_data_alloc(SDP_UINT8, &channel)));

	sdp_set_access_protos(record, sdp_list_append(NULL, proto));

	svclass = sdp_list_append(NULL, &uuid);
	sdp_set_service_classes(record, svclass);


	store_record(srcaddr, dstaddr, record);

//  device->tmp_records = record;
//  sdp_set_info_attr(record, name, NULL, NULL);

	/* force reading sdp records from file */

	if (device->tmp_records) {
		sdp_list_free (device->tmp_records, (sdp_free_func_t) sdp_record_free);
		device->tmp_records = NULL;
	}
	return record;
}
#endif //BT_ALT_STACK
//--- BRCM

void device_probe_drivers(struct btd_device *device, GSList *profiles)
{
	GSList *list;
	char addr[18];
	int err;

	ba2str(&device->bdaddr, addr);

	if (device->blocked) {
		DBG("Skipping drivers for blocked device %s", addr);
		goto add_uuids;
	}

	DBG("Probing drivers for %s", addr);

	for (list = device_drivers; list; list = list->next) {
		struct btd_device_driver *driver = list->data;
		GSList *probe_uuids;

		probe_uuids = device_match_driver(device, driver, profiles);

		if (!probe_uuids)
			continue;

		err = driver->probe(device, probe_uuids);
		if (err < 0) {
			error("%s driver probe failed for device %s",
							driver->name, addr);
			g_slist_free(probe_uuids);
			continue;
		}

		device->drivers = g_slist_append(device->drivers, driver);
		g_slist_free(probe_uuids);
	}

add_uuids:
	for (list = profiles; list; list = list->next) {
		GSList *l = g_slist_find_custom(device->uuids, list->data,
						(GCompareFunc) strcasecmp);
		if (l)
			continue;

		device->uuids = g_slist_insert_sorted(device->uuids,
						g_strdup(list->data),
						(GCompareFunc) strcasecmp);
//+++ BRCM
#ifdef BT_ALT_STACK
		dtun_init_device_uuid(device, g_strdup(list->data));
#endif
//--- BRCM
	}
}

static void device_remove_drivers(struct btd_device *device, GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	GSList *list, *next;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;
	sdp_list_t *records;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	records = read_records(&src, &device->bdaddr);

	DBG("Removing drivers for %s", dstaddr);

	for (list = device->drivers; list; list = next) {
		struct btd_device_driver *driver = list->data;
		const char **uuid;

		next = list->next;

		for (uuid = driver->uuids; *uuid; uuid++) {
			if (!g_slist_find_custom(uuids, *uuid,
						(GCompareFunc) strcasecmp))
				continue;

			DBG("UUID %s was removed from device %s",
							*uuid, dstaddr);

			driver->remove(device);
			device->drivers = g_slist_remove(device->drivers,
								driver);
			break;
		}
	}

	for (list = uuids; list; list = list->next) {
		sdp_record_t *rec;

		device->uuids = g_slist_remove(device->uuids, list->data);

		rec = find_record_in_list(records, list->data);
		if (!rec)
			continue;

		delete_record(srcaddr, dstaddr, rec->handle);

		records = sdp_list_remove(records, rec);
		sdp_record_free(rec);

	}

	if (records)
		sdp_list_free(records, (sdp_free_func_t) sdp_record_free);
}

static void services_changed(struct btd_device *device)
{
	DBusConnection *conn = get_dbus_connection();
	char **uuids;
	GSList *l;
	int i;

	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;

	emit_array_property_changed(conn, device->path, DEVICE_INTERFACE,
					"UUIDs", DBUS_TYPE_STRING, &uuids, i);

	g_free(uuids);
}

//+++ BRCM
void services_changed_with_empty_uuids(struct btd_device *device)
{
    DBusConnection *conn = get_dbus_connection();
    emit_array_property_changed(conn, device->path, DEVICE_INTERFACE,
                    "UUIDs", DBUS_TYPE_STRING, NULL, 0);
}
void device_fetch_remote_di_info (struct btd_device *device,
	tDTUN_SIG_DM_FETCH_REMOTE_DI_INFO *di_info)
{
	DBusConnection *conn = get_dbus_connection();
	uint16_t rec_num = di_info->rec_num;
	uint16_t status = di_info->status;
	char remote_addr[18], *addr = remote_addr;

	ba2str(&di_info->remote_addr, addr);
	debug("%s: rec_num=%d status=%d [%s]", __FUNCTION__, rec_num, status, addr);

	if (!g_dbus_emit_signal(
		conn, device->path, DEVICE_INTERFACE, "RemoteDiInfoReceived",
		DBUS_TYPE_STRING, &addr,
		DBUS_TYPE_UINT16, &rec_num,
		DBUS_TYPE_UINT16, &status,
		DBUS_TYPE_INVALID))
	{
		error("%s: Failed to emit signal", __FUNCTION__);
	}
}

void device_fetch_remote_di_rec (struct btd_device *device,
	tDTUN_SIG_DM_FETCH_REMOTE_DI_REC *di_rec)
{
	DBusConnection *conn = get_dbus_connection();
	uint16_t handle = di_rec->handle;
	uint16_t status = di_rec->status;
	boolean primary_record = di_rec->primary_record;
	uint16_t spec_id = di_rec->spec_id;
	uint16_t vendor_id = di_rec->vendor_id;
	uint16_t vendor_id_source = di_rec->vendor_id_source;
	uint16_t product_id = di_rec->product_id;
	uint16_t version = di_rec->version;
	char *client_executable_url = di_rec->client_executable_url;
	char *service_description = di_rec->service_description;
	char *documentation_url = di_rec->documentation_url;

	debug("handle=%d status=%d primary_record=%d spec_id=0x%04X vendor_id=%d vendor_id_source=%d product_id=0x%04X version=0x%04X",
		handle, status, primary_record, spec_id, vendor_id, vendor_id_source, product_id, version);
	if (*client_executable_url) {
		debug("  client_executable_url = [%s]", client_executable_url);
	}
	if (*service_description) {
		debug("  service_description = [%s]", service_description);
	}
	if (*documentation_url) {
		debug("  documentation_url = [%s]", documentation_url);
	}

	if (!g_dbus_emit_signal(
		conn, device->path, DEVICE_INTERFACE, "RemoteDiRecordReceived",
		DBUS_TYPE_UINT16,  &handle,
		DBUS_TYPE_UINT16,  &status,
		DBUS_TYPE_BOOLEAN, &primary_record,
		DBUS_TYPE_UINT16,  &spec_id,
		DBUS_TYPE_UINT16,  &vendor_id,
		DBUS_TYPE_UINT16,  &vendor_id_source,
		DBUS_TYPE_UINT16,  &product_id,
		DBUS_TYPE_UINT16,  &version,
		DBUS_TYPE_STRING,  &client_executable_url,
		DBUS_TYPE_STRING,  &service_description,
		DBUS_TYPE_STRING,  &documentation_url,
		DBUS_TYPE_INVALID))
	{
		error("%s: Failed to emit signal", __FUNCTION__);
	}
}
//--- BRCM

static int rec_cmp(const void *a, const void *b)
{
	const sdp_record_t *r1 = a;
	const sdp_record_t *r2 = b;

	return r1->handle - r2->handle;
}

static void update_services(struct browse_req *req, sdp_list_t *recs)
{
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device_get_adapter(device);
	sdp_list_t *seq;
	char srcaddr[18], dstaddr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_list_t *svcclass = NULL;
		gchar *profile_uuid;
		GSList *l;

		if (!rec)
			break;

		if (sdp_get_service_classes(rec, &svcclass) < 0)
			continue;

		/* Check for empty service classes list */
		if (svcclass == NULL) {
			DBG("Skipping record with no service classes");
			continue;
		}

		/* Extract the first element and skip the remainning */
		profile_uuid = bt_uuid2string(svcclass->data);
		if (!profile_uuid) {
			sdp_list_free(svcclass, free);
			continue;
		}

		if (!strcasecmp(profile_uuid, PNP_UUID)) {
			uint16_t source, vendor, product, version;
			sdp_data_t *pdlist;

			pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID_SOURCE);
			source = pdlist ? pdlist->val.uint16 : 0x0000;

			pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
			vendor = pdlist ? pdlist->val.uint16 : 0x0000;

			pdlist = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
			product = pdlist ? pdlist->val.uint16 : 0x0000;

			pdlist = sdp_data_get(rec, SDP_ATTR_VERSION);
			version = pdlist ? pdlist->val.uint16 : 0x0000;

			if (source || vendor || product || version)
				store_device_id(srcaddr, dstaddr, source,
						vendor, product, version);
		}

		/* Check for duplicates */
		if (sdp_list_find(req->records, rec, rec_cmp)) {
			g_free(profile_uuid);
			sdp_list_free(svcclass, free);
			continue;
		}

		store_record(srcaddr, dstaddr, rec);

		/* Copy record */
		req->records = sdp_list_append(req->records,
							sdp_copy_record(rec));

		l = g_slist_find_custom(device->uuids, profile_uuid,
							(GCompareFunc) strcmp);
		if (!l)
			req->profiles_added =
					g_slist_append(req->profiles_added,
							profile_uuid);
		else {
			req->profiles_removed =
					g_slist_remove(req->profiles_removed,
							l->data);
			g_free(profile_uuid);
		}

		sdp_list_free(svcclass, free);
	}
}

static void store_profiles(struct btd_device *device)
{
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src;
	char *str;

	adapter_get_address(adapter, &src);

	if (!device->uuids) {
		write_device_profiles(&src, &device->bdaddr, "");
		return;
	}

	str = bt_list2string(device->uuids);
	write_device_profiles(&src, &device->bdaddr, str);
	g_free(str);
}

static void create_device_reply(struct btd_device *device, struct browse_req *req)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		return;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &device->path,
					DBUS_TYPE_INVALID);

	g_dbus_send_message(req->conn, reply);
}

GSList *device_services_from_record(struct btd_device *device, GSList *profiles)
{
	GSList *l, *prim_list = NULL;
	char *att_uuid;
	uuid_t proto_uuid;

	sdp_uuid16_create(&proto_uuid, ATT_UUID);
	att_uuid = bt_uuid2string(&proto_uuid);

	for (l = profiles; l; l = l->next) {
		const char *profile_uuid = l->data;
		const sdp_record_t *rec;
		struct att_primary *prim;
		uint16_t start = 0, end = 0, psm = 0;
		uuid_t prim_uuid;

		rec = btd_device_get_record(device, profile_uuid);
		if (!rec)
			continue;

		if (!record_has_uuid(rec, att_uuid))
			continue;

		if (!gatt_parse_record(rec, &prim_uuid, &psm, &start, &end))
			continue;

		prim = g_new0(struct att_primary, 1);
		prim->start = start;
		prim->end = end;
		sdp_uuid2strn(&prim_uuid, prim->uuid, sizeof(prim->uuid));

		prim_list = g_slist_append(prim_list, prim);
	}

	g_free(att_uuid);

	return prim_list;
}

static void search_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;
	char addr[18];

	ba2str(&device->bdaddr, addr);

	if (err < 0) {
		error("%s: error updating services: %s (%d)",
				addr, strerror(-err), -err);
		goto send_reply;
	}

	update_services(req, recs);

	if (device->tmp_records)
		sdp_list_free(device->tmp_records,
					(sdp_free_func_t) sdp_record_free);

	device->tmp_records = req->records;
	req->records = NULL;

	if (!req->profiles_added && !req->profiles_removed) {
		DBG("%s: No service update", addr);
		goto send_reply;
	}

	/* Probe matching drivers for services added */
	if (req->profiles_added) {
		GSList *list;

		device_probe_drivers(device, req->profiles_added);

		list = device_services_from_record(device, req->profiles_added);
		if (list)
			device_register_services(req->conn, device, list,
								ATT_PSM);
	}

	/* Remove drivers for services removed */
	if (req->profiles_removed)
		device_remove_drivers(device, req->profiles_removed);

	/* Propagate services changes */
	services_changed(req->device);

send_reply:
	if (!req->msg)
		goto cleanup;

	if (dbus_message_is_method_call(req->msg, DEVICE_INTERFACE,
					"DiscoverServices"))
//+++ BRCM
#ifdef BT_ALT_STACK
		discover_services_reply(err, device->tmp_records);
#else
		discover_services_reply(req, err, device->tmp_records);
#endif
//--- BRCM
	else if (dbus_message_is_method_call(req->msg, ADAPTER_INTERFACE,
						"CreatePairedDevice"))
		create_device_reply(device, req);
	else if (dbus_message_is_method_call(req->msg, ADAPTER_INTERFACE,
						"CreateDevice")) {
		if (err < 0) {
			DBusMessage *reply;
			reply = btd_error_failed(req->msg, strerror(-err));
			g_dbus_send_message(req->conn, reply);
			goto cleanup;
		}

		create_device_reply(device, req);
		device_set_temporary(device, FALSE);
	}

cleanup:
	if (!device->temporary) {
		bdaddr_t sba, dba;

		adapter_get_address(device->adapter, &sba);
		device_get_address(device, &dba);

		store_profiles(device);
		write_device_type(&sba, &dba, device->type);
	}

	device->browse = NULL;
	browse_request_free(req);
}

static void browse_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t src;
	uuid_t uuid;

	/* If we have a valid response and req->search_uuid == 2, then L2CAP
	 * UUID & PNP searching was successful -- we are done */
	if (err < 0 || (req->search_uuid == 2 && req->records)) {
		if (err == -ECONNRESET && req->reconnect_attempt < 1) {
			req->search_uuid--;
			req->reconnect_attempt++;
		} else
			goto done;
	}

	update_services(req, recs);

	adapter_get_address(adapter, &src);

	/* Search for mandatory uuids */
	if (uuid_list[req->search_uuid]) {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid++]);
		bt_search_service(&src, &device->bdaddr, &uuid,
						browse_cb, user_data, NULL);
		return;
	}

done:
	search_cb(recs, err, user_data);
}

static void init_browse(struct browse_req *req, gboolean reverse)
{
	GSList *l;

	/* If we are doing reverse-SDP don't try to detect removed profiles
	 * since some devices hide their service records while they are
	 * connected
	 */
	if (reverse)
		return;

	for (l = req->device->uuids; l; l = l->next)
		req->profiles_removed = g_slist_append(req->profiles_removed,
						l->data);
}

static char *primary_list_to_string(GSList *primary_list)
{
	GString *services;
	GSList *l;

	services = g_string_new(NULL);

	for (l = primary_list; l; l = l->next) {
		struct att_primary *primary = l->data;
		char service[64];

		memset(service, 0, sizeof(service));

		snprintf(service, sizeof(service), "%04X#%04X#%s ",
				primary->start, primary->end, primary->uuid);

		services = g_string_append(services, service);
	}

	return g_string_free(services, FALSE);
}

static void store_services(struct btd_device *device)
{
	struct btd_adapter *adapter = device->adapter;
	bdaddr_t dba, sba;
	char *str = primary_list_to_string(device->primaries);

	adapter_get_address(adapter, &sba);
	device_get_address(device, &dba);

	write_device_type(&sba, &dba, device->type);
	write_device_services(&sba, &dba, str);

	g_free(str);
}

static void primary_cb(GSList *services, guint8 status, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;
	GSList *l, *uuids = NULL;

	if (status) {
		DBusMessage *reply;
		reply = btd_error_failed(req->msg, att_ecode2str(status));
		g_dbus_send_message(req->conn, reply);
		goto done;
	}

	services_changed(device);
	device_set_temporary(device, FALSE);

	for (l = services; l; l = l->next) {
		struct att_primary *prim = l->data;
		uuids = g_slist_append(uuids, prim->uuid);
	}

	device_probe_drivers(device, uuids);

	device_register_services(req->conn, device, g_slist_copy(services), -1);

	g_slist_free(uuids);

	create_device_reply(device, req);

	store_services(device);

done:
	device->browse = NULL;
	browse_request_free(req);
}

static void gatt_connect_cb(GIOChannel *io, GError *gerr, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct btd_device *device = req->device;

	if (gerr) {
		DBusMessage *reply;

		DBG("%s", gerr->message);

		reply = btd_error_failed(req->msg, gerr->message);
		g_dbus_send_message(req->conn, reply);

		device->browse = NULL;
		browse_request_free(req);

		return;
	}

	req->attrib = g_attrib_new(io);
	g_io_channel_unref(io);

	gatt_discover_primary(req->attrib, NULL, primary_cb, req);
}

int device_browse_primary(struct btd_device *device, DBusConnection *conn,
				DBusMessage *msg, gboolean secure)
{
	struct btd_adapter *adapter = device->adapter;
	struct browse_req *req;
	BtIOSecLevel sec_level;
	GIOChannel *io;
	bdaddr_t src;

	if (device->browse)
		return -EBUSY;

	req = g_new0(struct browse_req, 1);
	req->device = btd_device_ref(device);

	adapter_get_address(adapter, &src);

	sec_level = secure ? BT_IO_SEC_HIGH : BT_IO_SEC_LOW;

	io = bt_io_connect(BT_IO_L2CAP, gatt_connect_cb, req, NULL, NULL,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_DEST_BDADDR, &device->bdaddr,
				BT_IO_OPT_CID, ATT_CID,
				BT_IO_OPT_SEC_LEVEL, sec_level,
				BT_IO_OPT_INVALID);

	if (io == NULL ) {
		browse_request_free(req);
		return -EIO;
	}

	if (conn == NULL)
		conn = get_dbus_connection();

	req->conn = dbus_connection_ref(conn);
	device->browse = req;

	if (msg) {
		const char *sender = dbus_message_get_sender(msg);

		req->msg = dbus_message_ref(msg);
		/* Track the request owner to cancel it
		 * automatically if the owner exits */
		req->listener_id = g_dbus_add_disconnect_watch(conn,
						sender,
						discover_services_req_exit,
						req, NULL);
	}

	return 0;
}

//+++ BRCM
#ifdef BT_ALT_STACK
int device_browse_sdp(struct btd_device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search, gboolean reverse)
{
	if (search) {
		dtun_client_get_remote_svc_channel(device, device->bdaddr, search);
	} else {
		dtun_client_get_remote_services(device->bdaddr);
	}
	if (msg) {
		if (g_browse_req)
			dbus_message_unref(g_browse_req);
		g_browse_req = dbus_message_ref(msg);
	}
	if (conn) {
		if (g_browse_conn)
			dbus_connection_unref(g_browse_conn);
		g_browse_conn = dbus_connection_ref(conn);
	}

	return 0;
}
#else
int device_browse_sdp(struct btd_device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search, gboolean reverse)
{
	struct btd_adapter *adapter = device->adapter;
	struct browse_req *req;
	bt_callback_t cb;
	bdaddr_t src;
	uuid_t uuid;
	int err;

	if (device->browse)
		return -EBUSY;

	adapter_get_address(adapter, &src);

	req = g_new0(struct browse_req, 1);
	req->device = btd_device_ref(device);
	if (search) {
		memcpy(&uuid, search, sizeof(uuid_t));
		cb = search_cb;
	} else {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid++]);
		init_browse(req, reverse);
		cb = browse_cb;
	}

	err = bt_search_service(&src, &device->bdaddr, &uuid, cb, req, NULL);
	if (err < 0) {
		browse_request_free(req);
		return err;
	}

	if (conn == NULL)
		conn = get_dbus_connection();

	req->conn = dbus_connection_ref(conn);
	device->browse = req;

	if (msg) {
		const char *sender = dbus_message_get_sender(msg);

		req->msg = dbus_message_ref(msg);
		/* Track the request owner to cancel it
		 * automatically if the owner exits */
		req->listener_id = g_dbus_add_disconnect_watch(conn,
						sender,
						discover_services_req_exit,
						req, NULL);
	}

	return err;
}
#endif
//--- BRCM

struct btd_adapter *device_get_adapter(struct btd_device *device)
{
	if (!device)
		return NULL;

	return device->adapter;
}

void device_get_address(struct btd_device *device, bdaddr_t *bdaddr)
{
	bacpy(bdaddr, &device->bdaddr);
}

const gchar *device_get_path(struct btd_device *device)
{
	if (!device)
		return NULL;

	return device->path;
}

struct agent *device_get_agent(struct btd_device *device)
{
	if (!device)
		return NULL;

	if (device->agent)
		return device->agent;

	return adapter_get_agent(device->adapter);
}

gboolean device_is_busy(struct btd_device *device)
{
	return device->browse ? TRUE : FALSE;
}

gboolean device_is_temporary(struct btd_device *device)
{
	return device->temporary;
}

void device_set_temporary(struct btd_device *device, gboolean temporary)
{
	if (!device)
		return;

	DBG("temporary %d", temporary);

	device->temporary = temporary;
}

void device_set_bonded(struct btd_device *device, gboolean bonded)
{
	if (!device)
		return;

	DBG("bonded %d", bonded);

	device->bonded = bonded;
}

void device_set_type(struct btd_device *device, device_type_t type)
{
	if (!device)
		return;

	device->type = type;
}

static gboolean start_discovery(gpointer user_data)
{
	struct btd_device *device = user_data;

//+++ BRCM
#ifdef BT_ALT_STACK
	if (device_is_paired(device))
		device_browse_sdp(device, NULL, NULL, NULL, TRUE);
#else
	device_browse_sdp(device, NULL, NULL, NULL, TRUE);
#endif
//--- BRCM

	device->discov_timer = 0;

	return FALSE;
}

static DBusMessage *new_authentication_return(DBusMessage *msg, int status)
{
	switch (status) {
	case 0x00: /* success */
		return dbus_message_new_method_return(msg);

	case 0x04: /* page timeout */
		return dbus_message_new_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				"Page Timeout");
	case 0x08: /* connection timeout */
		return dbus_message_new_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				"Connection Timeout");
	case 0x10: /* connection accept timeout */
	case 0x22: /* LMP response timeout */
	case 0x28: /* instant passed - is this a timeout? */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationTimeout",
					"Authentication Timeout");
	case 0x17: /* too frequent pairing attempts */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".RepeatedAttempts",
					"Repeated Attempts");

	case 0x06:
	case 0x18: /* pairing not allowed (e.g. gw rejected attempt) */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationRejected",
					"Authentication Rejected");

	case 0x07: /* memory capacity */
	case 0x09: /* connection limit */
	case 0x0a: /* synchronous connection limit */
	case 0x0d: /* limited resources */
	case 0x13: /* user ended the connection */
	case 0x14: /* terminated due to low resources */
	case 0x16: /* connection terminated */
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationCanceled",
					"Authentication Canceled");

	case 0x05: /* authentication failure */
	case 0x0E: /* rejected due to security reasons - is this auth failure? */
	case 0x25: /* encryption mode not acceptable - is this auth failure? */
	case 0x26: /* link key cannot be changed - is this auth failure? */
	case 0x29: /* pairing with unit key unsupported - is this auth failure? */
	case 0x2f: /* insufficient security - is this auth failure? */
	default:
		return dbus_message_new_error(msg,
					ERROR_INTERFACE ".AuthenticationFailed",
					"Authentication Failed");
	}
}

static void bonding_request_free(struct bonding_req *bonding)
{
	struct btd_device *device;

	if (!bonding)
		return;

	if (bonding->listener_id)
		g_dbus_remove_watch(bonding->conn, bonding->listener_id);

	if (bonding->msg)
		dbus_message_unref(bonding->msg);

	if (bonding->conn)
		dbus_connection_unref(bonding->conn);

	if (bonding->io)
		g_io_channel_unref(bonding->io);

	device = bonding->device;
	g_free(bonding);

	if (!device)
		return;

	device->bonding = NULL;

	adapter_resume_discovery(device->adapter);

	if (!device->agent)
		return;

	agent_cancel(device->agent);
	agent_free(device->agent);
	device->agent = NULL;
}

//+++ BRCM_LOCAL : Do Not Show Toast message At Just Works
#ifdef BT_USE_PAIREDPLUS
static char* PAIREDPLUS_TRUE  = "true";
static char* PAIREDPLUS_FALSE = "false";
#endif
//--- BRCM_LOCAL

void device_set_paired(struct btd_device *device, gboolean value)
{
	DBusConnection *conn = get_dbus_connection();

//+++ BRCM
	// emit property even if it is same as previous state as app needs to come back
	// the  status
	/* Google original
	if (device->paired == value)
		return;
	*/
//--- BRCM

	device->paired = value;

//+++ BRCM_LOCAL : Do Not Show Toast message At Just Works
#ifdef BT_USE_PAIREDPLUS
    {
        char **values;

        values = g_new0(char *, 3);
        values[0] = device->paired    ? PAIREDPLUS_TRUE : PAIREDPLUS_FALSE;
        values[1] = device->temporary ? PAIREDPLUS_TRUE : PAIREDPLUS_FALSE;

        emit_array_property_changed(conn, device->path, DEVICE_INTERFACE,
                    "PairedPlus", DBUS_TYPE_STRING, &values, 2);

        g_free(values);
    }
#else
	emit_property_changed(conn, device->path, DEVICE_INTERFACE, "Paired",
				DBUS_TYPE_BOOLEAN, &value);
#endif
//--- BRCM_LOCAL
}

static void device_agent_removed(struct agent *agent, void *user_data)
{
	struct btd_device *device = user_data;

	device->agent = NULL;

	if (device->authr)
		device->authr->agent = NULL;
}

static struct bonding_req *bonding_request_new(DBusConnection *conn,
						DBusMessage *msg,
						struct btd_device *device,
						const char *agent_path,
						uint8_t capability)
{
	struct bonding_req *bonding;
	const char *name = dbus_message_get_sender(msg);
	struct agent *agent;
	char addr[18];

	ba2str(&device->bdaddr, addr);
	DBG("Requesting bonding for %s", addr);

	if (!agent_path)
		goto proceed;

	agent = agent_create(device->adapter, name, agent_path,
					capability,
					device_agent_removed,
					device);
	if (!agent) {
		error("Unable to create a new agent");
		return NULL;
	}

	device->agent = agent;

	DBG("Temporary agent registered for %s at %s:%s",
			addr, name, agent_path);

proceed:
	bonding = g_new0(struct bonding_req, 1);

	bonding->conn = dbus_connection_ref(conn);
	bonding->msg = dbus_message_ref(msg);

	adapter_suspend_discovery(device->adapter);

	return bonding;
}

//+++ BRCM
#ifdef BT_ALT_STACK
void device_check_bonding_failed( struct btd_device *device, uint8_t status)
{
	DBG("device_check_bonding_failed");
	if( device->bonding )
	{
		error_failed (device->bonding->conn,device->bonding->msg,bt_error(status));
		device_bonding_complete(device,status);
	}
}
#endif
//--- BRCM

static void create_bond_req_exit(DBusConnection *conn, void *user_data)
{
	struct btd_device *device = user_data;
	char addr[18];

	ba2str(&device->bdaddr, addr);
	DBG("%s: requestor exited before bonding was completed", addr);

	if (device->authr)
		device_cancel_authentication(device, FALSE);

	if (device->bonding) {
		device->bonding->listener_id = 0;
		device_request_disconnect(device, NULL);
	}
}

DBusMessage *device_create_bonding(struct btd_device *device,
					DBusConnection *conn,
					DBusMessage *msg,
					const char *agent_path,
					uint8_t capability)
{
	char filename[PATH_MAX + 1];
	char *str, srcaddr[18], dstaddr[18];
	struct btd_adapter *adapter = device->adapter;
	struct bonding_req *bonding;
	bdaddr_t src;
	int err;
//+++ BRCM
	uint8_t device_type;
	uint32_t addr_type;

#ifdef BT_ALT_STACK
	tDTUN_DEVICE_METHOD method;
#endif
//--- BRCM

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	if (device->bonding)
		return btd_error_in_progress(msg);

	/* check if a link key already exists */
	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr,
			"linkkeys");

	str = textfile_caseget(filename, dstaddr);
	if (str) {
		free(str);
		return btd_error_already_exists(msg);
	}

//+++ BRCM
#ifdef BT_ALT_STACK
//+++ BRCM
	char addr_and_type[24];

	if (read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_PENC,	NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_PID,	NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_PCSRK, NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_LENC,	NULL, NULL) == 0 ||
		read_ble_link_key(&src, &device->bdaddr, DTUN_LE_KEY_LCSRK, NULL, NULL) == 0) {
		DBG("There's BLE Link Key. Delete it and Bonding again.");
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_PENC);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_PID);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_PCSRK);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_LENC);
		textfile_casedel(filename, addr_and_type);
		sprintf(addr_and_type, "%s-%02x", dstaddr, DTUN_LE_KEY_LCSRK);
		textfile_casedel(filename, addr_and_type);

		device->paired = FALSE;
		device_set_bonded(device, FALSE);
	}

//--- BRCM

	debug("device_create_bonding  src=%s dest=%s", srcaddr, dstaddr);
	dtun_read_dev_info(&src, &device->bdaddr, &device_type, &addr_type);
	debug("dev_type=0x%x addr_type=0x%x", device_type, addr_type);
	if(device_type == DEVICE_TYPE_LE)
		dtun_add_ble_dev_info(&device->bdaddr , device_type, addr_type);
	memcpy(&method.bond.bdaddr, &device->bdaddr.b, 6);
	method.bond.hdr.id = DTUN_METHOD_DM_CREATE_BONDING;
	method.bond.hdr.len = sizeof(tDTUN_BOND) - sizeof(tDTUN_HDR);
	method.bond.cod = read_device_cod(&src, &device->bdaddr);

	dtun_client_call_method(&method);

	bonding = bonding_request_new(conn, msg, device, agent_path,
					capability);

	if (!bonding)
		return NULL;
#else
	err = adapter_create_bonding(adapter, &device->bdaddr, capability);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	bonding = bonding_request_new(conn, msg, device, agent_path,
					capability);
	if (!bonding) {
		adapter_cancel_bonding(adapter, &device->bdaddr);
		return NULL;
	}

	bonding->listener_id = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						create_bond_req_exit, device,
						NULL);
#endif
//--- BRCM

	device->bonding = bonding;
	bonding->device = device;

	return NULL;
}

void device_simple_pairing_complete(struct btd_device *device, uint8_t status)
{
	struct authentication_req *auth = device->authr;

	if (auth && auth->type == AUTH_TYPE_NOTIFY && auth->agent)
		agent_cancel(auth->agent);
}

static void device_auth_req_free(struct btd_device *device)
{
	g_free(device->authr);
	device->authr = NULL;
}

void device_bonding_complete(struct btd_device *device, uint8_t status)
{
	struct bonding_req *bonding = device->bonding;
	struct authentication_req *auth = device->authr;
	bdaddr_t bdaddr;

	DBG("bonding %p status 0x%02x", bonding, status);

	if (auth && auth->type == AUTH_TYPE_NOTIFY && auth->agent)
		agent_cancel(auth->agent);

	// Temporary hack till we move to mgmt interface.
	if (status == 0x06 && auth == NULL) {
		device_remove_bonding(device);
		device_get_address(device, &bdaddr);
		btd_adapter_retry_authentication(device->adapter, &bdaddr);
//+++ BRCM
		// for this "Temporary hack" , until retry is  implemented   cancel bonding and
		//send notification to app about pairing state
		device_cancel_bonding(device, status);
		device_set_paired(device, FALSE);
//+++ BRCM_LOCAL : CSP#538367 due to holding device information,re-fetching SDP records could get failed
// This fix cause same problem on JB(GK S240) - remove the fix. CSP#603844
        {
	        DBG("%p: ref=%d clear", device, device->ref);

//            btd_device_unref(device);
        }
		DBG("device_bonding_complete : bonding failed, clearing device information");
//--- BRCM_LOCAL 
//--- BRCM
		return;
	} else if (status) {
		device_cancel_authentication(device, TRUE);
		device_cancel_bonding(device, status);
//+++ BRCM
		device_set_paired(device, FALSE);
		DBG("device_bonding_complete : bonding failed");
//--- BRCM
		return;
	}

	device_auth_req_free(device);

	/* If we're already paired nothing more is needed */
	if (device->paired)
		return;

	device_set_paired(device, TRUE);

	/* If we were initiators start service discovery immediately.
	 * However if the other end was the initator wait a few seconds
	 * before SDP. This is due to potential IOP issues if the other
	 * end starts doing SDP at the same time as us */
	if (bonding) {
		DBG("Proceeding with service discovery");
		/* If we are initiators remove any discovery timer and just
		 * start discovering services directly */
		if (device->discov_timer) {
			g_source_remove(device->discov_timer);
			device->discov_timer = 0;
		}

		device_browse_sdp(device, bonding->conn, bonding->msg,
				NULL, FALSE);

//+++ BRCM
#ifdef BT_ALT_STACK
		DBusMessage *reply = new_authentication_return(device->bonding->msg, 0);
		g_dbus_send_message(device->bonding->conn, reply);
#endif
//--- BRCM

		bonding_request_free(bonding);
	} else {
		if (!device->browse && !device->discov_timer &&
				main_opts.reverse_sdp) {
			/* If we are not initiators and there is no currently
			 * active discovery or discovery timer, set discovery
			 * timer */
			DBG("setting timer for reverse service discovery");
			device->discov_timer = g_timeout_add_seconds(
							DISCOVERY_TIMER,
							start_discovery,
							device);
		}
	}
}

gboolean device_is_creating(struct btd_device *device, const char *sender)
{
	DBusMessage *msg;

	if (device->bonding && device->bonding->msg)
		msg = device->bonding->msg;
	else if (device->browse && device->browse->msg)
		msg = device->browse->msg;
	else
		return FALSE;

	if (!dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
						"CreatePairedDevice") &&
			!dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
							"CreateDevice"))
		return FALSE;

	if (sender == NULL)
		return TRUE;

	return g_str_equal(sender, dbus_message_get_sender(msg));
}

gboolean device_is_bonding(struct btd_device *device, const char *sender)
{
	struct bonding_req *bonding = device->bonding;

	if (!device->bonding)
		return FALSE;

	if (!sender)
		return TRUE;

	return g_str_equal(sender, dbus_message_get_sender(bonding->msg));
}

void device_cancel_bonding(struct btd_device *device, uint8_t status)
{
	struct bonding_req *bonding = device->bonding;
	DBusMessage *reply;
	char addr[18];

	if (!bonding)
		return;

	ba2str(&device->bdaddr, addr);
	DBG("Canceling bonding request for %s", addr);

	if (device->authr)
		device_cancel_authentication(device, FALSE);

	reply = new_authentication_return(bonding->msg, status);
	g_dbus_send_message(bonding->conn, reply);

	bonding_request_cancel(bonding);
	bonding_request_free(bonding);
}

static void pincode_cb(struct agent *agent, DBusError *err,
					const char *pincode, void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (auth->cb == NULL)
		return;

	((agent_pincode_cb) auth->cb)(agent, err, pincode, device);

	device->authr->cb = NULL;
	device->authr->agent = NULL;
}

static void confirm_cb(struct agent *agent, DBusError *err, void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (auth->cb == NULL)
		return;

	((agent_cb) auth->cb)(agent, err, device);

	device->authr->cb = NULL;
	device->authr->agent = NULL;
}

static void passkey_cb(struct agent *agent, DBusError *err,
						uint32_t passkey, void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (auth->cb == NULL)
		return;

	((agent_passkey_cb) auth->cb)(agent, err, passkey, device);

	device->authr->cb = NULL;
	device->authr->agent = NULL;
}

static void pairing_consent_cb(struct agent *agent, DBusError *err, void *data)
{
	struct authentication_req *auth = data;
	struct btd_device *device = auth->device;

	/* No need to reply anything if the authentication already failed */
	if (!auth->cb)
		return;

	((agent_cb) auth->cb)(agent, err, device);

	auth->cb = NULL;
}

int device_request_authentication(struct btd_device *device, auth_type_t type,
						uint32_t passkey, void *cb)
{
	struct authentication_req *auth;
	struct agent *agent;
	char addr[18];
	int err;

	ba2str(&device->bdaddr, addr);
	DBG("Requesting agent authentication for %s", addr);

	if (device->authr) {
		error("Authentication already requested for %s", addr);
		return -EALREADY;
	}

	agent = device_get_agent(device);
	if (!agent) {
		error("No agent available for request type %d", type);
		return -EPERM;
	}

	auth = g_new0(struct authentication_req, 1);
	auth->agent = agent;
	auth->device = device;
	auth->cb = cb;
	auth->type = type;
//+++ BRCM
	if(device->type == DEVICE_TYPE_LE){
		info("device type is le only");
		auth->is_le_only = 1;
	}
//--- BRCM
	device->authr = auth;

	switch (type) {
	case AUTH_TYPE_PINCODE:
		err = agent_request_pincode(agent, device, pincode_cb,
								auth, NULL);
		break;
	case AUTH_TYPE_PASSKEY:
		err = agent_request_passkey(agent, device, passkey_cb,
								auth, NULL);
		break;
	case AUTH_TYPE_CONFIRM:
		err = agent_request_confirmation(agent, device, passkey,
						confirm_cb, auth, NULL);
		break;
	case AUTH_TYPE_NOTIFY:
		err = agent_display_passkey(agent, device, passkey);
		break;
	case AUTH_TYPE_AUTO:
		err = 0;
		break;
	case AUTH_TYPE_PAIRING_CONSENT:
		err = agent_request_pairing_consent(agent, device,
							pairing_consent_cb, auth, NULL);
		break;
	default:
		err = -EINVAL;
	}

	if (err < 0) {
		error("Failed requesting authentication");
		device_auth_req_free(device);
	}

	return err;
}

static void cancel_authentication(struct authentication_req *auth)
{
	struct btd_device *device;
	struct agent *agent;
	DBusError err;

	if (!auth || !auth->cb)
		return;

	device = auth->device;
	agent = auth->agent;

	dbus_error_init(&err);
	dbus_set_error_const(&err, "org.bluez.Error.Canceled", NULL);

	switch (auth->type) {
	case AUTH_TYPE_PINCODE:
		((agent_pincode_cb) auth->cb)(agent, &err, NULL, device);
		break;
	case AUTH_TYPE_CONFIRM:
		((agent_cb) auth->cb)(agent, &err, device);
		break;
	case AUTH_TYPE_PASSKEY:
		((agent_passkey_cb) auth->cb)(agent, &err, 0, device);
		break;
	case AUTH_TYPE_PAIRING_CONSENT:
		((agent_cb) auth->cb) (agent, &err, device);
		break;
	case AUTH_TYPE_NOTIFY:
		/* User Notify doesn't require any reply */
		break;
	}

	dbus_error_free(&err);
	auth->cb = NULL;
}

void device_cancel_authentication(struct btd_device *device, gboolean aborted)
{
	struct authentication_req *auth = device->authr;
	char addr[18];

	if (!auth)
		return;

	ba2str(&device->bdaddr, addr);
	DBG("Canceling authentication request for %s", addr);

	if (auth->agent)
		agent_cancel(auth->agent);

	if (!aborted)
		cancel_authentication(auth);

	device_auth_req_free(device);
}

gboolean device_is_authenticating(struct btd_device *device)
{
	return (device->authr != NULL);
}

gboolean device_is_authorizing(struct btd_device *device)
{
	return device->authorizing;
}

void device_set_authorizing(struct btd_device *device, gboolean auth)
{
	device->authorizing = auth;
}

void device_register_services(DBusConnection *conn, struct btd_device *device,
						GSList *prim_list, int psm)
{
	device->services = attrib_client_register(conn, device, psm, NULL,
								prim_list);
	device->primaries = g_slist_concat(device->primaries, prim_list);
}

GSList *btd_device_get_primaries(struct btd_device *device)
{
	return device->primaries;
}

//+++ BRCM
#ifdef BT_ALT_STACK
void btd_device_append_uuid(struct btd_device *device, const char *uuid)
{
	GSList *uuid_list;
	char *new_uuid;

	info("uuid %s", uuid);
	if (g_slist_find_custom(device->uuids, uuid,
				(GCompareFunc) strcasecmp))
		return;

	new_uuid = g_strdup(uuid);
	uuid_list = g_slist_append(NULL, new_uuid);

	device_probe_drivers(device, uuid_list);
#ifndef BT_ALT_STACK_2_2
	g_free(new_uuid);
	g_slist_free(uuid_list);
#endif //BT_ALT_STACK_2_2
}

void btd_device_commit_uuids(struct btd_device *device)
{
	store_profiles(device);
	services_changed(device);
}

#endif //BT_ALT_STACK
//--- BRCM

void btd_device_add_uuid(struct btd_device *device, const char *uuid)
{
	GSList *uuid_list;
	char *new_uuid;

	if (g_slist_find_custom(device->uuids, uuid,
				(GCompareFunc) strcasecmp))
		return;

	new_uuid = g_strdup(uuid);
	uuid_list = g_slist_append(NULL, new_uuid);

	device_probe_drivers(device, uuid_list);

	g_free(new_uuid);
	g_slist_free(uuid_list);

	store_profiles(device);
	services_changed(device);
}

const sdp_record_t *btd_device_get_record(struct btd_device *device,
							const char *uuid)
{
//+++ BRCM
#ifdef BT_ALT_STACK
	bdaddr_t src;
	sdp_record_t* rec = NULL;
	if (device->tmp_records)
		rec = find_record_in_list(device->tmp_records, uuid);

	if (rec == NULL) {
		if (device->tmp_records) {
			sdp_list_free(device->tmp_records,
				(sdp_free_func_t) sdp_record_free);
			device->tmp_records = NULL;
			error("btd_device_get_record: can not find record for uuid:%s, calling read_records to refresh the records", uuid);
		}
		adapter_get_address(device->adapter, &src);
		device->tmp_records = read_records(&src, &device->bdaddr);
		if (device->tmp_records)
			rec = find_record_in_list(device->tmp_records, uuid);
	}
	return rec;
#else
	bdaddr_t src;

	if (device->tmp_records) {
		const sdp_record_t *record;

		record = find_record_in_list(device->tmp_records, uuid);
		if (record != NULL)
			return record;
	}

	adapter_get_address(device->adapter, &src);

	device->tmp_records = read_records(&src, &device->bdaddr);
	if (!device->tmp_records)
		return NULL;

	return find_record_in_list(device->tmp_records, uuid);
#endif //BT_ALT_STACK
//--- BRCM
}

int btd_register_device_driver(struct btd_device_driver *driver)
{
	device_drivers = g_slist_append(device_drivers, driver);

	return 0;
}

void btd_unregister_device_driver(struct btd_device_driver *driver)
{
	device_drivers = g_slist_remove(device_drivers, driver);
}

struct btd_device *btd_device_ref(struct btd_device *device)
{
	device->ref++;

	DBG("%p: ref=%d", device, device->ref);

	return device;
}

void btd_device_unref(struct btd_device *device)
{
	DBusConnection *conn = get_dbus_connection();
	gchar *path;

	device->ref--;

	DBG("%p: ref=%d", device, device->ref);

	if (device->ref > 0)
		return;

	path = g_strdup(device->path);

	g_dbus_unregister_interface(conn, path, DEVICE_INTERFACE);

	g_free(path);
}

void device_set_class(struct btd_device *device, uint32_t value)
{
	DBusConnection *conn = get_dbus_connection();

	emit_property_changed(conn, device->path, DEVICE_INTERFACE, "Class",
				DBUS_TYPE_UINT32, &value);
}

//+++ BRCM
#ifdef BT_ALT_STACK
gboolean device_is_weak_linkkey(struct btd_device *device)
{
	struct btd_adapter *adapter = device->adapter;
	char filename[PATH_MAX + 1], *str;
	char tmp[3];
	char srcaddr[18], dstaddr[18];
	gboolean ret = FALSE;
	bdaddr_t src;
	uint8_t key_type = 0, pin_code_len = 0;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);
	ba2str(&device->bdaddr, dstaddr);

	create_name(filename, PATH_MAX, STORAGEDIR,
			srcaddr, "linkkeys");
	str = textfile_caseget(filename, dstaddr);
	if (str) {
		//debug("device_is_week_linkkey: %s", str);

		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, str + 33, 2);
		key_type = (uint8_t) strtol(tmp, NULL, 10);

		memcpy(tmp, str + 35, 2);
		pin_code_len = (uint8_t) strtol(tmp, NULL, 10);

		/* authenticated combination (5) or pin code len is 16 -> link key is strong*/
		if (!((key_type == 5) || (pin_code_len == 16)))
			ret = TRUE;

	}

	info("device_is_weak_linkkey returning: %d", ret);

	g_free(str);

	return ret;
}

uint8_t device_authr_is_le_only(struct btd_device *device)
{
    if (device->authr)
    { 
        info("device_authr_is_le_only   device->type  %d", device->type );
        info("device_authr_is_le_only    device->authr->is_le_only= %d", device->authr->is_le_only);
        return device->authr->is_le_only;
    }
    info("device_authr_is_le_only  return 0 authr==NULL  ");
    return 0;
}

void device_set_device_type(struct btd_device *device, device_type_t dev_type)
{
     info(" device_set_device_type dev_type= %d device=0x%x",  dev_type, device);
    if(device)
         device->type = dev_type;
}
void device_input_conn_status(struct btd_device *device, uint32_t status)
{
	DBusConnection *conn = get_dbus_connection();
	emit_property_changed(conn, device->path, "org.bluez.Input",
			"Connected", DBUS_TYPE_UINT32, &status);
}
#endif
//--- BRCM

