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

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "textfile.h"

#include "hcid.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "error.h"
#include "glib-helper.h"
#include "dbus-common.h"
#include "agent.h"
#include "storage.h"
#include "event.h"
#include "sdpd.h"
#include "eir.h"
//+++ BRCM
#ifdef BT_ALT_STACK
#include "dtun_clnt.h"

//+++ BRCM
extern void device_set_device_type(struct btd_device *device, device_type_t dev_type);
//--- BRCM
extern void dtun_pin_reply(tDTUN_ID id, pin_code_reply_cp *pr, uint8_t is_le_only);
extern void dtun_ssp_confirm_reply(bdaddr_t *dba, boolean accepted, boolean is_le_only);
#endif

#ifdef BT_ALT_STACK
gboolean get_adapter_and_device(bdaddr_t *src, bdaddr_t *dst,
					struct btd_adapter **adapter,
					struct btd_device **device,
					gboolean create)
#else
static gboolean get_adapter_and_device(bdaddr_t *src, bdaddr_t *dst,
					struct btd_adapter **adapter,
					struct btd_device **device,
					gboolean create)
#endif
//--- BRCM
{
	DBusConnection *conn = get_dbus_connection();
	char peer_addr[18];

	*adapter = manager_find_adapter(src);
	if (!*adapter) {
		error("Unable to find matching adapter");
		return FALSE;
	}

	ba2str(dst, peer_addr);

	if (create)
		*device = adapter_get_device(conn, *adapter, peer_addr);
	else
		*device = adapter_find_device(*adapter, peer_addr);

	if (create && !*device) {
	    error("Unable to get device object!");
	    return FALSE;
	}

	return TRUE;
}

/*****************************************************************
 *
 *  Section reserved to HCI commands confirmation handling and low
 *  level events(eg: device attached/dettached.
 *
 *****************************************************************/

static size_t decode_hex(const char *pin, char *out)
{
	size_t i;

	for (i = 0; i < 16 && pin[i * 2] && pin[i * 2 + 1]; i++)
		sscanf(&pin[i * 2], "%02hhX", &out[i]);

	return i;
}

static size_t decode_pin(const char *pin, char *out)
{
	size_t len;

	if (!pin)
		return 0;

	if (pin[0] == '$') {
		len = decode_hex(&pin[1], out);
	} else {
		len = strnlen(pin, 16);
		memcpy(out, pin, len);
	}

	return len;
}

static void pincode_cb(struct agent *agent, DBusError *derr,
				const char *pincode, struct btd_device *device)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	bdaddr_t dba;
	int err;
	size_t len;
	char rawpin[16];
//+++ BRCM
#ifdef BT_ALT_STACK
	pin_code_reply_cp pr;
#endif
//--- BRCM
	device_get_address(device, &dba);

	len = decode_pin(pincode, rawpin);
//+++ BRCM
#ifdef BT_ALT_STACK
	if (derr || !len) {
		memset(&pr, 0, sizeof(pr));
		bacpy(&pr.bdaddr, &dba);
		dtun_pin_reply(DTUN_METHOD_DM_PIN_NEG_REPLY, &pr, device_authr_is_le_only(device));
		return;
	}
#else
	if (derr || !len) {
		err = btd_adapter_pincode_reply(adapter, &dba, NULL, 0);
		if (err < 0)
			goto fail;
		return;
	}
#endif
//--- BRCM
//+++ BRCM
#ifdef BT_ALT_STACK
	if (pincode == NULL)
		return;

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &dba);
	memcpy(&pr.pin_code, pincode, len);
	pr.pin_len = len;

	dtun_pin_reply(DTUN_METHOD_DM_PIN_REPLY, &pr, device_authr_is_le_only(device));
	return;
#else
	err = btd_adapter_pincode_reply(adapter, &dba, rawpin, len);
	if (err < 0)
		goto fail;

	return;
#endif
//--- BRCM
fail:
	error("Sending PIN code reply failed: %s (%d)", strerror(-err), -err);
}

int btd_event_request_pin(bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	char pin[17];
	int pinlen;
//+++ BRCM
    device_type_t device_type = read_device_type(sba, dba);
//--- BRCM

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

//+++ BRCM
    device_set_device_type( device,   device_type);
//--- BRCM
	memset(pin, 0, sizeof(pin));
	pinlen = read_pin_code(sba, dba, pin);
	if (pinlen > 0) {
		btd_adapter_pincode_reply(adapter, dba, pin, pinlen);
		return 0;
	}

	return device_request_authentication(device, AUTH_TYPE_PINCODE, 0,
								pincode_cb);
}

static int confirm_reply(struct btd_adapter *adapter,
                         struct btd_device *device, gboolean success)
{
	bdaddr_t bdaddr;

	device_get_address(device, &bdaddr);
//+++ BRCM
#ifdef BT_ALT_STACK
	dtun_ssp_confirm_reply(&bdaddr, success, device_authr_is_le_only(device));
	return 0;
#else
	return btd_adapter_confirm_reply(adapter, &bdaddr, success);
#endif
//--- BRCM
}

static void confirm_cb(struct agent *agent, DBusError *err, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device_get_adapter(device);
	gboolean success = (err == NULL) ? TRUE : FALSE;

	confirm_reply(adapter, device, success);
}

static void passkey_cb(struct agent *agent, DBusError *err, uint32_t passkey,
			void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_adapter *adapter = device_get_adapter(device);
	bdaddr_t bdaddr;

	device_get_address(device, &bdaddr);
//+++ BRCM
#ifdef BT_ALT_STACK
	error("passkey_cb unimplemented");
#else
	if (err)
		passkey = INVALID_PASSKEY;

	btd_adapter_passkey_reply(adapter, &bdaddr, passkey);
#endif
//--- BRCM
}

int btd_event_user_confirm(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_CONFIRM,
							passkey, confirm_cb);
}

int btd_event_user_consent(bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_PAIRING_CONSENT,
						0, confirm_cb);
}

int btd_event_user_passkey(bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_PASSKEY, 0,
								passkey_cb);
}

int btd_event_user_notify(bdaddr_t *sba, bdaddr_t *dba, uint32_t passkey)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(sba, dba, &adapter, &device, TRUE))
		return -ENODEV;

	return device_request_authentication(device, AUTH_TYPE_NOTIFY,
								passkey, NULL);
}

void btd_event_bonding_complete(bdaddr_t *local, bdaddr_t *peer,
							uint8_t status)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	gboolean create;

	DBG("status 0x%02x", status);

	create = status ? FALSE : TRUE;

	if (!get_adapter_and_device(local, peer, &adapter, &device, create))
		return;

	if (device)
		device_bonding_complete(device, status);
}

void btd_event_simple_pairing_complete(bdaddr_t *local, bdaddr_t *peer,
								uint8_t status)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	gboolean create;

	DBG("status=%02x", status);

	create = status ? FALSE : TRUE;

	if (!get_adapter_and_device(local, peer, &adapter, &device, create))
		return;

	if (!device)
		return;

	device_simple_pairing_complete(device, status);
}

static void update_lastseen(bdaddr_t *sba, bdaddr_t *dba)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = gmtime(&t);

	write_lastseen_info(sba, dba, tm);
}

static void update_lastused(bdaddr_t *sba, bdaddr_t *dba)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = gmtime(&t);

	write_lastused_info(sba, dba, tm);
}

void btd_event_device_found(bdaddr_t *local, bdaddr_t *peer, uint32_t class,
//+++ BRCM
#ifdef BT_ALT_STACK
				int8_t rssi, uint8_t dev_type, uint8_t addr_type, uint8_t *data)
#else
				int8_t rssi, uint8_t *data)
#endif
//--- BRCM
{
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	update_lastseen(local, peer);
	write_remote_class(local, peer, class);
//+++ BRCM
#ifdef BT_ALT_STACK
        /* store device_type only after pairing. else the device is being treated as paired */
        // write_device_type(local, peer, dev_type);
	write_address_type(local, peer, addr_type);
#endif
//--- BRCM

	if (data)
		write_remote_eir(local, peer, data);
//+++ BRCM
#ifdef BT_ALT_STACK
	adapter_update_found_devices(adapter, peer, class, rssi, dev_type, data);
#else
	adapter_update_found_devices(adapter, peer, class, rssi, data);
#endif
//--- BRCM
}

void btd_event_set_legacy_pairing(bdaddr_t *local, bdaddr_t *peer,
							gboolean legacy)
{
	struct btd_adapter *adapter;
	struct remote_dev_info *dev, match;

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, peer);
	match.name_status = NAME_ANY;

	dev = adapter_search_found_devices(adapter, &match);
	if (dev)
		dev->legacy = legacy;
}

void btd_event_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	uint32_t old_class = 0;

	read_remote_class(local, peer, &old_class);

	if (old_class == class)
		return;

	write_remote_class(local, peer, class);

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	device_set_class(device, class);
}

void btd_event_remote_name(bdaddr_t *local, bdaddr_t *peer, uint8_t status,
				char *name)
{
	struct btd_adapter *adapter;
	char srcaddr[18], dstaddr[18];
	struct btd_device *device;
	struct remote_dev_info match, *dev_info;

	if (status == 0) {
		if (!g_utf8_validate(name, -1, NULL)) {
			int i;

			/* Assume ASCII, and replace all non-ASCII with
			 * spaces */
			for (i = 0; name[i] != '\0'; i++) {
				if (!isascii(name[i]))
					name[i] = ' ';
			}
			/* Remove leading and trailing whitespace characters */
			g_strstrip(name);
		}

		write_device_name(local, peer, name);
	}

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	ba2str(local, srcaddr);
	ba2str(peer, dstaddr);

	if (status != 0)
		goto proceed;

	bacpy(&match.bdaddr, peer);
	match.name_status = NAME_ANY;

	dev_info = adapter_search_found_devices(adapter, &match);
	if (dev_info) {
		g_free(dev_info->name);
		dev_info->name = g_strdup(name);
		adapter_emit_device_found(adapter, dev_info);
	}

	if (device)
		device_set_name(device, name);

proceed:
	/* remove from remote name request list */
	adapter_remove_found_device(adapter, peer);
//+++ BRCM
#ifndef BT_ALT_STACK
	/* check if there is more devices to request names */
	if (adapter_resolve_names(adapter) == 0)
		return;

	adapter_set_state(adapter, STATE_IDLE);
#endif
//--- BRCM
}

int btd_event_link_key_notify(bdaddr_t *local, bdaddr_t *peer,
				uint8_t *key, uint8_t key_type,
				uint8_t pin_length)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	int ret;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return -ENODEV;

	DBG("storing link key of type 0x%02x", key_type);

	ret = write_link_key(local, peer, key, key_type, pin_length);

	if (ret == 0) {
		device_set_bonded(device, TRUE);

		if (device_is_temporary(device))
			device_set_temporary(device, FALSE);
	}

	return ret;
}

void btd_event_conn_complete(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return;

	update_lastused(local, peer);

	adapter_add_connection(adapter, device);
}

void btd_event_conn_failed(bdaddr_t *local, bdaddr_t *peer, uint8_t status)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	DBusConnection *conn = get_dbus_connection();

	DBG("status 0x%02x", status);

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	if (device_is_temporary(device))
		adapter_remove_device(conn, adapter, device, TRUE);
}

void btd_event_disconn_complete(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	DBG("");

	if (!get_adapter_and_device(local, peer, &adapter, &device, FALSE))
		return;

	if (!device)
		return;

	adapter_remove_connection(adapter, device);
}

//+++ BRCM
void btd_event_wbs_config(bdaddr_t *local, uint8_t wbs)
{
    struct btd_adapter *adapter = manager_find_adapter(local);
    DBG("");
    if (! adapter) {
        error("Unable to find matching adapter");
        return;
    }
    adapter_emit_wbs_config(adapter, wbs);
}
//--- BRCM

/* Section reserved to device HCI callbacks */

void btd_event_returned_link_key(bdaddr_t *local, bdaddr_t *peer)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return;

	device_set_paired(device, TRUE);
}
