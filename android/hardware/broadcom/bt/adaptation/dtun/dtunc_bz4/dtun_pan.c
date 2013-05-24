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
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <linux/sockios.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/bnep.h>
#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "dbus-common.h"
#include "adapter.h"
#include "device.h"

#define LOG_TAG "dtun_pan"

#include "error.h"
//#include "common.h"
#include "dtun.h"
#include "dtun_clnt.h"
#include "dtun_pan.h"

#include "utils/Log.h"
#define info(fmt, ...)  ALOGI ("%s: " fmt,__FUNCTION__,  ## __VA_ARGS__)
#define debug(fmt, ...) ALOGD ("%s: " fmt,__FUNCTION__,  ## __VA_ARGS__)
#define error(fmt, ...) ALOGE ("##### ERROR : %s: " fmt "#####",__FUNCTION__,  ## __VA_ARGS__)
#undef DBG
#define DBG debug
#define NETWORK_SERVER_INTERFACE "org.bluez.NetworkServer"
#define BRCM_PAN_TAP_DEV_NAME "brcm-pan"
static struct btd_adapter* g_adapter;
static DBusConnection *g_dbus_conn;
static void dtun_pan_cmd(int cmd, bdaddr_t* src, bdaddr_t* dest, int local_role, int dest_role);
static void server_signal_dev_disconnected(bdaddr_t * peer_addr);
static int server_signal_dev_connected(bdaddr_t * peer_addr, uint16_t dst_role);
static int server_init(const char* path);
static int server_exit(const char* path);
static DBusMessage *register_server(DBusConnection *conn, DBusMessage *msg, void *data);
static DBusMessage *unregister_server(DBusConnection *conn, DBusMessage *msg, void *data);
static DBusMessage *set_service_sdp(DBusConnection *conn, DBusMessage *msg, void *data);
static DBusMessage *disconnect_device(DBusConnection *conn, DBusMessage *msg, void *data);

static void pan_unregister_device_driver(struct btd_adapter *adapter);
//#define PAN_ROLE_CLIENT         0x01     /* PANU role */
//#define PAN_ROLE_GN_SERVER      0x02     /* GN role */
//#define PAN_ROLE_NAP_SERVER     0x04     /* NAP role */
//#define BNEP_SVC_PANU  0x1115
//#define BNEP_SVC_NAP   0x1116
//#define BNEP_SVC_GN    0x1117

static inline int bz_role2bta(int role)
{
    switch(role)
    {
        case BNEP_SVC_PANU:
            return PAN_ROLE_CLIENT;
        case BNEP_SVC_GN:
            return PAN_ROLE_GN_SERVER;
        case BNEP_SVC_NAP:
            return PAN_ROLE_NAP_SERVER;
        default:
            error("invalid bluez pan role:%d", role);
            break;
    }
    return -1;
}
static inline int bta_role2bz(int role)
{
    switch(role)
    {
        case PAN_ROLE_CLIENT:
            return BNEP_SVC_PANU;
        case PAN_ROLE_GN_SERVER:
            return BNEP_SVC_GN;
        case PAN_ROLE_NAP_SERVER:
            return BNEP_SVC_NAP;
        default:
            error("invalid bta pan role:%d", role);
            break;
    }
    return -1;

}
	
static inline int android_role2bta(int role)
{
    switch(role)
    {
        case 1:	// BluetoothPan.LOCAL_NAP_ROLE
            return PAN_ROLE_NAP_SERVER;
		case 2: // BluetoothPan.LOCAL_PANU_ROLE
			return PAN_ROLE_CLIENT;
        default:
            error("invalid android pan role:%d", role);
            break;
    }
    return -1;
}


int pan_dbus_init (struct btd_adapter *adapter)
{
    g_adapter = adapter;

   const char* path = adapter_get_path(adapter);
   ALOGI("%s: path = %s", __FUNCTION__, path);
   server_init(path);
   return 0;
}
void pan_dbus_exit (void)
{   
	ALOGI("%s", __FUNCTION__);
    const char* path = adapter_get_path(g_adapter);
    server_exit(path);
    pan_unregister_device_driver(g_adapter);
    
    dbus_connection_unref( g_dbus_conn );
    g_dbus_conn = NULL;
    g_adapter = NULL;
    ALOGI("pan_dbus_exit complete");
}

static GDBusMethodTable server_methods[] = {
	{ "Register",	"ss",	"",	register_server		},
	{ "Unregister",	"s",	"",	unregister_server	},
	{ "SetSDP", "q",	"", set_service_sdp	},
	{ "DisconnectDevice", "ss",  "", disconnect_device },
	{ }
};

static GDBusSignalTable server_signals[] = {
	{ "DeviceConnected",	"ssq"    },
	{ "DeviceDisconnected",	"s"      },
	{ }
};


static int server_init(const char* path)
{
	ALOGI("server_init");
	if (!g_dbus_register_interface(g_dbus_conn, path, NETWORK_SERVER_INTERFACE,
					server_methods, server_signals, NULL, NULL, NULL)) 
    {
		error("D-Bus failed to register %s interface", NETWORK_SERVER_INTERFACE);
		return -1;
	}
	debug("PAN NAP Registered interface %s on path %s", NETWORK_SERVER_INTERFACE, path);
    //dtun_pan_cmd(PAN_CMD_REGISTER, NULL, NULL, PAN_ROLE_PAN_NAP, PAN_ROLE_CLIENT);  
	return 0;
}

static int server_exit(const char* path)
{
	ALOGI("server_exit");
	g_dbus_unregister_interface(g_dbus_conn, path, NETWORK_SERVER_INTERFACE);
    //dtun_pan_cmd(PAN_CMD_UNREGISTER, NULL, NULL, 0, 0);
    
	return 0;
}

static DBusMessage *register_server(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
    ALOGI("register_server");
	DBusMessage *reply;
	const char *uuid, *bridge;

    if (!dbus_message_get_args(msg, NULL, 
                DBUS_TYPE_STRING, &uuid,
                DBUS_TYPE_STRING, &bridge, 
                DBUS_TYPE_INVALID))
		return NULL;

    ALOGI("uuid %s, bridge %s", uuid, bridge);

	if (g_strcmp0(uuid, "nap"))
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "Invalid UUID");

    debug("nap bridge:%s", bridge);
    dtun_pan_cmd(PAN_CMD_REGISTER, NULL, NULL, PAN_ROLE_NAP_SERVER, PAN_ROLE_CLIENT); 
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	return reply;
}

static DBusMessage *unregister_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *uuid;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &uuid,
							DBUS_TYPE_INVALID))
		return NULL;

	if (g_strcmp0(uuid, "nap"))
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "Invalid UUID");

    dtun_pan_cmd(PAN_CMD_UNREGISTER, NULL, NULL, 0, 0);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;
	return reply;
}
	
static DBusMessage *disconnect_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct network_server *ns = data;
	struct network_session *session;
	const char *addr, *devname;
	bdaddr_t dst_addr;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &addr,
						DBUS_TYPE_STRING, &devname,
						DBUS_TYPE_INVALID))
		return NULL;

	str2ba(addr, &dst_addr);
	//session = find_session_by_addr(ns->sessions, dst_addr);

	dtun_pan_cmd(PAN_CMD_DISCONNECT, NULL, &dst_addr, 0, 0);

#if 0
	if (!session)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "No active session");

	if (session->io) {
                bnep_if_down(devname);
                bnep_kill_connection(&dst_addr);
	} else
		return not_connected(msg);
#endif

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;
	return reply;
}

static DBusMessage *set_service_sdp(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	uint16_t local_role;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT16, &local_role,
							DBUS_TYPE_INVALID))
		return NULL;

    debug("set_service_sdp: role=%d", local_role);

	local_role=android_role2bta(local_role);

    dtun_pan_cmd(PAN_CMD_SETSDP, NULL, NULL, local_role, 0);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;
	return reply;
}

static void server_signal_dev_disconnected(bdaddr_t * peer_addr)
{
	char address[18];
	const char *paddr = address;

	char devname[16];

	if (!g_dbus_conn) return;

	memset(devname, 0, sizeof(devname));
	strcpy(devname, BRCM_PAN_TAP_DEV_NAME);

	ba2str(peer_addr, address);
	g_dbus_emit_signal(g_dbus_conn, adapter_get_path(g_adapter),
				NETWORK_SERVER_INTERFACE, "DeviceDisconnected",
				DBUS_TYPE_STRING, &paddr,
				DBUS_TYPE_INVALID);
}


static int server_signal_dev_connected(bdaddr_t * peer_addr, uint16_t dst_role)
{
	char devname[16];
	char address[18];
	const char *paddr = address;
	const char *pdevname = devname;
	int nsk;

	ALOGI("%s", __FUNCTION__);

	memset(devname, 0, sizeof(devname));
	strcpy(devname, BRCM_PAN_TAP_DEV_NAME);

	info("Added new connection: %s", devname);

	ba2str(peer_addr, address);
	gboolean result = g_dbus_emit_signal(g_dbus_conn, adapter_get_path(g_adapter),
				NETWORK_SERVER_INTERFACE, "DeviceConnected",
				DBUS_TYPE_STRING, &paddr,
				DBUS_TYPE_STRING, &pdevname,
				DBUS_TYPE_UINT16, &dst_role,
				DBUS_TYPE_INVALID);

	return 0;
}

/////////////////////////////////////////
//connection-panu 
#include <bluetooth/bnep.h>
#define NETWORK_PEER_INTERFACE "org.bluez.Network"
#define PANU_UUID	"00001115-0000-1000-8000-00805f9b34fb"
#define NAP_UUID	"00001116-0000-1000-8000-00805f9b34fb"
#define GN_UUID		"00001117-0000-1000-8000-00805f9b34fb"
//#define BNEP_SVC_UUID	"0000000f-0000-1000-8000-00805f9b34fb"

typedef enum {
	CONNECTED,
	CONNECTING,
	DISCONNECTED
} conn_state;

struct network_peer {
	bdaddr_t	src;
	bdaddr_t	dst;
	char		*path;		/* D-Bus path */
	struct btd_device *device;
	GSList		*connections;
};

struct network_conn {
	DBusMessage	*msg;
	char		dev[16];	/* Interface name */
	uint16_t	id;		/* Role: Service Class Identifier */
	uint16_t	role;		/* Role: Service Class Identifier of device (phone) */
	conn_state	state;
	guint		watch;		/* Disconnect watch */
	guint		dc_id;
	struct network_peer *peer;
};

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));
static struct {
	const char	*name;		/* Friendly name */
	const char	*uuid128;	/* UUID 128 */
	uint16_t	id;		/* Service class identifier */
} __svc[] = {
	{ "panu",	PANU_UUID,	BNEP_SVC_PANU	},
	{ "gn",		GN_UUID,	BNEP_SVC_GN	},
	{ "nap",	NAP_UUID,	BNEP_SVC_NAP	},
	{ NULL }
};
static GSList *peers = NULL;

static int16_t bnep_service_id(const char *svc)
{
	int i;
	uint16_t id;

	/* Friendly service name */
	for (i = 0; __svc[i].name; i++)
		if (!strcasecmp(svc, __svc[i].name)) {
			return __svc[i].id;
		}

	/* UUID 128 string */
	for (i = 0; __svc[i].uuid128; i++)
		if (!strcasecmp(svc, __svc[i].uuid128)) {
			return __svc[i].id;
		}

	/* Try convert to HEX */
	id = strtol(svc, NULL, 16);
	if ((id < BNEP_SVC_PANU) || (id > BNEP_SVC_GN))
		return 0;

	return id;
}

static const char *bnep_uuid(uint16_t id)
{
	int i;

	for (i = 0; __svc[i].uuid128; i++)
		if (__svc[i].id == id)
			return __svc[i].uuid128;
	return NULL;
}

static const char *bnep_name(uint16_t id)
{
	int i;

	for (i = 0; __svc[i].name; i++)
		if (__svc[i].id == id)
			return __svc[i].name;
	return NULL;
}


static struct network_peer *find_peer(GSList *list, const char *path)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_peer *peer = l->data;

		if (!strcmp(peer->path, path))
			return peer;
	}

	return NULL;
}

static struct network_conn *find_connection(GSList *list, uint16_t id)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_conn *nc = l->data;

		if (nc->id == id)
			return nc;
	}

	return NULL;
}


static inline DBusMessage *not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							"Not supported");
}

static inline DBusMessage *already_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Device already connected");
}

static inline DBusMessage *not_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Device not connected");
}

static inline DBusMessage *not_permited(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Operation not permited");
}

static void cancel_connection(struct network_conn *nc, const char *err_msg)
{
	DBusMessage *reply;

	if (nc->msg && err_msg) {
		reply = g_dbus_create_error(nc->msg, ERROR_INTERFACE ".ConnectionAttemptFailed", "Connection attempt failed");
		g_dbus_send_message(g_dbus_conn, reply);
	}
	nc->state = DISCONNECTED;
}
static void connection_destroy(DBusConnection *conn, void *user_data)
{
	struct network_conn *nc = user_data;

	if (nc->state == CONNECTED) {
        dtun_pan_cmd(PAN_CMD_DISCONNECT, &nc->peer->src, &nc->peer->dst, PAN_ROLE_CLIENT, bz_role2bta(nc->role));
	} else cancel_connection(nc, NULL);
}
static DBusMessage *connection_connect(DBusConnection *conn,
				DBusMessage *msg, void *data, char *src_svc, char *dst_svc)
{
	struct network_peer *peer = data;
	struct network_conn *nc;
	uint16_t src_id;
	uint16_t dst_id;
	GError *err = NULL;

    info("src %s, dst %s", src_svc, dst_svc);

	src_id = bnep_service_id(src_svc);
	dst_id = bnep_service_id(dst_svc);

	nc = find_connection(peer->connections, dst_id);
	if (!nc)
    { 
        info("not supported %d %d", src_id, dst_id);
		return not_supported(msg);
    }
	if (nc->state != DISCONNECTED)
    {
        info("already connected");
		return already_connected(msg);
    }
	nc->role = src_id;
    
    dtun_pan_cmd(PAN_CMD_CONNECT, &peer->src, &peer->dst, bz_role2bta(src_id), bz_role2bta(dst_id));

	nc->state = CONNECTING;
	nc->msg = dbus_message_ref(msg);
	nc->watch = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						connection_destroy,
						nc, NULL);

	return NULL;
}

static DBusMessage *connection_connect_panu(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char *src_svc;
	char *dst_svc;
    
    info("get params");
    
	src_svc = g_strdup("panu");
	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &dst_svc,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

    info("trying to connect to %s", dst_svc);
    
	connection_connect(conn, msg, data, src_svc, dst_svc);
	return NULL;
}

static DBusMessage *connection_connect_generic(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char *src_svc;
	char *dst_svc;

    info("trying to connect pan");
    
	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &src_svc,
						DBUS_TYPE_STRING, &dst_svc,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;
    
	connection_connect(conn, msg, data, src_svc, dst_svc);
	return NULL;
}

static DBusMessage *connection_cancel(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	const char *owner = dbus_message_get_sender(nc->msg);
	const char *caller = dbus_message_get_sender(msg);

	if (!g_str_equal(owner, caller))
		return not_permited(msg);

	connection_destroy(conn, nc);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *connection_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	GSList *l;

	for (l = peer->connections; l; l = l->next) {
		struct network_conn *nc = l->data;

		if (nc->state == DISCONNECTED)
			continue;

		return connection_cancel(conn, msg, nc);
	}

	return not_connected(msg);
}

static DBusMessage *connection_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc = NULL;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	dbus_bool_t connected;
	const char *property;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	for (l = peer->connections; l; l = l->next) {
		struct network_conn *tmp = l->data;

		if (tmp->state != CONNECTED)
			continue;

		nc = tmp;
		break;
	}

	connected = nc ? TRUE : FALSE;
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &connected);

	/* Interface */
	property = nc ? nc->dev : "";
	dict_append_entry(&dict, "Interface", DBUS_TYPE_STRING, &property);

	/* UUID */
	property = nc ? bnep_uuid(nc->id) : "";
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &property);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void connection_free(struct network_conn *nc)
{
	if (nc->dc_id)
		device_remove_disconnect_watch(nc->peer->device, nc->dc_id);

	connection_destroy(g_dbus_conn, nc);

	g_free(nc);
	nc = NULL;
}

static void peer_free(struct network_peer *peer)
{
	g_slist_foreach(peer->connections, (GFunc) connection_free, NULL);
	g_slist_free(peer->connections);
	btd_device_unref(peer->device);
	g_free(peer->path);
	g_free(peer);
}

static void connection_path_unregister(void *data)
{
	struct network_peer *peer = data;

	DBG("Unregistered interface %s on path %s",
		NETWORK_PEER_INTERFACE, peer->path);

	peers = g_slist_remove(peers, peer);
	peer_free(peer);
}


static GDBusMethodTable connection_methods[] = {
	{ "Connect",  "s", "s", connection_connect_panu,
              G_DBUS_METHOD_FLAG_ASYNC },
	{ "Connect", "ss",	"s", connection_connect_generic,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	connection_disconnect	},
	{ "GetProperties",	"",	"a{sv}",connection_get_properties },
	{ }
};

static GDBusSignalTable connection_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

void connection_unregister(const char *path, uint16_t id)
{
	struct network_peer *peer;
	struct network_conn *nc;

	peer = find_peer(peers, path);
	if (!peer)
		return;

	nc = find_connection(peer->connections, id);
	if (!nc)
		return;

	peer->connections = g_slist_remove(peer->connections, nc);
	connection_free(nc);
	if (peer->connections)
		return;

    // workaround for bt shutdown race condition where remove callback (nap_remove()) 
    // comes after dbus pan exit function is executed and has freed the bus connection.
    if (g_dbus_conn)
	    g_dbus_unregister_interface(g_dbus_conn, path, NETWORK_PEER_INTERFACE);
}

static struct network_peer *create_peer(struct btd_device *device,
					const char *path, bdaddr_t *src,
					bdaddr_t *dst)
{
	struct network_peer *peer;

	peer = g_new0(struct network_peer, 1);
	peer->device = btd_device_ref(device);
	peer->path = g_strdup(path);
	bacpy(&peer->src, src);
	bacpy(&peer->dst, dst);

	if (g_dbus_register_interface(g_dbus_conn, path,
					NETWORK_PEER_INTERFACE,
					connection_methods,
					connection_signals, NULL,
					peer, connection_path_unregister) == FALSE) {
		error("D-Bus failed to register %s interface",
			NETWORK_PEER_INTERFACE);
		peer_free(peer);
		return NULL;
	}

	debug("Registered interface %s on path %s",
		NETWORK_PEER_INTERFACE, path);

	return peer;
}

int connection_register(struct btd_device *device, const char *path,
			bdaddr_t *src, bdaddr_t *dst, uint16_t id)
{
	struct network_peer *peer;
	struct network_conn *nc;

	if (!path) {
		ALOGE("Error! Path is invalid arg");
		return -EINVAL;
	}

	peer = find_peer(peers, path);
	if (!peer) {
		peer = create_peer(device, path, src, dst);
		if (!peer) {
			ALOGE("Error creating peer for path %s", path);
			return -1;
		}
		peers = g_slist_append(peers, peer);
	}

	nc = find_connection(peer->connections, id);
	if (nc) {
		ALOGE("No connection found for id %d", id);
		return 0;
	}

	nc = g_new0(struct network_conn, 1);
	nc->id = id;
	memset(nc->dev, 0, sizeof(nc->dev));
	//strcpy(nc->dev, "bnep%d");
	strcpy(nc->dev, BRCM_PAN_TAP_DEV_NAME);
	nc->state = DISCONNECTED;
	nc->peer = peer;

	peer->connections = g_slist_append(peer->connections, nc);

	return 0;

}
static int network_probe(struct btd_device *device, GSList *uuids, uint16_t id)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	bdaddr_t src, dst;

	debug("path %s", path);

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst);

	return connection_register(device, path, &src, &dst, id);
}

static void network_remove(struct btd_device *device, uint16_t id)
{
	const gchar *path = device_get_path(device);

    DBG("path %s, id %d", path, id);
	connection_unregister(path, id);
}

static int panu_probe(struct btd_device *device, GSList *uuids)
{
    ALOGI("panu_probe");
	return network_probe(device, uuids, BNEP_SVC_PANU);
}

//+++ BRCM_LOCAL : CSP#538367 due to holding device information,re-fetching SDP records could get failed
//org static void panu_remove(struct btd_device *device)
void panu_remove(struct btd_device *device)
//--- BRCM_LOCAL
{
    ALOGI("panu_remove");
	network_remove(device, BNEP_SVC_PANU);
}

static int gn_probe(struct btd_device *device, GSList *uuids)
{
	return network_probe(device, uuids, BNEP_SVC_GN);
}

static void gn_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_GN);
}

static int nap_probe(struct btd_device *device, GSList *uuids)
{
	return network_probe(device, uuids, BNEP_SVC_NAP);
}

static void nap_remove(struct btd_device *device)
{
    ALOGI("%s", __FUNCTION__);
	network_remove(device, BNEP_SVC_NAP);
}

static struct btd_device_driver network_panu_driver = 
{
	.name	= "network-panu",
	.uuids	= BTD_UUIDS(PANU_UUID),
	.probe	= panu_probe,
	.remove	= panu_remove,
};

static struct btd_device_driver network_gn_driver = 
{
	.name	= "network-gn",
	.uuids	= BTD_UUIDS(GN_UUID),
	.probe	= gn_probe,
	.remove	= gn_remove,
};

static struct btd_device_driver network_nap_driver = 
{
	.name	= "network-nap",
	.uuids	= BTD_UUIDS(NAP_UUID),
	.probe	= nap_probe,
	.remove	= nap_remove,
};

int pan_register_device_driver(DBusConnection *conn)
{
    g_dbus_conn = dbus_connection_ref( conn );
    btd_register_device_driver(&network_panu_driver);
    btd_register_device_driver(&network_gn_driver);
    btd_register_device_driver(&network_nap_driver);
    return 0;
}


static void pan_unregister_device_driver(struct btd_adapter *adapter)
{
  	btd_unregister_device_driver(&network_panu_driver);
	btd_unregister_device_driver(&network_gn_driver);
	btd_unregister_device_driver(&network_nap_driver);
}

static void disconnect_cb(struct btd_device *device, gboolean removal,
				void *user_data)
{
	struct network_conn *nc = user_data;

	info("Network: disconnect %s", nc->peer->path);

	connection_destroy(NULL, user_data);
}

static void panu_connection_signal_dev_connected(bdaddr_t * peer_addr, int16_t dst_role)
{
	const char *pdev, *uuid;
	gboolean connected;
  	char addr[18];
	ba2str(peer_addr, addr);
    struct btd_device *device = adapter_find_device(g_adapter, addr);
    const char* path = device_get_path(device);
  	struct network_peer *peer;
	struct network_conn *nc;

	ALOGD("%s path:%s", __FUNCTION__, path);
	peer = find_peer(peers, path);
	if (!peer) {
		ALOGE("%s - No peer found for the path. Hence returning with sending", __FUNCTION__);
		return;
	}

	nc = find_connection(peer->connections, dst_role);
	if (!nc) {
		ALOGE("%s No network_connection found. Hence exitting", __FUNCTION__);
		return;
	}

	pdev = nc->dev;
	uuid = bnep_uuid(nc->id);

    if (nc->msg)
    {
        ALOGI("%s g_dbus_send_reply for pending request", __FUNCTION__);
    	g_dbus_send_reply(g_dbus_conn, nc->msg,
    			DBUS_TYPE_STRING, &pdev,
    			DBUS_TYPE_INVALID);
    }
    else
    {
        ALOGI("%s No pending request", __FUNCTION__);
    }

	connected = TRUE;
	emit_property_changed(g_dbus_conn, nc->peer->path,
				NETWORK_PEER_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &connected);
                
	emit_property_changed(g_dbus_conn, nc->peer->path,
				NETWORK_PEER_INTERFACE, "Interface",
				DBUS_TYPE_STRING, &pdev);
	emit_property_changed(g_dbus_conn, nc->peer->path,
				NETWORK_PEER_INTERFACE, "UUID",
				DBUS_TYPE_STRING, &uuid);

	nc->state = CONNECTED;

//+++ BRCM_LOCAL CASE#569769 SEGV on device_add_disconnect_watch()
// nc->peer->device is need for update to new created device
    nc->peer->device = device;
//--- BRCM_LOCAL

	nc->dc_id = device_add_disconnect_watch(nc->peer->device, disconnect_cb,
						nc, NULL);
        
}
static void panu_connection_signal_dev_disconnected(bdaddr_t * peer_addr, int16_t dst_role)
{
	char addr[18];
	ba2str(peer_addr, addr);
    struct btd_device *device = adapter_find_device(g_adapter, addr);
    const char* path = device_get_path(device);
  	struct network_peer *peer;
	struct network_conn *nc;

	peer = find_peer(peers, path);
	if (!peer)
		return;

	nc = find_connection(peer->connections, dst_role);
	if (!nc)
		return;


  	if (g_dbus_conn != NULL) {
		gboolean connected = FALSE;
		const char *property = "";
		emit_property_changed(g_dbus_conn, path,
					NETWORK_PEER_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &connected);
		emit_property_changed(g_dbus_conn, path,
					NETWORK_PEER_INTERFACE, "Interface",
					DBUS_TYPE_STRING, &property);
		emit_property_changed(g_dbus_conn, path,
					NETWORK_PEER_INTERFACE, "UUID",
					DBUS_TYPE_STRING, &property);
		device_remove_disconnect_watch(device, nc->dc_id);
		nc->dc_id = 0;
		if (nc->watch) {
			g_dbus_remove_watch(g_dbus_conn, nc->watch);
			nc->watch = 0;
		}
	}

	info("%s disconnected", nc->dev);

	nc->state = DISCONNECTED;

}
////////////////////////////////////////////////////
//dtun cmd & signal
void dtun_sig_pan_state_changed(tDTUN_DEVICE_SIGNAL *p_data)
{
    int state = p_data->pan.info.state;

    debug("pan state:%d; local_role:%d; peer_role:%d", state, p_data->pan.info.local_role, p_data->pan.info.peer_role);

    switch(state)
    {
        case PAN_STATE_CONNECTED:
            if(p_data->pan.info.local_role == PAN_ROLE_CLIENT) //PANU
                panu_connection_signal_dev_connected(&p_data->pan.info.peer_addr, bta_role2bz(p_data->pan.info.peer_role));
            else //PAN-NAP
                server_signal_dev_connected(&p_data->pan.info.peer_addr, bta_role2bz(p_data->pan.info.peer_role)); 
            break;
        case PAN_STATE_DISCONNECTED:
            if(p_data->pan.info.local_role == PAN_ROLE_CLIENT)
                panu_connection_signal_dev_disconnected(&p_data->pan.info.peer_addr, bta_role2bz(p_data->pan.info.peer_role));
            else 
                server_signal_dev_disconnected(&p_data->pan.info.peer_addr);
            break;
        default:
            error("unknown dtun pan state:%d", state);
            break;
    }        

}
static void dtun_pan_cmd(int cmd, bdaddr_t* src, bdaddr_t* dest, int local_role, int peer_role)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d, local_role:%d, peer_role:%d", cmd, local_role, peer_role );
    memset(&method.pan, 0, sizeof method.pan);
    method.pan.hdr.id = DTUN_METHOD_PAN_CMD;
    method.pan.hdr.len = sizeof method.pan.info;
    method.pan.info.cmd = cmd;
    method.pan.info.local_role = local_role;
    method.pan.info.peer_role = peer_role;
    if(dest)
        memcpy(&method.pan.info.peer_addr, dest, sizeof(bdaddr_t));
    if(src)    
        memcpy(&method.pan.info.local_addr, src, sizeof(bdaddr_t));
	dtun_client_call_method(&method);
}
