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


/*
**
** This file mainly registers and deregisters DBus interfaces used for Health Device Profiles
** It handles all the DBus Method calls related to HDP, and routes them to BTAPP
**  
*/
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "log.h"
#include "error.h"
#include <stdlib.h>
#include <stdint.h>
#include <btio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>



#include <bluetooth/bluetooth.h>
#include <glib.h>
#include <gdbus.h>

#include "dbus-common.h"
#include "adapter.h"
#include "device.h"


#include "error.h"
//#include "common.h"
#include "dtun.h"
#include "dtun_clnt.h"
#include "dtun_hl.h"


#define LOG_TAG "dtun_hl"
#include "utils/Log.h"
#define info(fmt, ...)  ALOGI ("%s: " fmt,__FUNCTION__,  ## __VA_ARGS__)
#define debug(fmt, ...) ALOGD ("%s: " fmt,__FUNCTION__,  ## __VA_ARGS__)
#define error(fmt, ...) ALOGE ("##### ERROR : %s: " fmt "#####",__FUNCTION__,  ## __VA_ARGS__)
#undef DBG
#define DBG debug
#define MANAGER_PATH		"/org/bluez"

#define HEALTH_MANAGER		"org.bluez.HealthManager"
#define HEALTH_DEVICE		"org.bluez.HealthDevice"
#define HEALTH_CHANNEL		"org.bluez.HealthChannel"

#define HL_VERSION		0x0100

#define HL_SERVICE_NAME	"Bluez HL"
#define HL_SERVICE_DSC		"A Bluez health device profile implementation"
#define HL_SERVICE_PROVIDER	"Bluez"

#define HL_MDEP_ECHO		0x00
#define HL_MDEP_INITIAL	0x01
#define HL_MDEP_FINAL		0x7F

#define HL_DC_INITIAL	0x01
#define HL_DC_FINAL	0x03

#define HL_ERROR		g_quark_from_static_string("hl-error-quark")

#define HL_NO_PREFERENCE_DC	0x00
#define HL_RELIABLE_DC		0x01
#define HL_STREAMING_DC	0x02

#define HL_SINK_ROLE_AS_STRING		"sink"
#define HL_SOURCE_ROLE_AS_STRING	"source"


#define HL_STATUS_OK	    0x00
#define HL_STATUS_ERROR 	0x01
#define HL_STREAMING_DC	0x02

#ifndef DBUS_TYPE_UNIX_FD
    #define DBUS_TYPE_UNIX_FD -1
//##define DBUS_TYPE_UNIX_FD      ((int) 'h')

#endif


typedef enum
{
    HL_SOURCE = 0x00,
    HL_SINK = 0x01
} HdpRole;

typedef enum
{
    HL_DIC_PARSE_ERROR,
    HL_DIC_ENTRY_PARSE_ERROR,
    HL_CONNECTION_ERROR,
    HL_UNSPECIFIED_ERROR,
    HL_UNKNOWN_ERROR
} HdpError;

enum data_specs
{
    DATA_EXCHANGE_SPEC_11073 = 0x01
};

struct hl_application
{
    DBusConnection      *conn;      /* For dbus watcher */
    DBusMessage         *msg;
    char                *path;      /* The path of the application */
    uint16_t            data_type;  /* Data type handled for this application */
    gboolean            data_type_set;  /* Flag for dictionary parsing */
    uint8_t             role;       /* Role of this application */
    gboolean            role_set;   /* Flag for dictionary parsing */
    uint8_t             chan_type;  /* QoS preferred by source applications */
    gboolean            chan_type_set;  /* Flag for dictionary parsing */
    char                *description;   /* Options description for SDP record */
    uint8_t             id;     /* The identification is also the mdepid */
    char                *oname;     /* Name of the owner application */
    int                 dbus_watcher;   /* Watch for clients disconnection */
    gint                ref;        /* Reference counter */

};

struct hl_device
{
    DBusConnection      *conn;      /* For name listener handling */
    struct btd_device   *dev;       /* Device reference */
    struct hl_adapter   *hl_adapter;    /* hl_adapater */
    struct mcap_mcl     *mcl;       /* The mcap control channel */
    gboolean            mcl_conn;   /* Mcl status */
    gboolean            sdp_present;    /* Has an sdp record */
    GSList              *channels;  /* Data Channel list */
    struct hl_channel   *ndc;       /* Data channel being negotiated */
    struct hl_channel   *fr;        /* First reliable data channel */
    gint            ref;        /* Reference counting */
};

struct hl_create_dc
{
    DBusConnection          *conn;
    DBusMessage             *msg;
    char                    *path;
    struct hl_application   *app;
    struct hl_device        *dev;
    uint8_t                 config;
    uint8_t                 bd_addr[8];
    uint8_t                 id;
    gint                    ref;        /* Reference counting */
};

struct hl_del_dc
{
    DBusConnection      *conn;
    DBusMessage         *msg;
    struct hl_channel   *hl_chann;
    char                *path;
    gint                ref;
};

struct hl_acq_dc
{
    DBusConnection      *conn;
    DBusMessage         *msg;
    struct hl_channel   *hl_chann;
    uint16_t            id;
    char                *path;
    gint                ref;
};

struct hl_sock
{
    struct hl_channel   *hl_chann;
    uint16_t            fd;
	char				*sock_path;
    gint                ref;
};


struct hl_channel
{
    struct hl_device    *dev;       /* Device where this channel belongs */
    struct hl_application   *app;       /* Application */
    struct mcap_mdl     *mdl;       /* The data channel reference */
    char            *path;      /* The path of the channel */
    uint8_t         config;     /* Channel configuration */
    uint8_t         mdep;       /* Remote MDEP */
    uint16_t        mdlid;      /* Data channel Id */
    struct hl_echo_data *edata;     /* private data used by echo channels */
    gint            ref;        /* Reference counter */
};

typedef gboolean (*parse_item_f)(DBusMessageIter *iter, gpointer user_data,
                                 GError **err);

struct dict_entry_func
{
    char        *key;
    parse_item_f    func;
};
  

static struct btd_adapter* adapter;
static DBusConnection *connection;
#define ECHO_TIMEOUT	1 /* second */
#define HL_ECHO_LEN	15

static DBusConnection *connection = NULL;

static GSList *applications = NULL;
static GSList *devices = NULL;
static GSList *create_dc = NULL;
static GSList *del_dc = NULL;
static GSList *acq_dc = NULL;
static GSList *sock_list = NULL;
static boolean local_release = false;

static uint8_t next_app_id = HL_MDEP_INITIAL;
static uint8_t next_dc_id = HL_DC_INITIAL;

static GSList *adapters;

static struct hl_device *create_health_device(DBusConnection *conn,
                                              struct btd_device *device);
int hl_manager_init(DBusConnection *conn);
void hl_manager_exit();
static DBusMessage *manager_create_application(DBusConnection *conn,
                                               DBusMessage *msg, void *user_data);
static DBusMessage *manager_destroy_application(DBusConnection *conn,
                                                DBusMessage *msg, void *user_data);
static DBusMessage *channel_get_properties(DBusConnection *conn,
                                           DBusMessage *msg, void *user_data);
static DBusMessage *channel_acquire(DBusConnection *conn,
                                    DBusMessage *msg, void *user_data);

static DBusMessage *channel_release(DBusConnection *conn,
                                    DBusMessage *msg, void *user_data);

static void client_disconnected(DBusConnection *conn, void *user_data);
static gboolean parse_dict_entry(struct dict_entry_func dict_context[],
                                 DBusMessageIter *iter,
                                 GError **err,
                                 gpointer user_data);
static gboolean parse_data_type(DBusMessageIter *iter, gpointer data,
                                GError **err);

static gboolean parse_dict(struct dict_entry_func dict_context[],
                           DBusMessageIter *iter,
                           GError **err,
                           gpointer user_data);

static gboolean parse_role(DBusMessageIter *iter, gpointer data, GError **err);

static gboolean parse_desc(DBusMessageIter *iter, gpointer data, GError **err);
static gboolean parse_chan_type(DBusMessageIter *iter, gpointer data,
                                GError **err);

static uint8_t get_app_id();
static uint8_t get_dc_id();
static int cmp_create_dc_id(gconstpointer a, gconstpointer b);
static int cmp_app_id(gconstpointer a, gconstpointer b);
static gint cmp_chan_mdlid(gconstpointer a, gconstpointer b);
static int cmp_app(gconstpointer a, gconstpointer b);
static int cmp_create_dc(gconstpointer a, gconstpointer b);
static int cmp_del_dc(gconstpointer a, gconstpointer b);
static int cmp_acq_dc(gconstpointer a, gconstpointer b);
static gboolean set_app_path(struct hl_application *app);
static gboolean set_dc_path(struct hl_create_dc *data);
static void hl_free_application(struct hl_application *app);
static int cmp_device(gconstpointer a, gconstpointer b);
static void free_health_device(struct hl_device *device);
static void free_hl_create_dc(struct hl_create_dc *dc_data);
static struct hl_create_dc *hl_create_data_ref(struct hl_create_dc *dc_data);
static void hl_create_data_unref(struct hl_create_dc *dc_data);
static void free_hl_del_dc(struct hl_del_dc *data);
static void hl_create_data_unref(struct hl_create_dc *dc_data);
static struct hl_del_dc *hl_del_dc_ref(struct hl_del_dc *data);
static void hl_del_dc_unref(struct hl_del_dc *data);
static void free_hl_acq_dc(struct hl_acq_dc *data);
static struct hl_acq_dc *hl_acq_dc_ref(struct hl_acq_dc *data);
static void hl_acq_dc_unref(struct hl_acq_dc * data);
static struct hl_sock *hl_sock_ref(struct hl_sock *data);
static void hl_sock_unref(struct hl_sock *data);

static void health_device_destroy(void *data);
static DBusMessage *device_create_channel(DBusConnection *conn,
                                          DBusMessage *msg, void *user_data);
static DBusMessage *device_destroy_channel(DBusConnection *conn,
                                           DBusMessage *msg, void *user_data);
static DBusMessage *device_get_properties(DBusConnection *conn,
                                          DBusMessage *msg, void *user_data);
static struct hl_channel *create_channel(struct hl_device *dev,
                                         uint8_t config,
                                         uint16_t mdlid,
                                         struct hl_application *app,
                                         GError **err);
static gint cmp_chan_path(gconstpointer a, gconstpointer b);
static struct hl_channel *hl_channel_ref(struct hl_channel *chan);
static void free_health_channel(struct hl_channel *chan);
static void hl_channel_unref(struct hl_channel *chan);
static void health_channel_destroy(void *data);
static struct hl_channel *create_channel(struct hl_device *dev,
                                         uint8_t config,
                                         uint16_t mdlid,
                                         struct hl_application *app,
                                         GError **err);
static void remove_channels(struct hl_device *dev);
static void disconnect_cb(struct btd_device *device, gboolean removal,
                          void *user_data);

static void dtun_hl_app_create_cmd(int cmd, char *path, int role, int chan_type, int data_type, char *description);
static void dtun_hl_app_destroy_cmd(int cmd, const char *path);
static void dtun_hl_channel_cmd(int cmd, bdaddr_t* src, bdaddr_t* dest, int local_role, int peer_role);
static void dtun_hl_channel_create_cmd(int cmd, char *app_path, uint8_t config, bdaddr_t* bdaddr, char *dc_path, boolean is_echo);

static void dtun_hl_channel_destroy_cmd(int cmd, char *app_path, uint16_t mdl_id, bdaddr_t* bdaddr);
static void dtun_hl_channel_acquire_cmd(int cmd, char *app_path, bdaddr_t* bdaddr, uint16_t mdl_id);
static void dtun_hl_channel_release_cmd(int cmd, char *app_path, bdaddr_t* bdaddr, uint16_t mdl_id);

 
static inline void set_socket_blocking(int s)
{
    int opts;
    opts = fcntl(s, F_GETFL);
    if (opts<0) error("set blocking (%s)", strerror(errno));
    opts &= ~O_NONBLOCK;
    fcntl(s, F_SETFL, opts);
}


static inline int connect_server_socket(const char* server_socket_name)
{
    int s = socket(AF_LOCAL, SOCK_STREAM, 0);
    set_socket_blocking(s);
    //char name[128];
    //name[0] = 0;
    //strncpy(name + 1, server_socket_name, sizeof name -1);
    if(socket_local_client_connect(s, server_socket_name, ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM) >= 0)
    {
        debug("connected to local socket:%s, fd:%d", server_socket_name, s);
        return s;
    }
    else error("connect to local socket:%s, fd:%d failed, errno:%d", server_socket_name, s, errno);
    close(s);
    return -1;        
}

static gint cmp_dev_addr(gconstpointer a, gconstpointer dst);


static int cmp_device(gconstpointer a, gconstpointer b)
{
    const struct hl_device *hl_device = a;
    const struct btd_device *device = b;

    if (hl_device->dev == device)
        return 0;

    return -1;
}


struct hl_application *hl_application_ref(struct hl_application *app)
{
    if (!app)
        return NULL;

    app->ref++;

    DBG("health_application_ref(%p): ref=%d", app, app->ref);
    return app;
}

void hl_application_unref(struct hl_application *app)
{
    if (!app)
        return;

    app->ref --;

    DBG("health_application_unref(%p): ref=%d", app, app->ref);
    if (app->ref > 0)
        return;

    hl_free_application(app);
}




static void manager_path_unregister(gpointer data)
{
    g_slist_foreach(applications, (GFunc) hl_application_unref, NULL);

    g_slist_free(applications);
    applications = NULL;

    // g_slist_foreach(adapters, (GFunc) update_adapter, NULL);
} 
static GDBusMethodTable health_manager_methods[] = {
    {"CreateApplication", "a{sv}", "o", manager_create_application, G_DBUS_METHOD_FLAG_ASYNC},
    {"DestroyApplication", "o", "", manager_destroy_application, G_DBUS_METHOD_FLAG_ASYNC},
    { NULL}
};




int hl_dbus_init (DBusConnection *_conn)
{
    ALOGI("hl_dbus_init");
    connection = dbus_connection_ref( _conn );
    ALOGI("hl_dbus_init 1");

    if (connection == NULL)
        return -EIO;
//Enable BTA_HL 
//After we get the signal - BTA_HL enabled

    ALOGI("hl_dbus_init 2");
    if (hl_manager_init(connection) < 0)
    {
        ALOGI("hl_dbus_init 3");
        dbus_connection_unref(connection);
        return -EIO;
    }
    ALOGI("hl_dbus_init 4");


    return 0;
}

//SIGNAL handler

void hl_dbus_exit (void)
{   
    ALOGI("%s", __FUNCTION__);
    hl_manager_exit();

    //dbus_connection_unref(connection);//??
    //connection = NULL;//???
    ALOGI("hl_dbus_exit complete");
}

void hl_manager_stop()
{
    g_dbus_unregister_interface(connection, MANAGER_PATH, HEALTH_MANAGER);

    dbus_connection_unref(connection);
    DBG("Stopped Health manager");
}

int hl_manager_start(DBusConnection *conn)
{
    DBG("Starting Health manager");

    if (!g_dbus_register_interface(conn, MANAGER_PATH,
                                   HEALTH_MANAGER,
                                   health_manager_methods, NULL, NULL,
                                   NULL, manager_path_unregister))
    {
        error("D-Bus failed to register %s interface", HEALTH_MANAGER);
        return -1;
    }

    connection = dbus_connection_ref(conn);

    return 0;
}


int hl_manager_init(DBusConnection *conn)
{
    if (hl_manager_start(conn))
        return -1;

    //connection = dbus_connection_ref(conn);
    //btd_register_device_driver(&hl_device_driver);

    return 0;
}

void hl_manager_exit(void)
{
    //btd_unregister_device_driver(&hl_device_driver);
    hl_manager_stop();
    //dbus_connection_unref(connection);
    connection = NULL;
}

static void client_disconnected(DBusConnection *conn, void *user_data)
{
    struct hl_application *app = user_data;

    DBG("Client disconnected from the bus, deleting hl application");
    applications = g_slist_remove(applications, app);

    app->dbus_watcher = 0; /* Watcher shouldn't be freed in this case */
    hl_application_unref(app);
}
static gboolean parse_dict_entry(struct dict_entry_func dict_context[],
                                 DBusMessageIter *iter,
                                 GError **err,
                                 gpointer user_data)
{
    DBusMessageIter entry;
    char *key;
    int ctype, i;
    struct dict_entry_func df;

    dbus_message_iter_recurse(iter, &entry);
    ctype = dbus_message_iter_get_arg_type(&entry);
    if (ctype != DBUS_TYPE_STRING)
    {
        g_set_error(err, HL_ERROR, HL_DIC_ENTRY_PARSE_ERROR,
                    "Dictionary entries should have a string as key");
        return FALSE;
    }

    dbus_message_iter_get_basic(&entry, &key);
    dbus_message_iter_next(&entry);
    /* Find function and call it */
    for (i = 0, df = dict_context[0]; df.key; i++, df = dict_context[i])
    {
        if (g_ascii_strcasecmp(df.key, key) == 0)
            return df.func(&entry, user_data, err);
    }

    g_set_error(err, HL_ERROR, HL_DIC_ENTRY_PARSE_ERROR,
                "No function found for parsing value for key %s", key);
    return FALSE;
}

static gboolean parse_dict(struct dict_entry_func dict_context[],
                           DBusMessageIter *iter,
                           GError **err,
                           gpointer user_data)
{
    int ctype;
    DBusMessageIter dict;

    ctype = dbus_message_iter_get_arg_type(iter);

    ALOGI("parse_dict ctype=%d", ctype);

    if (ctype != DBUS_TYPE_ARRAY)
    {
        g_set_error(err, HL_ERROR, HL_DIC_PARSE_ERROR,
                    "Dictionary should be an array");
        return FALSE;
    }

    dbus_message_iter_recurse(iter, &dict);
    while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
           DBUS_TYPE_INVALID)
    {
        if (ctype != DBUS_TYPE_DICT_ENTRY)
        {
            g_set_error(err, HL_ERROR, HL_DIC_PARSE_ERROR,
                        "Dictionary array should "
                        "contain dict entries");
            return FALSE;
        }

        /* Start parsing entry */
        if (!parse_dict_entry(dict_context, &dict, err,
                              user_data))
            return FALSE;
        /* Finish entry parsing */

        dbus_message_iter_next(&dict);
    }

    return TRUE;
}

static gboolean parse_data_type(DBusMessageIter *iter, gpointer data,
                                GError **err)
{
    struct hl_application *app = data;
    DBusMessageIter *value;
    int ctype;

    ctype = dbus_message_iter_get_arg_type(iter);
    value = iter;
    if (ctype == DBUS_TYPE_VARIANT)
    {
        DBusMessageIter variant;

        /* Get value inside the variable */
        dbus_message_iter_recurse(iter, &variant);
        ctype = dbus_message_iter_get_arg_type(&variant);
        value = &variant;
    }

    if (ctype != DBUS_TYPE_UINT16)
    {
        g_set_error(err, HL_ERROR, HL_DIC_ENTRY_PARSE_ERROR,
                    "Final value for data type should be uint16");
        return FALSE;
    }

    dbus_message_iter_get_basic(value, &app->data_type);
    app->data_type_set = TRUE;
    return TRUE;
}

static gboolean parse_role(DBusMessageIter *iter, gpointer data, GError **err)
{
    struct hl_application *app = data;
    DBusMessageIter *string;
    int ctype;
    const char *role;

    ctype = dbus_message_iter_get_arg_type(iter);
    if (ctype == DBUS_TYPE_VARIANT)
    {
        DBusMessageIter value;

        /* Get value inside the variable */
        dbus_message_iter_recurse(iter, &value);
        ctype = dbus_message_iter_get_arg_type(&value);
        string = &value;
    }
    else
    {
        string = iter;
    }

    if (ctype != DBUS_TYPE_STRING)
    {
        g_set_error(err, HL_ERROR, HL_UNSPECIFIED_ERROR,
                    "Value data spec should be variable or string");
        return FALSE;
    }

    dbus_message_iter_get_basic(string, &role);
    if (g_ascii_strcasecmp(role, HL_SINK_ROLE_AS_STRING) == 0)
    {
        app->role = HL_SINK;
    }
    else if (g_ascii_strcasecmp(role, HL_SOURCE_ROLE_AS_STRING) == 0)
    {
        app->role = HL_SOURCE;
    }
    else
    {
        g_set_error(err, HL_ERROR, HL_UNSPECIFIED_ERROR,
                    "Role value should be \"source\" or \"sink\"");
        return FALSE;
    }

    app->role_set = TRUE;

    return TRUE;
}

static gboolean parse_desc(DBusMessageIter *iter, gpointer data, GError **err)
{
    struct hl_application *app = data;
    DBusMessageIter *string;
    int ctype;
    const char *desc;

    ctype = dbus_message_iter_get_arg_type(iter);
    if (ctype == DBUS_TYPE_VARIANT)
    {
        DBusMessageIter variant;

        /* Get value inside the variable */
        dbus_message_iter_recurse(iter, &variant);
        ctype = dbus_message_iter_get_arg_type(&variant);
        string = &variant;
    }
    else
    {
        string = iter;
    }

    if (ctype != DBUS_TYPE_STRING)
    {
        g_set_error(err, HL_ERROR, HL_DIC_ENTRY_PARSE_ERROR,
                    "Value data spec should be variable or string");
        return FALSE;
    }

    dbus_message_iter_get_basic(string, &desc);
    app->description = g_strdup(desc);
    return TRUE;
}

static gboolean parse_chan_type(DBusMessageIter *iter, gpointer data,
                                GError **err)
{
    struct hl_application *app = data;
    DBusMessageIter *value;
    char *chan_type;
    int ctype;

    ctype = dbus_message_iter_get_arg_type(iter);
    value = iter;
    if (ctype == DBUS_TYPE_VARIANT)
    {
        DBusMessageIter variant;

        /* Get value inside the variable */
        dbus_message_iter_recurse(iter, &variant);
        ctype = dbus_message_iter_get_arg_type(&variant);
        value = &variant;
    }

    if (ctype != DBUS_TYPE_STRING)
    {
        g_set_error(err, HL_ERROR, HL_DIC_ENTRY_PARSE_ERROR,
                    "Final value for channel type should be an string");
        return FALSE;
    }

    dbus_message_iter_get_basic(value, &chan_type);

    if (g_ascii_strcasecmp("Reliable", chan_type) == 0)
        app->chan_type = HL_RELIABLE_DC;
    else if (g_ascii_strcasecmp("Streaming", chan_type) == 0)
        app->chan_type = HL_STREAMING_DC;
    else
    {
        g_set_error(err, HL_ERROR, HL_DIC_ENTRY_PARSE_ERROR,
                    "Invalid value for data type");
        return FALSE;
    }

    app->chan_type_set = TRUE;

    return TRUE;
}

static struct dict_entry_func dict_parser[] = {
    {"DataType",        parse_data_type},
    {"Role",        parse_role},
    {"Description",     parse_desc},
    {"ChannelType",     parse_chan_type},
    {NULL, NULL}
};


struct hl_application *hl_get_app_config(DBusMessageIter *iter, GError **err)
{
    struct hl_application *app;

    ALOGI("hl_get_app_config");


    app = g_new0(struct hl_application, 1);

    app->ref = 1;
    //if (app) hl_application_ref(app);

    if (!parse_dict(dict_parser, iter, err, app))
        goto fail;
    if (!app->data_type_set || !app->role_set)
    {
        error("hl_get_app_config error 1");
        g_set_error(err, HL_ERROR, HL_DIC_PARSE_ERROR,
                    "Mandatory fields aren't set");
        goto fail;
    }
    error("hl_get_app_config success");
    return app;

    fail:

    error("hl_get_app_config success");
    hl_application_unref(app);
    return NULL;
}

static DBusMessage *manager_create_application(DBusConnection *conn,
                                               DBusMessage *msg, void *user_data)
{
    struct hl_application *app;
    const char *name;
    DBusMessageIter iter;
    GError *err = NULL;


    debug( "Entered manager create app");

    dbus_message_iter_init(msg, &iter);

    app = hl_get_app_config(&iter, &err);
    if (err)
    {
        debug( "manager_create_application error 1");
        DBusMessage *reply;

        reply = g_dbus_create_error(msg,
                                    ERROR_INTERFACE ".InvalidArguments",
                                    "Invalid arguments: %s", err->message);
        g_error_free(err);
        return reply;
    }
/* todo remove  name = dbus_message_get_sender(msg);
    if (!name)
    {
        hl_application_unref(app);
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".HealthError",
                                   "Can't get sender name");
    }
*/
    if (!set_app_path(app))
    {
        hl_application_unref(app);
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".HealthError",
                                   "Can't get a valid id for the application");
    }

    //todo remove app->oname = g_strdup(name);
    app->conn = dbus_connection_ref(conn);
    app->msg = dbus_message_ref(msg);
    applications = g_slist_prepend(applications, app);

    dtun_hl_app_create_cmd(HL_CMD_APP_CREATE,app->path,app->role,app->chan_type,app->data_type,app->description);


    app->dbus_watcher = g_dbus_add_disconnect_watch(conn, name,
                                                    client_disconnected, app, NULL);
    debug( "leaving manager_create_application");
    return NULL;

}

static DBusMessage *manager_destroy_application(DBusConnection *conn,
                                                DBusMessage *msg, void *user_data)
{
    const char *path;
    struct hl_application *app;
    GSList *l;

    debug("entered manager_destroy_application");


    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
                               DBUS_TYPE_INVALID))
    {
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Invalid arguments in method call");
    }
    l = g_slist_find_custom(applications, path, cmp_app);

    if (!l)
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Invalid arguments in method call, "
                                   "no such application");

    app = l->data;
    dtun_hl_app_destroy_cmd(HL_CMD_APP_DESTROY, app->path);

    debug("leaving manager_destroy_application");
    return NULL;
}

static int cmp_app_id(gconstpointer a, gconstpointer b)
{
    const struct hl_application *app = a;
    const uint8_t *id = b;

    return app->id - *id;
}

static int cmp_app(gconstpointer a, gconstpointer b)
{
    const struct hl_application *app = a;

    return g_strcmp0(app->path, b);
}

static gint cmp_dev_addr(gconstpointer a, gconstpointer dst)
{
    const struct hl_device *device = a;
    bdaddr_t addr;

    device_get_address(device->dev, &addr);
    return bacmp(&addr, dst);
}

static uint8_t get_app_id()
{
    uint8_t id = next_app_id;

    do
    {
        GSList *l = g_slist_find_custom(applications, &id, cmp_app_id);

        if (!l)
        {
            next_app_id = (id % HL_MDEP_FINAL) + 1;
            return id;
        }
        else
            id = (id % HL_MDEP_FINAL) + 1;
    } while (id != next_app_id);

    /* No more ids available */
    return 0;
}

static int cmp_create_dc_id(gconstpointer a, gconstpointer b)
{
    const struct hl_create_dc *data = a;
    const uint8_t *id = b;

    return data->id - *id;
}

static uint8_t get_dc_id()
{
    uint8_t id = next_dc_id;

    do
    {
        GSList *l = g_slist_find_custom(create_dc, &id, cmp_create_dc_id);

        if (!l)
        {
            next_dc_id = (id % HL_DC_FINAL) + 1;
            return id;
        }
        else
            id = (id % HL_DC_FINAL) + 1;
    } while (id != next_dc_id);

    /* No more ids available */
    return 0;
}



static gint cmp_chan_mdlid(gconstpointer a, gconstpointer b)
{
    const struct hl_channel *chan = a;
    const uint16_t *mdlid = b;

    if (chan->mdlid == *mdlid)
        return 0;
    return -1;

}


static int cmp_create_dc(gconstpointer a, gconstpointer b)
{
    const struct hl_create_dc *data = a;
    return g_strcmp0(data->path, b);
}

static int cmp_del_dc(gconstpointer a, gconstpointer b)
{
    const struct hl_del_dc *data = a;
    const uint16_t *mdlid = b;
    DBG("hl_del_dc mdlid=%d---, mdlid=%d",data->hl_chann->mdlid,*((uint16_t *)b));
    if (data->hl_chann->mdlid == *mdlid)
        return 0;
    return -1;
}

static int cmp_del_dc_path(gconstpointer a, gconstpointer b)
{
    const struct hl_del_dc *data = a;
    DBG("cmp_del_dc_path: data->path=%s b=%s",data->path, b);

    return g_strcmp0(data->path, b);
}

static int cmp_acq_dc(gconstpointer a, gconstpointer b)
{
    const struct hl_acq_dc *data = a;

    DBG("cmp_acq_dc_path: data->path=%s b=%s",data->path, b);
    return g_strcmp0(data->path, b);
}
static int cmp_sock_path(gconstpointer a, gconstpointer b)
{
    const struct hl_sock *data = a;
	
	DBG("cmp_sock_path: data->path=%s b=%s",data->sock_path, b);
    return g_strcmp0(data->sock_path, b);
}


static gboolean set_app_path(struct hl_application *app)
{
    app->id = get_app_id();
    if (!app->id)
        return FALSE;
    app->path = g_strdup_printf(MANAGER_PATH "/health_app_%d", app->id);

    return TRUE;
};

static gboolean set_dc_path(struct hl_create_dc *data)
{
    data->id = get_dc_id();
    if (!data->id)
        return FALSE;
    data->path = g_strdup_printf("%s/create_dc_%d", device_get_path(data->dev->dev), data->id);

    return TRUE;
};

static void hl_free_application(struct hl_application *app)
{
    if (app->dbus_watcher)
        g_dbus_remove_watch(app->conn, app->dbus_watcher);

    if (app->conn)
        dbus_connection_unref(app->conn);
    g_free(app->oname);
    g_free(app->description);
    g_free(app->path);
    g_free(app);
}



/////////////////////////////////////////////////////////////////////////////////////
//Health Device
struct hl_device *health_device_ref(struct hl_device *hl_dev)
{
    hl_dev->ref++;

    DBG("health_device_ref(%p): ref=%d", hl_dev, hl_dev->ref);

    return hl_dev;
}

void health_device_unref(struct hl_device *hl_dev)
{
    hl_dev->ref--;

    DBG("health_device_unref(%p): ref=%d", hl_dev, hl_dev->ref);

    if (hl_dev->ref > 0)
        return;

    free_health_device(hl_dev);
}

static void free_hl_create_dc(struct hl_create_dc *dc_data)
{
    dbus_message_unref(dc_data->msg);
    dbus_connection_unref(dc_data->conn);
    hl_application_unref(dc_data->app);
    health_device_unref(dc_data->dev);

    g_free(dc_data);
}

static struct hl_create_dc *hl_create_data_ref(struct hl_create_dc *dc_data)
{
    dc_data->ref++;

    DBG("hl_create_data_ref(%p): ref=%d", dc_data, dc_data->ref);

    return dc_data;
}

static void hl_create_data_unref(struct hl_create_dc *dc_data)
{
    dc_data->ref--;

    DBG("hl_create_data_unref(%p): ref=%d", dc_data, dc_data->ref);

    if (dc_data->ref > 0)
        return;

    free_hl_create_dc(dc_data);
}

static void free_hl_del_dc(struct hl_del_dc *data)
{
    dbus_message_unref(data->msg);
    dbus_connection_unref(data->conn);
    hl_channel_unref(data->hl_chann);

    g_free(data);
}

static struct hl_del_dc *hl_del_dc_ref(struct hl_del_dc *data)
{
    data->ref++;

    DBG("hl_del_dc_data_ref(%p): ref=%d", data, data->ref);

    return data;
}

static void hl_del_dc_unref(struct hl_del_dc *data)
{
    data->ref--;

    DBG("hl_del_dc_data_unref(%p): ref=%d", data, data->ref);

    if (data->ref > 0)
        return;

    free_hl_del_dc(data);
}


static void free_hl_acq_dc(struct hl_acq_dc *data)
{
    dbus_message_unref(data->msg);
    dbus_connection_unref(data->conn);
    hl_channel_unref(data->hl_chann);

    g_free(data);
}

static struct hl_acq_dc *hl_acq_dc_ref(struct hl_acq_dc *data)
{
    data->ref++;

    DBG("hl_acq_dc_data_ref(%p): ref=%d", data, data->ref);

    return data;
}

static void hl_acq_dc_unref(struct hl_acq_dc *data)
{
    data->ref--;

    DBG("hl_acq_dc_data_unref(%p): ref=%d", data, data->ref);

    if (data->ref > 0)
        return;

    free_hl_acq_dc(data);
}


static struct hl_sock *hl_sock_ref(struct hl_sock *data)
{
    data->ref++;

    DBG("hl_sock_ref(%p): ref=%d", data, data->ref);

    return data;
}

static void hl_sock_unref(struct hl_sock *data)
{
    data->ref--;

    DBG("hl_sock_unref(%p): ref=%d", data, data->ref);

    if (data->ref > 0)
        return;

    g_free(data);
}

static void health_device_destroy(void *data)
{
    struct hl_device *device = data;

    DBG("Unregistered interface %s on path %s", HEALTH_DEVICE,
        device_get_path(device->dev));

    remove_channels(device);
    if (device->ndc)
    {
        hl_channel_unref(device->ndc);
        device->ndc = NULL;
    }

    devices = g_slist_remove(devices, device);
    health_device_unref(device);
}
static void free_health_device(struct hl_device *device)
{
    if (device->conn)
    {
        dbus_connection_unref(device->conn);
        device->conn = NULL;
    }

    if (device->dev)
    {
        btd_device_unref(device->dev);
        device->dev = NULL;
    }
    // device_unref_mcl(device);

    g_free(device);
}

boolean hl_device_register(DBusConnection *conn, struct btd_device *device)
{
    struct hl_device *hdev;
    GSList *l;

    l = g_slist_find_custom(devices, device, cmp_device);
    if (l)
    {
        hdev = l->data;
        hdev->sdp_present = TRUE;
        return true;
    }

    hdev = create_health_device(conn, device);
    if (!hdev)
        return false;

    hdev->sdp_present = TRUE;

    devices = g_slist_prepend(devices, hdev);
    return true;
}

void hl_device_unregister(struct btd_device *device)
{
    struct hl_device *hl_dev;
    const char *path;
    GSList *l;

    l = g_slist_find_custom(devices, device, cmp_device);
    if (!l)
        return;

    hl_dev = l->data;
    path = device_get_path(hl_dev->dev);
    g_dbus_unregister_interface(hl_dev->conn, path, HEALTH_DEVICE);
}

static GDBusMethodTable health_device_methods[] = {
    //{"Echo",		"",	"b",	device_echo,
    //					G_DBUS_METHOD_FLAG_ASYNC },
    {"CreateChannel",   "os",   "o",    device_create_channel,
        G_DBUS_METHOD_FLAG_ASYNC},
    {"DestroyChannel",  "o",    "", device_destroy_channel,
        G_DBUS_METHOD_FLAG_ASYNC},
    {"GetProperties",   "", "a{sv}", device_get_properties},
    { NULL}
};

static GDBusSignalTable health_device_signals[] = {
    {"ChannelConnected",        "o"},
    {"ChannelDeleted",      "o"},
    {"PropertyChanged",     "sv"},
    { NULL}
};

static struct hl_device *create_health_device(DBusConnection *conn,
                                              struct btd_device *device)
{
    struct btd_adapter *adapter = device_get_adapter(device);
    const gchar *path = device_get_path(device);
    struct hl_device *dev;
    GSList *l;
    DBG("Inside create_health_device path =%s",path);
    if (!device)
        return NULL;

    dev = g_new0(struct hl_device, 1);
    dev->conn = dbus_connection_ref(conn);
    dev->dev = btd_device_ref(device);
    health_device_ref(dev);

    dev->hl_adapter = NULL;

    if (!g_dbus_register_interface(conn, path,
                                   HEALTH_DEVICE,
                                   health_device_methods,
                                   health_device_signals, NULL,
                                   dev, health_device_destroy))
    {
        error("D-Bus failed to register %s interface", HEALTH_DEVICE);
        goto fail;
    }

    DBG("Registered interface %s on path %s", HEALTH_DEVICE, path);
    return dev;

    fail:
    health_device_unref(dev);
    return NULL;
}

static DBusMessage *device_create_channel(DBusConnection *conn,
                                          DBusMessage *msg, void *user_data)
{
    struct hl_device *device = user_data;
    struct hl_application *app;
    struct hl_create_dc *data;
    char *app_path, *conf;
    DBusMessage *reply;
    GError *err = NULL;
    uint8_t config;
    GSList *l;
    boolean is_echo = true;
    bdaddr_t  addr;

    DBG("Entered device_create_channel");
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &app_path,
                               DBUS_TYPE_STRING, &conf,
                               DBUS_TYPE_INVALID))
    {
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Invalid arguments in method call");
    }

    //TODO: check if medp_id = echo
    l = g_slist_find_custom(applications, app_path, cmp_app);
    if (!l)
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Invalid arguments in method call, "
                                   "no such application");
    app = l->data;

    if (g_ascii_strcasecmp("Reliable", conf) == 0)
        config = HL_RELIABLE_DC;
    else if (g_ascii_strcasecmp("Streaming", conf) == 0)
        config = HL_STREAMING_DC;
    else if (g_ascii_strcasecmp("Any", conf) == 0)
        config = HL_NO_PREFERENCE_DC;
    else
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Invalid arguments in method call");

    if (app->role == HL_SINK && config != HL_NO_PREFERENCE_DC)
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Configuration not valid for sinks");

    if (app->role == HL_SOURCE && config == HL_NO_PREFERENCE_DC)
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Configuration not valid for sources");

    if (!device->fr && config == HL_STREAMING_DC)
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".InvalidArguments",
                                   "Configuration not valid, first "
                                   "channel should be reliable");

    data = g_new0(struct hl_create_dc, 1);
    data->dev = health_device_ref(device);
    data->config = config;
    data->app = hl_application_ref(app);
    data->msg = dbus_message_ref(msg);
    data->conn = dbus_connection_ref(conn);
    device_get_address(device->dev, &addr);
    hl_create_data_ref(data);
    if (!set_dc_path(data))
    {
        hl_create_data_unref(data);
        return g_dbus_create_error(msg,
                                   ERROR_INTERFACE ".HealthError",
                                   "Can't get a valid id for the data channnel");
    }
    create_dc = g_slist_prepend(create_dc, data);

    dtun_hl_channel_create_cmd(HL_CMD_CHANNEL_CREATE,app->path,config, &addr,data->path,is_echo);
    DBG("Leaving device_create_channel");
    return NULL;

}

static DBusMessage *device_destroy_channel(DBusConnection *conn,
                                           DBusMessage *msg, void *user_data)
{
    struct hl_device *device = user_data;
    struct hl_del_dc *del_data;
    struct hl_channel *hl_chan;
    DBusMessage *reply;
    GError *err = NULL;
    char *path;
    GSList *l;
    bdaddr_t  addr;

    DBG("Entered device_destroy_channel");
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
                               DBUS_TYPE_INVALID))
    {
        return btd_error_invalid_args(msg);
    }

    l = g_slist_find_custom(device->channels, path, cmp_chan_path);
    if (!l)
        return btd_error_invalid_args(msg);

    hl_chan = l->data;
    DBG("Device destroy channel 1");
    del_data = g_new0(struct hl_del_dc, 1);
    del_data->msg = dbus_message_ref(msg);
    del_data->conn = dbus_connection_ref(conn);
    del_data->hl_chann = hl_channel_ref(hl_chan);
    device_get_address(hl_chan->dev->dev, &addr);
    del_data->path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                     addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], hl_chan->mdlid);

    DBG("Device destroy channel Path %s",del_data->path);
    hl_del_dc_ref(del_data);    
    del_dc = g_slist_prepend(del_dc, del_data);
    DBG("Entered device_destroy_channel: channel path = %s, mdl_id =%d", path, hl_chan->mdlid);
    dtun_hl_channel_destroy_cmd(HL_CMD_CHANNEL_DESTROY,hl_chan->app->path,hl_chan->mdlid,&addr);
    DBG("Leaving device_destroy_channel");
    return NULL;

}

static DBusMessage *device_get_properties(DBusConnection *conn,
                                          DBusMessage *msg, void *user_data)
{
    struct hl_device *device = user_data;
    DBusMessageIter iter, dict;
    DBusMessage *reply;
    char *path;

    reply = dbus_message_new_method_return(msg);
    if (!reply)
        return NULL;

    dbus_message_iter_init_append(reply, &iter);

    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

    if (device->fr)
        path = g_strdup(device->fr->path);
    else
        path = g_strdup("");
    dict_append_entry(&dict, "MainChannel", DBUS_TYPE_OBJECT_PATH, &path);
    g_free(path);
    dbus_message_iter_close_container(&iter, &dict);

    return reply;

}



/////////////////////////////////////////
//health channel

static void health_channel_destroy(void *data)
{
    struct hl_channel *hl_chan = data;
    struct hl_device *dev = hl_chan->dev;

    DBG("Destroy Health Channel %s", hl_chan->path);
    if (!g_slist_find(dev->channels, hl_chan))
        goto end;

    dev->channels = g_slist_remove(dev->channels, hl_chan);

    if (hl_chan->mdep != HL_MDEP_ECHO)
        g_dbus_emit_signal(dev->conn, device_get_path(dev->dev),
                           HEALTH_DEVICE, "ChannelDeleted",
                           DBUS_TYPE_OBJECT_PATH, &hl_chan->path,
                           DBUS_TYPE_INVALID);

    if (hl_chan == dev->fr)
    {
        char *empty_path;

        hl_channel_unref(dev->fr);
        dev->fr = NULL;
        empty_path = "/";
        emit_property_changed(dev->conn, device_get_path(dev->dev),
                              HEALTH_DEVICE, "MainChannel",
                              DBUS_TYPE_OBJECT_PATH, &empty_path);
    }

    end:
    hl_channel_unref(hl_chan);
}

static GDBusMethodTable health_channels_methods[] = {
    {"GetProperties","",    "a{sv}",    channel_get_properties},
    {"Acquire", "", "h",        channel_acquire,
        G_DBUS_METHOD_FLAG_ASYNC},
    {"Release", "", "",     channel_release,
        G_DBUS_METHOD_FLAG_ASYNC},
    { NULL}
};

static struct hl_channel *hl_channel_ref(struct hl_channel *chan)
{
    if (!chan)
        return NULL;

    chan->ref++;

    DBG("health_channel_ref(%p): ref=%d", chan, chan->ref);
    return chan;
}

static void free_health_channel(struct hl_channel *chan)
{
    if (chan->mdep == HL_MDEP_ECHO)
    {
        //free_echo_data(chan->edata);
        chan->edata = NULL;
    }

    //mcap_mdl_unref(chan->mdl);
    hl_application_unref(chan->app);
    health_device_unref(chan->dev);
    g_free(chan->path);
    g_free(chan);
}

static void hl_channel_unref(struct hl_channel *chan)
{
    if (!chan)
        return;

    chan->ref --;
    DBG("health_channel_unref(%p): ref=%d", chan, chan->ref);

    if (chan->ref > 0)
        return;

    free_health_channel(chan);
}
static gint cmp_chan_path(gconstpointer a, gconstpointer b)
{
    const struct hl_channel *chan = a;
    const char *path = b;

    return g_ascii_strcasecmp(chan->path, path);
}


static struct hl_channel *create_channel(struct hl_device *dev,
                                         uint8_t config,
                                         uint16_t mdlid,
                                         struct hl_application *app,
                                         GError **err)
{
    struct hl_channel *hl_chann;

    if (!dev)
        return NULL;

    hl_chann = g_new0(struct hl_channel, 1);
    hl_chann->config = config;
    hl_chann->dev = health_device_ref(dev);
    hl_chann->mdlid = mdlid;

    //if (mdl)
    //	hl_chann->mdl = mcap_mdl_ref(mdl);

    if (app)
    {
        hl_chann->mdep = app->id;
        hl_chann->app = hl_application_ref(app);
    } 

    hl_chann->path = g_strdup_printf("%s/chan%d",
                                     device_get_path(hl_chann->dev->dev),
                                     hl_chann->mdlid);
    DBG("HL channnel created with path %s", hl_chann->path);
    dev->channels = g_slist_append(dev->channels,
                                   hl_channel_ref(hl_chann));

    if (hl_chann->mdep == HL_MDEP_ECHO)
        return hl_channel_ref(hl_chann);

    if (!g_dbus_register_interface(dev->conn, hl_chann->path,
                                   HEALTH_CHANNEL,
                                   health_channels_methods, NULL, NULL,
                                   hl_chann, health_channel_destroy))
    {
        g_set_error(err, HL_ERROR, HL_UNSPECIFIED_ERROR,
                    "Can't register the channel interface");
        health_channel_destroy(hl_chann);
        return NULL;
    }
    DBG("HL channnel created");
    return hl_channel_ref(hl_chann);
}

static void remove_channels(struct hl_device *dev)
{
    struct hl_channel *chan;
    char *path;

    while (dev->channels)
    {
        chan = dev->channels->data;

        path = g_strdup(chan->path);
        if (!g_dbus_unregister_interface(dev->conn, path,
                                         HEALTH_CHANNEL))
            health_channel_destroy(chan);
        g_free(path);
    }
}

static DBusMessage *channel_get_properties(DBusConnection *conn,
                                           DBusMessage *msg, void *user_data)
{
    struct hl_channel *chan = user_data;
    DBusMessageIter iter, dict;
    DBusMessage *reply;
    const char *path;
    char *type;

    reply = dbus_message_new_method_return(msg);
    if (!reply)
        return NULL;

    dbus_message_iter_init_append(reply, &iter);

    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

    path = device_get_path(chan->dev->dev);
    dict_append_entry(&dict, "Device", DBUS_TYPE_OBJECT_PATH, &path);

    path = chan->app->path;
    dict_append_entry(&dict, "Application", DBUS_TYPE_OBJECT_PATH, &path);

    if (chan->config == HL_RELIABLE_DC)
        type = g_strdup("Reliable");
    else
        type = g_strdup("Streaming");

    dict_append_entry(&dict, "Type", DBUS_TYPE_STRING, &type);

    g_free(type);

    dbus_message_iter_close_container(&iter, &dict);

    return reply;


}


static DBusMessage *channel_acquire(DBusConnection *conn,
                                    DBusMessage *msg, void *user_data)
{
    struct hl_channel *chan = user_data;
    struct hl_acq_dc *acq_data;
    struct hl_sock *sock_temp;
    bdaddr_t addr;
    GError *gerr = NULL;
    DBusMessage *reply; 
    GSList *l,*sock_l;

    DBG("entered channel_acquire ");
    acq_data = g_new0(struct hl_acq_dc, 1);
    acq_data->conn = dbus_connection_ref(conn);
    acq_data->msg = dbus_message_ref(msg);
    acq_data->hl_chann = hl_channel_ref(chan);
    acq_data->id = chan->mdlid;
    hl_acq_dc_ref(acq_data);

    DBG("channel_acquire acq_data->msg=0x%x", acq_data->msg);
    DBG("channel_acquire acq_data->conn=0x%x", acq_data->conn);

    device_get_address(chan->dev->dev, &addr);
    acq_data->path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                     addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], chan->mdlid);
    acq_dc = g_slist_prepend(acq_dc, acq_data);
    DBG("channel_acquire: acquire acq_path %s",acq_data->path);
    sock_l = g_slist_find_custom(sock_list, acq_data->path , cmp_sock_path);
   
    if (sock_l)
    {
        sock_temp = sock_l->data;
        DBG("Acquire:socket already exits");
        close(sock_temp->fd);		
	 sock_list = g_slist_remove(sock_list, sock_temp);
	 hl_sock_unref(sock_temp);
	 local_release = true;
	 dtun_hl_channel_release_cmd(HL_CMD_CHANNEL_RELEASE, chan->app->path, &addr, chan->mdlid);
    }		

    dtun_hl_channel_acquire_cmd(HL_CMD_CHANNEL_ACQUIRE, chan->app->path, &addr, chan->mdlid);
    DBG("leaving channel_acquire ");
    return NULL;
}
static DBusMessage *channel_release(DBusConnection *conn,
                                    DBusMessage *msg, void *user_data)
{

    struct hl_channel *chan = user_data;
    struct hl_sock *sock_data;
    struct hl_acq_dc *acq_data;
    bdaddr_t addr;
    GError *gerr = NULL;
    DBusMessage *reply; 
    GSList *l;
    char *path;

    DBG("entered channel_release ");
    acq_data = g_new0(struct hl_acq_dc, 1);
    acq_data->conn = dbus_connection_ref(conn);
    acq_data->msg = dbus_message_ref(msg);
    acq_data->hl_chann = hl_channel_ref(chan);
    acq_data->id = chan->mdlid;
    hl_acq_dc_ref(acq_data);
    device_get_address(chan->dev->dev, &addr);
    acq_data->path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], chan->mdlid);
    DBG("channel_release: release acq_path %s",acq_data->path);
    acq_dc = g_slist_prepend(acq_dc, acq_data);
    dtun_hl_channel_release_cmd(HL_CMD_CHANNEL_RELEASE, chan->app->path, &addr, chan->mdlid);

    path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
				addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], chan->mdlid);

    l = g_slist_find_custom(sock_list, path , cmp_sock_path);
    if (!l){
	DBG("No sock data found");
	return g_dbus_create_error(msg,
                                    ERROR_INTERFACE,".HealthError","No socket found for the channel");
    }
    sock_data = l->data;
    DBG("channel_release:sock data found");
    close(sock_data->fd);
    DBG("channel_release:socket closed");
    sock_list = g_slist_remove(sock_list, sock_data);
    hl_sock_unref(sock_data);
    
    DBG("leaving channel_release ");
	return NULL;
}


////////////////////////////////////////////////////
//dtun cmd & signal
void dtun_sig_hl_app_create(tDTUN_DEVICE_SIGNAL *p_data)
{
    uint8_t status = p_data->hl_app_create.info.status;
    boolean is_create = p_data->hl_app_create.info.is_create;
    struct hl_application *app;
    GSList *l;
    const char *path = p_data->hl_app_create.info.path;
    DBusMessage *reply;
    DBG("Health Application create signal");
    if (is_create)
    {
        l = g_slist_find_custom(applications, path, cmp_app);

        if (!l)
            return error("NO such application found");
        app = l->data;
        if (status == HL_STATUS_OK)
        {
            DBG("Health Application %s created successfully",p_data->hl_app_create.info.path);
            reply =  g_dbus_create_reply(app->msg, DBUS_TYPE_OBJECT_PATH, &app->path,
                                         DBUS_TYPE_INVALID);
            g_dbus_send_message(app->conn, reply);
        }
        else
        {
            reply = g_dbus_create_error(app->msg,
                                        ERROR_INTERFACE,".HealthError","Application not created successfully");
            g_dbus_send_message(app->conn, reply);
        }
    }
}

void dtun_sig_hl_app_destroy(tDTUN_DEVICE_SIGNAL *p_data)
{
    uint8_t status = p_data->hl_app_destroy.info.status;
    boolean is_create = p_data->hl_app_destroy.info.is_create;
    struct hl_application *app;
    GSList *l;
    const char *path = p_data->hl_app_destroy.info.path;
    DBusMessage *reply;

    l = g_slist_find_custom(applications, path, cmp_app);

    if (!l)
        return error("NO such application found");
    app = l->data;

    if ((!is_create) && (status == HL_STATUS_OK))
    {
	 DBG("Health Application %s destroyd successfully",p_data->hl_app_destroy.info.path);
        reply = g_dbus_create_reply(app->msg,DBUS_TYPE_INVALID);
        g_dbus_send_message(app->conn, reply);
        DBG("Health Application destroy: reply sent");
        applications = g_slist_remove(applications, app);
        hl_application_unref(app);
        DBG("Health Application destroyd successfully");
    }
    else
    {
        reply = g_dbus_create_error(app->msg,
                                    ERROR_INTERFACE,".HealthError","Application not destroyed successfully");
        g_dbus_send_message(app->conn, reply);

    }
}

static void dtun_hl_app_create_cmd(int cmd, char *path, int role, int chan_type, int data_type, char *description)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d, role:%d, chan_type:%d, data_type:%d", cmd, role, chan_type, data_type);
    debug("path=%s", path);
    memset(&method.hl_app_create, 0, sizeof method.hl_app_create);
    method.hl_app_create.hdr.id = DTUN_METHOD_HL_APP_CREATE;
    method.hl_app_create.hdr.len = sizeof(method.hl_app_create.info);

    strncpy(method.hl_app_create.info.path, path, sizeof(method.hl_app_create.info.path)-1);
    method.hl_app_create.info.path[sizeof(method.hl_app_create.info.path)-1] = '\0';
    strncpy(method.hl_app_create.info.description, description, sizeof(method.hl_app_create.info.description)-1);
    method.hl_app_create.info.description[sizeof(method.hl_app_create.info.description)-1] = '\0';
    method.hl_app_create.info.role = role;
    method.hl_app_create.info.chan_type = chan_type;
    method.hl_app_create.info.data_type = data_type;
    debug("calling dtun_client_call_method");
    dtun_client_call_method(&method);
}

static void dtun_hl_app_destroy_cmd(int cmd, const char *path)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d, path:%s", cmd, path);
    memset(&method.hl_app_destroy, 0, sizeof(method.hl_app_destroy));
    method.hl_app_destroy.hdr.id = DTUN_METHOD_HL_APP_DESTROY;
    method.hl_app_destroy.hdr.len = sizeof(method.hl_app_destroy.info);
    strncpy(method.hl_app_destroy.info.path, path, sizeof(method.hl_app_destroy.info.path)-1);
    method.hl_app_destroy.info.path[sizeof(method.hl_app_destroy.info.path)-1] = '\0';
    dtun_client_call_method(&method);
}


void dtun_sig_hl_channel_connected(tDTUN_DEVICE_SIGNAL *p_data)
{
    struct hl_application *app;
    struct hl_channel *hl_chan;
    struct hl_create_dc *data;
    struct hl_device *dev;
    GSList *l, *nl, *appList;
    bdaddr_t addr;
    uint8_t conf = p_data->hl_channel_connect.info.config;
    uint16_t mdl_id = p_data->hl_channel_connect.info.mdl_id;
    const char *app_path = p_data->hl_channel_connect.info.app_path;
    boolean is_echo = p_data->hl_channel_connect.info.is_echo;
    memcpy(&addr, p_data->hl_channel_connect.info.bd_addr, sizeof(bdaddr_t));
    DBG("Data channel connected signal");
    DBG("Data channel created by remote request");
    DBG("Dev address ");
    nl = g_slist_find_custom(devices, &addr, cmp_dev_addr);
    if (!nl)
        return error("NO such device found");
    dev = nl->data;
    l = g_slist_find_custom(dev->channels, &mdl_id, cmp_chan_mdlid);
    if(!l)
		return error("NO such channel found");
    hl_chan = l->data;
    char *path;
    DBG("Data channel with mdl_id %d already exits, and was reconnected",mdl_id);
    appList = g_slist_find_custom(applications, app_path, cmp_app);
    if (!appList)
        return error("NO such app found found");
    app = appList->data;
        g_dbus_emit_signal(dev->conn,
                           device_get_path(hl_chan->dev->dev),
                           HEALTH_DEVICE,
                           "ChannelConnected",
                           DBUS_TYPE_OBJECT_PATH, &hl_chan->path,
                           DBUS_TYPE_INVALID);
    return;
}

void dtun_sig_hl_channel_create(tDTUN_DEVICE_SIGNAL *p_data)
{
    uint8_t status = p_data->hl_channel_create.info.status;
    struct hl_application *app;
    struct hl_channel *hl_chan;
    struct hl_create_dc *data;
    struct hl_device *dev;
	struct hl_sock *sock;
    GError *gerr = NULL;
    DBusMessage *reply;
    GSList *l, *nl, *appList;
    bdaddr_t addr;

    uint8_t conf = p_data->hl_channel_create.info.config;
    uint16_t mdl_id = p_data->hl_channel_create.info.mdl_id;
    const char *app_path = p_data->hl_channel_create.info.app_path;
    const char *dc_path = p_data->hl_channel_create.info.dc_path;
    boolean is_echo = p_data->hl_channel_create.info.is_echo;
    boolean is_local = p_data->hl_channel_create.info.is_local_initiated;
    memcpy(&addr, p_data->hl_channel_create.info.bd_addr, sizeof(bdaddr_t));
    debug("Data channel create signal");
    // If channel was created by peer request
    if (!is_local && status == HL_STATUS_OK)
    {
        DBG("Data channel created by remote request");
        DBG("Dev address ");
        nl = g_slist_find_custom(devices, &addr, cmp_dev_addr);
        if (!nl)
            return error("NO such device found");
        dev = nl->data;

        l = g_slist_find_custom(dev->channels, &mdl_id, cmp_chan_mdlid);

        if (l)
        {
            hl_chan = l->data;
            char *path;
            DBG("Data channel with mdl_id %d already exits, deregister it",mdl_id);
            path = g_strdup(hl_chan->path);
            g_dbus_unregister_interface(dev->conn, path, HEALTH_CHANNEL);
            g_free(path);
        }
        appList = g_slist_find_custom(applications, app_path, cmp_app);

        if (!appList)
            return error("NO such app found found");
        app = appList->data;

        hl_chan = create_channel(dev, conf, mdl_id, app, NULL);
        if (hl_chan)
        {
            if (hl_chan->mdep == HL_MDEP_ECHO)
            {

                int fd;
                //fd = mcap_mdl_get_fd(chan->mdl);
            }
            //Only send the connected signa
            g_dbus_emit_signal(dev->conn,
                               device_get_path(hl_chan->dev->dev),
                               HEALTH_DEVICE,
                               "ChannelConnected",
                               DBUS_TYPE_OBJECT_PATH, &hl_chan->path,
                               DBUS_TYPE_INVALID);

            //set the first reliable channel ref if this is the first one
            if (dev->fr)
                goto end;
            dev->fr = hl_channel_ref(hl_chan);

            emit_property_changed(dev->conn, device_get_path(dev->dev),
                                  HEALTH_DEVICE, "MainChannel",
                                  DBUS_TYPE_OBJECT_PATH, &dev->fr->path);

            end:
            hl_channel_unref(hl_chan);

        }
        return;
    }
    else
    {
        l = g_slist_find_custom(create_dc, dc_path , cmp_create_dc);

        if (!l)
            return error("NO such create_dc found");
        data = l->data;
        create_dc = g_slist_remove(create_dc, data);
        if (status == HL_STATUS_OK)
        {
            DBG("Health data channel created successfully for app %s, MDL ID = %d",p_data->hl_channel_create.info.app_path, p_data->hl_channel_create.info.mdl_id);


            hl_chan = create_channel(data->dev, conf, mdl_id,
                                     data->app, &gerr);
            if (hl_chan)
            {
                if (hl_chan->mdep != HL_MDEP_ECHO)
                    g_dbus_emit_signal(data->conn,
                                       device_get_path(hl_chan->dev->dev),
                                       HEALTH_DEVICE,
                                       "ChannelConnected",
                                       DBUS_TYPE_OBJECT_PATH, &hl_chan->path,
                                       DBUS_TYPE_INVALID);

                reply = g_dbus_create_reply(data->msg,
                                            DBUS_TYPE_OBJECT_PATH, &hl_chan->path,
                                            DBUS_TYPE_INVALID);
                g_dbus_send_message(data->conn, reply);

		  dev = hl_chan->dev;
                if (dev->fr){
                    hl_channel_unref(hl_chan);
                    return;
                }
                dev->fr = hl_channel_ref(hl_chan);

                emit_property_changed(dev->conn, device_get_path(dev->dev),
                                      HEALTH_DEVICE, "MainChannel",
                                      DBUS_TYPE_OBJECT_PATH, &dev->fr->path);
                hl_channel_unref(hl_chan);
                hl_create_data_unref(data);
                DBG("Health data channel created successfully2 ");
            }
            else
            {
                reply = g_dbus_create_error(data->msg,
                                            ERROR_INTERFACE ".HealthError",
                                            "Failure in creating data channel");
                g_dbus_send_message(data->conn, reply);
                g_error_free(gerr);
                hl_create_data_unref(data);
            }

        }
        else
        {
            reply = g_dbus_create_error(data->msg,
                                        ERROR_INTERFACE ".HealthError",
                                        "Failure in creating data channel");
            g_dbus_send_message(data->conn, reply);
            hl_create_data_unref(data);
        }
    }

}

void dtun_sig_hl_channel_destroy(tDTUN_DEVICE_SIGNAL *p_data)
{
    uint8_t status = p_data->hl_channel_destroy.info.status;
    struct hl_del_dc *del_data;
    DBusMessage *reply;
    char *path, *del_data_path;
    GSList *l;
    GSList *nl;
    uint16_t mdl_id = p_data->hl_channel_destroy.info.mdl_id;
    boolean is_local = p_data->hl_channel_destroy.info.is_local_initiated;
    bdaddr_t addr;

    struct hl_channel *chan;
    struct hl_device *dev;

    memcpy(&addr, p_data->hl_channel_destroy.info.bd_addr, sizeof(bdaddr_t));
    del_data_path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                    addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], mdl_id);
    DBG("Entered signal Health data channel destroy for del_data_path %s, MDL ID = %d",del_data_path, p_data->hl_channel_destroy.info.mdl_id);
    // If channel deletion is initiatd by peer device
    if (!is_local && status == HL_STATUS_OK)
    {
        DBG("dtun_sig_hl_channel_destroy: destroy channel initiated by peer");
        nl = g_slist_find_custom(devices, &addr, cmp_dev_addr);
        if (!nl)
            return;
        dev = nl->data;

        l = g_slist_find_custom(dev->channels, &mdl_id, cmp_chan_mdlid);
        if (!l)
            return;

        chan = l->data;

        path = g_strdup(chan->path);
        if (!g_dbus_unregister_interface(chan->dev->conn, path, HEALTH_CHANNEL))
            health_channel_destroy(chan);
        g_free(path);
        return;

    }
    else
    {
        DBG("dtun_sig_hl_channel_destroy: destroy channel initiated locally");
        l = g_slist_find_custom(del_dc, del_data_path , cmp_del_dc_path);

        if (!l)
            return error("NO such del_dc found");
        del_data = l->data;
        del_dc = g_slist_remove(del_dc, del_data);
        if (status == HL_STATUS_OK)
        {

            uint8_t conf = p_data->hl_channel_create.info.config;

            path = g_strdup(del_data->hl_chann->path);
            g_dbus_unregister_interface(del_data->conn, path, HEALTH_CHANNEL);
            DBG("Health data channel destroyed successfully for app %s, MDL ID = %d",p_data->hl_channel_destroy.info.app_path, p_data->hl_channel_destroy.info.mdl_id);
            g_free(path);
            reply = g_dbus_create_reply(del_data->msg, DBUS_TYPE_INVALID);
            g_dbus_send_message(del_data->conn, reply);
        }
        else
        {
            reply = g_dbus_create_error(del_data->msg,
                                        ERROR_INTERFACE ".HealthError",
                                        "Health channel deletion failed");
            g_dbus_send_message(del_data->conn, reply);
        }
        hl_del_dc_unref(del_data);
        DBG("dtun_sig_hl_channel_destroy: Leaving");
    }
}

static void dtun_hl_channel_create_cmd(int cmd, char *app_path, uint8_t config, bdaddr_t* bdaddr, char *dc_path, boolean is_echo)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d ", cmd);
    memset(&method.hl_channel_create, 0, sizeof method.hl_channel_create);
    method.hl_channel_create.hdr.id = DTUN_METHOD_HL_CHANNEL_CREATE;
    method.hl_channel_create.hdr.len = sizeof(method.hl_channel_create.info);
    strncpy(method.hl_channel_create.info.app_path, app_path, sizeof(method.hl_channel_create.info.app_path)-1);
    method.hl_channel_create.info.app_path[sizeof(method.hl_channel_create.info.app_path)-1] = '\0';
    memcpy(&method.hl_channel_create.info.bd_addr, bdaddr, sizeof(bdaddr_t));
    strncpy(method.hl_channel_create.info.dc_path, dc_path, sizeof(method.hl_channel_create.info.dc_path)-1);
    method.hl_channel_create.info.dc_path[sizeof(method.hl_channel_create.info.dc_path)-1] = '\0';
    method.hl_channel_create.info.config = config;
    method.hl_channel_create.info.is_echo = is_echo;
    dtun_client_call_method(&method);
}

static void dtun_hl_channel_destroy_cmd(int cmd, char *app_path, uint16_t mdl_id, bdaddr_t* bdaddr)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d mdl_id =%d", cmd,mdl_id);
    memset(&method.hl_channel_destroy, 0, sizeof method.hl_channel_destroy);
    method.hl_channel_destroy.hdr.id = DTUN_METHOD_HL_CHANNEL_DESTROY;
    method.hl_channel_destroy.hdr.len = sizeof(method.hl_channel_destroy.info);
    method.hl_channel_destroy.info.mdl_id = mdl_id;
    strncpy(method.hl_channel_destroy.info.app_path, app_path, sizeof(method.hl_channel_destroy.info.app_path)-1);
    method.hl_channel_destroy.info.app_path[sizeof(method.hl_channel_destroy.info.app_path)-1] = '\0';
    memcpy(&method.hl_channel_destroy.info.bd_addr, bdaddr, sizeof(bdaddr_t));
    dtun_client_call_method(&method);
}

void dtun_sig_hl_channel_acquire(tDTUN_DEVICE_SIGNAL * p_data){
    uint8_t status = p_data->hl_channel_acquire.info.status;
    struct hl_channel *hl_chan;
    struct hl_acq_dc *data;
    struct hl_device *dev;
    GError *gerr = NULL;
    DBusMessage *reply;
    GSList *l, *sock_l;
    bdaddr_t addr;
    char *sock_path;
    char *acq_data_path;
    int fd = -1;
    struct hl_sock *sock_data, *sock_temp;
    uint16_t mdl_id = p_data->hl_channel_acquire.info.mdl_id;
    const char *app_path = p_data->hl_channel_acquire.info.app_path;
    memcpy(&addr, p_data->hl_channel_acquire.info.bd_addr, sizeof(bdaddr_t));
    DBG("%x:%x:%x:%x:%x:%x/chan%d",
            addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], mdl_id);
    acq_data_path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                    addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], mdl_id);


    DBG("dtun_sig_hl_channel_acquire: acq_data_path %s",acq_data_path);
    l = g_slist_find_custom(acq_dc, acq_data_path , cmp_acq_dc);
    if (!l)
        return error("NO such acq_dc found");
    data = l->data;
    acq_dc = g_slist_remove(acq_dc, data);

    if (status == HL_STATUS_OK)
    {
        DBG("Entered dtun_sig_hl_channel_acquire--3");
        sock_path = p_data->hl_channel_acquire.info.sock_path;
		fd = connect_server_socket(sock_path);
        if (fd >= 0)
        {
            DBG("dtun_sig_hl_channel_acquire 1 DBUS_TYPE_UNIX_FD=%d",DBUS_TYPE_UNIX_FD);
            DBG("dtun_sig_hl_channel_acquire 1 fd=%d",fd);
            DBG("dtun_sig_hl_channel_acquire 1 data->msg=0x%x",data->msg);

            reply = g_dbus_create_reply(data->msg, DBUS_TYPE_UNIX_FD, &fd,
                                        DBUS_TYPE_INVALID);

            DBG("dtun_sig_hl_channel_acquire 2 reply=0x%x", reply);
            g_dbus_send_message(data->conn, reply);
            sock_data = g_new0(struct hl_sock, 1);
            hl_sock_ref(sock_data);
            sock_data->sock_path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                    addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], mdl_id);
            sock_data->fd = fd;
	       
            sock_list = g_slist_prepend(sock_list, sock_data);
            DBG("dtun_sig_hl_channel_acquire 3");
        }


    }
    else
    {
        reply = g_dbus_create_error(data->msg,
                                    ERROR_INTERFACE ".HealthError",
                                    "Health channel acquire failed");
        g_dbus_send_message(data->conn, reply);
    }
  
    DBG("dtun_sig_hl_channel_acquire: Leaving");
	hl_acq_dc_unref(data);

}

void dtun_sig_hl_channel_release(tDTUN_DEVICE_SIGNAL * p_data){
    uint8_t status = p_data->hl_channel_release.info.status;
    struct hl_channel *hl_chan;
    struct hl_acq_dc *data;
    struct hl_device *dev;
    GError *gerr = NULL;
    DBusMessage *reply;
    GSList *l, *nl;
    bdaddr_t addr;
    char *acq_data_path; 
    debug("dtun_sig_hl_channel_release:");
    uint16_t mdl_id = p_data->hl_channel_release.info.mdl_id;
    const char *app_path = p_data->hl_channel_release.info.app_path;
    memcpy(&addr, p_data->hl_channel_release.info.bd_addr, sizeof(bdaddr_t));
    debug("dtun_sig_hl_channel_release 3:");
    debug("dtun_sig_hl_channel_release: mdl_id=%d, Status of release=%d",mdl_id,status);

    if(local_release){
        DBG("Release was called internally");
        local_release = false;
	 return;
    }
    acq_data_path = g_strdup_printf("%x:%x:%x:%x:%x:%x/chan%d",
                                    addr.b[0],addr.b[1],addr.b[2],addr.b[3],addr.b[4],addr.b[5], mdl_id);
    DBG("dtun_sig_hl_channel_release: release_data_path %s",acq_data_path);
    l = g_slist_find_custom(acq_dc, acq_data_path , cmp_acq_dc);
    if (!l)
        return error("NO such acq_dc found");
    data = l->data;
    acq_dc = g_slist_remove(acq_dc, data);
    reply = g_dbus_create_reply(data->msg,DBUS_TYPE_INVALID);
    g_dbus_send_message(data->conn, reply);
    hl_acq_dc_unref(data);

}

static void dtun_hl_channel_acquire_cmd(int cmd, char *app_path, bdaddr_t* bdaddr, uint16_t mdl_id)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d ", cmd);
    memset(&method.hl_channel_acquire, 0, sizeof method.hl_channel_acquire);
    method.hl_channel_acquire.hdr.id = DTUN_METHOD_HL_CHANNEL_ACQUIRE;
    method.hl_channel_acquire.hdr.len = sizeof(method.hl_channel_acquire.info);
    strncpy(method.hl_channel_acquire.info.app_path, app_path, sizeof(method.hl_channel_acquire.info.app_path)-1);
    method.hl_channel_acquire.info.app_path[sizeof(method.hl_channel_acquire.info.app_path)-1] = '\0';
    method.hl_channel_acquire.info.mdl_id = mdl_id;
    memcpy(&method.hl_channel_acquire.info.bd_addr, bdaddr, sizeof(bdaddr_t));
    dtun_client_call_method(&method);
}

static void dtun_hl_channel_release_cmd(int cmd, char *app_path, bdaddr_t* bdaddr, uint16_t mdl_id)
{
    tDTUN_DEVICE_METHOD method;
    debug( "cmd:%d ", cmd);
    memset(&method.hl_channel_release, 0, sizeof method.hl_channel_release);
    method.hl_channel_release.hdr.id = DTUN_METHOD_HL_CHANNEL_RELEASE;
    method.hl_channel_release.hdr.len = sizeof(method.hl_channel_release.info);
    strncpy(method.hl_channel_release.info.app_path, app_path, sizeof(method.hl_channel_release.info.app_path)-1);
    method.hl_channel_release.info.app_path[sizeof(method.hl_channel_release.info.app_path)-1] = '\0';
    method.hl_channel_release.info.mdl_id = mdl_id;
    memcpy(&method.hl_channel_release.info.bd_addr, bdaddr, sizeof(bdaddr_t));
    dtun_client_call_method(&method);
}




