/************************************************************************************
 *
 *  Copyright (C) 2009-2011 Broadcom Corporation
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
#ifndef _dtun_hl_H
#define _dtun_hl_H

int hl_dbus_init (DBusConnection *_conn);
void hl_dbus_exit (void);
void dtun_sig_hl_app_create(tDTUN_DEVICE_SIGNAL *p_data);
void dtun_sig_hl_app_destroy(tDTUN_DEVICE_SIGNAL *p_data);
void dtun_sig_hl_channel_create(tDTUN_DEVICE_SIGNAL *p_data);
void dtun_sig_hl_channel_destroy(tDTUN_DEVICE_SIGNAL *p_data);
void dtun_sig_hl_channel_acquire(tDTUN_DEVICE_SIGNAL *p_data);
void dtun_sig_hl_channel_release(tDTUN_DEVICE_SIGNAL *p_data);
void dtun_sig_hl_channel_connected(tDTUN_DEVICE_SIGNAL *p_data);
//void dtun_sig_pan_state_changed(tDTUN_DEVICE_SIGNAL *p_data);
#endif 
