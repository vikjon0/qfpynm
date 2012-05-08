#!/usr/bin/env python
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2011 Red Hat, Inc.
#

#
# The example shows how to update secrets in a connection by means of D-Bus
# Update() method. The method replaces all previous settings with new ones
# including possible secrets.
# So, we get all settings using GetSettings() and then find out what secrets
# are associated with the connection using GetSecrets(), ask for new secret 
# values, and add them to the settings that we pass to Update().
#

import dbus
import sys

bus = dbus.SystemBus()



aproxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
asettings = dbus.Interface(aproxy, "org.freedesktop.NetworkManager.Settings")
con_path = asettings.GetConnectionByUuid('e51322cc-56ca-490a-9308-f2c7c3e573c6')

acon_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
aconnection = dbus.Interface(acon_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
config = aconnection.GetSettings()


config['802-11-wireless'] = { 'ssid': dbus.ByteArray('kalle2'), 'mode': 'infrastructure', 'security': '802-11-wireless-security', 'name': '802-11-wireless' } 
config['802-11-wireless-security'] = { 'key-mgmt': 'wpa-psk', 'psk': '19841139kalle', 'name': '802-11-wireless-security' } 

# Change the connection with Update()
proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings.Connection")
settings.Update(config)
print("made it")

