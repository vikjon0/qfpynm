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
#

import dbus

def path_to_value(path):
    return dbus.ByteArray("file://" + path + "\0")

s_ip4 = dbus.Dictionary({'method': 'auto'})


s_con = { 'id': 'XXX', 'uuid': '5ef2d781-1197-44eb-8744-cd78b9c07315', 'type': '802-11-wireless', 'autoconnect': False, 'name': 'connection' }

s_wifi = { 'ssid': dbus.ByteArray("1969c"), 'mode': 'infrastructure', 'security': '802-11-wireless-security', 'name': '802-11-wireless' } 

s_wsec = { 'key-mgmt': 'wpa-psk', 'wpa-key': '19841129anna', 'name': '802-11-wireless-security' } 

s_ip4 = { 'method': 'auto', 'name': 'ipv4' } 

con = { 'connection': s_con, '802-11-wireless': s_wifi, '802-11-wireless-security': s_wsec, 'ipv4': s_ip4 } 



bus = dbus.SystemBus()

proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")

settings.AddConnection(con)

