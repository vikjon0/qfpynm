#!/usr/bin/env python
#
#    #######################################################################
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#    MA 02110-1301, USA.

#    Author VIKJON0  https://github.com/vikjon0/qfpynm

#    ########################################################################
#    Reference documentation
#    Network Manager dbus doc:
#    http://projects.gnome.org/NetworkManager/developers/api/09/spec.html#org.freedesktop.NetworkManager

#    examples
#    http://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/examples/python

#TODO disconnect connection instead of the device?
#TODO Make sure to add logic for WEP & None in change password
#TODO Reverse the list puting strongest first
#TODO What if more than one wifi card exists? list devices and select which one we mean
#TODO catch errors on the dbus actions..including the import. Test with nm not installed etc.
#TODO Check if the ssid is already added, if so just activate it and set to auto / or new name
#TODO Test to connect to WEP & None (and all different router settings)
#TODO Monitor state, what if wrong pwd etc. example/nm-state only detects not active,activating - active
#TODO Display status as the applet tool tip
#TODO Test state when switching from one wifi to another. make sure no delay from state 100 on old
#TODO Create/find a soft system for getting and setting properties in the connecton settings

#Longer term
#TODO Add detection of group/enterprise encryption
#TODO Add IPv6
#TODO Add handling of static IP
#TODO Add wired and 3G connections
#TODO Change it all into a class?

#########################################################
#    Limitations: 
#    One wifi card only (?)
#    Only wifi for now
#    only ipv4
#    Only dhcp
#    Only WPA connections
#    Does not display enterprise/group enncryptions

import dbus
import uuid

bus = dbus.SystemBus()

# Get a proxy and an interface for the base NetworkManager object
proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
manager = dbus.Interface(proxy, "org.freedesktop.NetworkManager")
#New
nm_proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
nm_iface = dbus.Interface(proxy, "org.freedesktop.NetworkManager")
    
nm_properties = dbus.Interface(nm_proxy, "org.freedesktop.DBus.Properties")
nm_settings_proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
nm_settings_iface = dbus.Interface(nm_settings_proxy, "org.freedesktop.NetworkManager.Settings")

def get_all_active_con():
    #Return a dict with uuid as key and id as value

    active_con_dict = {}
    
    active_con_paths = nm_properties.Get("org.freedesktop.NetworkManager", "ActiveConnections")
    #NB: This returns connection.active paths not the usual settings.connection paths
    #    The variable con refers to setting_con

    for active_con_path in active_con_paths:
        active_con_proxy = bus.get_object("org.freedesktop.NetworkManager", active_con_path)

        active_con_props = dbus.Interface(active_con_proxy, "org.freedesktop.DBus.Properties")
        uuid = active_con_props.Get("org.freedesktop.NetworkManager.Connection.Active", "Uuid")
    
        # Grab the connection object path so we can get all the connection's settings
        con_path = active_con_props.Get("org.freedesktop.NetworkManager.Connection.Active", "Connection")
 
        con_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
        con_iface = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")

        settings = con_iface.GetSettings()    
        active_con_dict[uuid] = settings['connection']['id']
        
    return active_con_dict
    
def get_con_uuid_by_path(con_path):
        con_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
        con_iface = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
        
        settings = con_iface.GetSettings()    
        return settings['connection']['uuid']

def get_connections():
    # Ask the settings service for the list of connections it provides
    connection_paths = nm_settings_iface.ListConnections()
    connection_list = []
    
    for con_path in connection_paths:
        con_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
        con_iface = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
        config = con_iface.GetSettings()

        connection_type =  config['connection']['type'] 
        if connection_type == '802-11-wireless':
            connection_dict = {}
    
            uuid = config['connection']['uuid']
            connection_dict['uuid'] = uuid
            connection_dict['id'] = config['connection']['id']
            
            active_connections = get_all_active_con()
           
            if uuid in active_connections:
                active = True
            else:
                active = False
                
            connection_dict['active'] = active
            connection_dict['ssid'] = essid_ssid(config['802-11-wireless']['ssid'])
 
            #autoconnect property only seem to exist if off (0)
            if 'autoconnect' in config['connection']:
                connection_dict['auto'] = config['connection']['autoconnect']
            else:
                connection_dict['auto'] = 1
                
            connection_list.append(connection_dict)
                    
    return (connection_list)
        
def print_connections():
    print 'SSID\t\tactive\tauto\tUUID\t\t\t\t\tID'
    
    connection_list = get_connections()
    for connection_dict in connection_list:
        if connection_dict['active']== True:
            active = "a"
        else:
            active = ""
        
        print '%s\t\t%s\t%s\t%s\t%s\t\t%s' % (connection_dict['ssid'],
            active,
            connection_dict['auto'],
            connection_dict['uuid'],
            connection_dict['id'],
            "")
        
def get_wifi_device():
    #Assuming only one exists
    #Returns device path
    
    # Get all network devices (list of device paths)
    devices = nm_iface.GetDevices()
    for d_path in devices:
        dev_proxy = bus.get_object("org.freedesktop.NetworkManager", d_path )
        dev_prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

        # Make sure the device is enabled before we try to use it
        state = dev_prop_iface.Get("org.freedesktop.NetworkManager.Device", "State")
        if state <= 2:
            continue

        # Get device's type; we only want wifi devices
        #iface = prop_iface.Get("org.freedesktop.NetworkManager.Device", "Interface")
        dtype = dev_prop_iface.Get("org.freedesktop.NetworkManager.Device", "DeviceType")
        if dtype == 2:   # WiFi
            return d_path 
            break
        
def get_all_access_points():
    #Returns list of AP paths    
    #Make use of get wifi d to make this more simple

    # Get the wifi device
    device = get_wifi_device()
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", device)
    dev_iface = dbus.Interface(dev_proxy, "org.freedesktop.NetworkManager.Device.Wireless")
    dev_prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

    # Get the associated AP's object path (connected AP)
    connected_path = dev_prop_iface.Get("org.freedesktop.NetworkManager.Device.Wireless", "ActiveAccessPoint")

    # Get all APs the card can see
    aps = dev_iface.GetAccessPoints()

    return aps, connected_path
    

def get_wireless_networks():
    wlessL = []
    aps, connected_path = get_all_access_points()

    # Loop the available wireless networks
    for ap_path in aps:
        net_dict = {}

        ap_proxy = bus.get_object("org.freedesktop.NetworkManager", ap_path)
        ap_prop_iface = dbus.Interface(ap_proxy, "org.freedesktop.DBus.Properties")

        net_dict['network_id'] = ""
        connected  = ap_path == connected_path
        net_dict['connected'] = connected
        net_dict['bssid'] = ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "HwAddress")
        net_dict['essid'] = essid_ssid(ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "Ssid"))
        net_dict['signal'] = int(ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "Strength"))
        net_dict['automatic'] = False
        
        WpaFlags = bitmask_str(NM_802_11_AP_SEC,ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "WpaFlags"))
        RsnFlags = bitmask_str(NM_802_11_AP_SEC,ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "RsnFlags"))
        Flags = bitmask_str(NM_802_11_AP_FLAGS,ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "Flags"))
        net_dict['mode']= IW_MODE[ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "Mode")]
        net_dict['channel'] = (int(ap_prop_iface.Get("org.freedesktop.NetworkManager.AccessPoint", "Frequency"))-2407)/5
        net_dict['automatic'] = ""

        net_dict['encrypt']= get_encryption(Flags, WpaFlags, RsnFlags)

        wlessL.append(net_dict)
        
    return (wlessL)

def print_wireless():
    print '#\tBSSID\t\tChnl\tSts\tESSID\t\tenctype'
    
    wlessL = get_wireless_networks()
    for net_dict in wlessL:
        if net_dict['connected']== True:
            sts = "c"
        else:
            sts = ""
        
        #print net_dict['essid'] +  net_dict['channel'] +  net_dict['encrypt'] + net_dict['signal']
        print '%s\t%s\t%s\t%s\t%s\t\t%s' % (net_dict['network_id'],
            net_dict['bssid'],
            net_dict['channel'],
            sts,
            net_dict['essid'],
            net_dict['encrypt'])

def get_device_state(dev_path):
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", dev_path)
    dev_prop_iface = dbus.Interface(dev_proxy, "org.freedesktop.DBus.Properties")

    state = dev_prop_iface.Get("org.freedesktop.NetworkManager.Device", "State")
    return state, nm_device_state[state]
    
def deactive_wifi():
    # Get the wifi device
    dev = get_wifi_device()
    dev_proxy = bus.get_object("org.freedesktop.NetworkManager", dev)

    dev_iface = dbus.Interface(dev_proxy, "org.freedesktop.NetworkManager.Device")
    dev_iface.Disconnect()
            
def activate_connection(uuid):
    # Now ask NM to activate that connection
    con_path = nm_settings_iface.GetConnectionByUuid(uuid)
    dev_path = get_wifi_device()
    
    #active_path = nm_iface.ActivateConnection(con_path, dev_path, "/")    
    nm_iface.ActivateConnection(con_path, dev_path, "/")


def deactivate_connection(uuid):
    active_connections = get_all_active_con()
           
    if uuid in active_connections:
        con_path = nm_settings_iface.GetConnectionByUuid(uuid)   
        nm_iface.DeactivateConnection(con_path)


def delete_connection(uuid):  
    con_path = nm_settings_iface.GetConnectionByUuid(uuid)
    con_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
    con_iface = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
        
    con_iface.Delete()

def create_wifi_config(uuid,ssid,akey):
    s_con = { 'id': ssid, 'uuid': uuid, 'type': '802-11-wireless', 'autoconnect': True, 'name': 'connection' }
    s_wifi = { 'ssid': dbus.ByteArray(ssid), 'mode': 'infrastructure', 'security': '802-11-wireless-security', 'name': '802-11-wireless' } 
    s_ip4 = { 'method': 'auto', 'name': 'ipv4' } 
    s_ip6 = { 'method': 'ignore', 'name': 'ipv6' } 
    
    encryption = "WPA"
    wep_alg = 'shared'
    
    if (encryption == "WPA"):
        s_wsec = { 'key-mgmt': 'wpa-psk', 'psk': akey, 'name': '802-11-wireless-security' } 
    elif (encryption == "WEP"):
        if wep_alg == 'shared':
            s_wsec = { 'key-mgmt': 'none', 'wep-key0': akey, 'auth-alg': 'shared', 'name': '802-11-wireless-security' }
        else:
            s_wsec = { 'key-mgmt': 'none', 'wep-key0': akey, 'name': '802-11-wireless-security' }
    else:
        s_wsec = {'name': '802-11-wireless-security' }
    
    config = { 'connection': s_con, '802-11-wireless': s_wifi, '802-11-wireless-security': s_wsec, 'ipv4': s_ip4,'ipv6': s_ip6 }    
    return config

def add_wifi(ssid,akey):
    config = create_wifi_config(str(uuid.uuid1()),ssid,akey)
    con_path =  nm_settings_iface.AddConnection(config)
    activate_connection(get_con_uuid_by_path(con_path))

    return con_path
   
    
def update_wifi(uuid,akey):
    #Add logic to use the correct key for encryption key depending on encryption type

    con_path = nm_settings_iface.GetConnectionByUuid(uuid)

    con_proxy = bus.get_object("org.freedesktop.NetworkManager", con_path)
    con_iface = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
    config = con_iface.GetSettings()

    #Change ssid
    #config['802-11-wireless'] = { 'ssid': dbus.ByteArray(ssid), 'mode': 'infrastructure', 'security': '802-11-wireless-security', 'name': '802-11-wireless' } 

    #Chnage password
    #config['802-11-wireless-security'] = { 'key-mgmt': 'wpa-psk', 'psk': akey, 'name': '802-11-wireless-security' } 
    config['802-11-wireless-security']['psk'] = akey
 
    # Change the connection with Update()
    con_iface.Update(config)


def validate_wifi_input(akey, enc_type):
    errors = ''
    if enc_type == 'WEP' and len(akey) != 10 and len(akey) != 26:
        errors = 'WEP hex-key len should be 10 (64 bits) or 26 (128 bits)'
    if enc_type == 'WPA' and len(akey) < 7:
        errors = 'WPA hex-key len should be minimum 7 characters'
    return errors


def get_encryption(flags, wpa_flags, rsn_flags):
    encryption_string = ""
    if (flags == "" and wpa_flags == "" and rsn_flags == ""): 
        encryption_string = "NONE"
    elif (flags != "" and wpa_flags == "" and rsn_flags == ""): 
            encryption_string = "WEP"   
    else:
        if (flags != "" and wpa_flags != ""):
            encryption_string = "WPA" 
        if (flags != "" and rsn_flags != ""):
            if encryption_string == "":
                encryption_string = "WPA2"
            else:
                encryption_string = encryption_string + "/WPA2"
            
    #Enterprise or group encryption not supported
    # Fromm nmcli (where above code is found)
    #if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)      
    #	    || (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X))
    #		g_string_append (security_str, _("Enterprise "));
    # Looks like all we have to do it so to check for this key in the flags: "512: "KEY_MGMT_802_1X""
    # Group I do not know what it is and nmcli does not seem to handle it it
            
    return encryption_string

def essid_ssid( ssid ):
    essid = ''
    for byte in ssid:
        essid+=chr(byte)
    return essid

def bitmask_str(map_input, value):
    ret = []
    for mask, s in map_input.iteritems():
        if value & mask: ret.append(s)
    return ",".join(ret)

NM_802_11_AP_SEC = {
    1: "PAIR_WEP40", 2: "PAIR_WEP104", 4: "PAIR_TKIP", 8: "PAIR_CCMP",
    16: "GROUP_WEP40", 32: "GROUP_WEP104", 64: "GROUP_TKIP",
    128: "GROUP_CCMP", 256: "KEY_MGMT_PSK", 512: "KEY_MGMT_802_1X",}

NM_802_11_AP_FLAGS = {1: "PRIVACY",}

IW_MODE = ["AUTO", "ADHOC", "INFRA", "MASTER", "REPEAT", "SECOND", "MONITOR",]



# NM Device States
nm_device_state = { 0: "Unknown",
           10: "Unmanaged",
           20: "Unavailable",
           30: "Disconnected",
           40: "Prepare",
           50: "Configuring",
           60: "Need Auth",
           70: "IP Config",
           80: "IP Check",
           90: "Secondaries",
           100: "Activated",
           110: "Deactivating",
           120: "Failed" }


########################################################################

if __name__ == '__main__':
    print "This is just for testing the toolkit...."
    print "0 Quit"
    print "1 List Wireless networks"
    print "2 Connect to wireless network (WPA only)"
    print "3 List connections (wifi)"
    print "4 Disconnect (wifi)"
    print "5 Remove connection"
    print "6 activate connection"
    print "7 Device state"
    print "8 Chnage pwd on WPA connection by UUID"
    
    aSelect = raw_input('Please enter a value:')

    if aSelect == "1":
        #listAP()
        print_wireless()

    if aSelect == "2":
        aNetwork_id = (raw_input('Enter network SSID :'))
        akey = raw_input("Enter the encryption key:")
        errors = validate_wifi_input(akey,'WPA')
        if not errors == '':
            print (errors)
            1/0
        acon_path = add_wifi(aNetwork_id, akey)
        import time
        for i in range(1, 150):
            state,stateTXT = get_device_state(get_wifi_device())
            print(str(state) +'-' + stateTXT) 
            # Do not exit directly just to be sure.
            # If trying with a bad key when wifi is disconnected do not give state 60 but 30....
            # better never to disconnect wifi and only deactivate c
            if (i > 10 and state == 60) or (i > 10 and state == 30)  or (state == 100 and i >2):
                break
            time.sleep(1)
        if state == 100:
            print "Connected!"

        elif state == 60  or state == 30:
            print "bad key?"
            aUUID = get_con_uuid_by_path(acon_path)
            #is deactive/activate really the best way?
            deactivate_connection(aUUID)
            akey = raw_input("Enter the encryption key:")
            update_wifi(aUUID, akey)
            activate_connection(aUUID)
            for i in range(1, 150):
                state,stateTXT = get_device_state(get_wifi_device())
                print(str(state) +'-' + stateTXT) 
                # Do not exit directly just to be sure.
                if (i > 10 and state == 60) or (state == 100 and i >2):
                    break
                time.sleep(1)
            if state == 100:
                print "Connected!"
            elif state == 60:
                print "bad key, no more tries!!!"

    if aSelect == "3":
        print_connections()

    if aSelect == "4":
        deactive_wifi()
        
    if aSelect == "5":
        aUUID =  (raw_input('Enter UUID:'))
        delete_connection(aUUID)

    if aSelect == "6":
        aUUID =  (raw_input('Enter UUID:'))
        activate_connection(aUUID)
        
    if aSelect == "7":
            import time
            for i in range(1, 150):
                state,stateTXT = get_device_state(get_wifi_device())
                print(str(state) +'-' + stateTXT) 
                #print (i)   
                time.sleep(1)
                
    if aSelect == "8":
            aUUID =  (raw_input('Enter UUID:'))
            akey = raw_input("Enter the encryption key:")
            update_wifi(aUUID,akey)
            #e51322cc-56ca-490a-9308-f2c7c3e573c6


