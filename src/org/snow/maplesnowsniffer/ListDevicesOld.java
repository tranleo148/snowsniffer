/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc> 
                       Matthias Butz <matze@odinms.de>
                       Jan Christian Meyer <vimes@odinms.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation. You may not use, modify
    or distribute this program under any other version of the
    GNU Affero General Public License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


package org.snow.maplesnowsniffer;

import java.io.IOException;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;

public class ListDevicesOld {

    private static NetworkInterface[] devices = JpcapCaptor.getDeviceList();

    public static void main(String args[]) throws IOException {

	System.out.println("Snow's Packet Sniff Device Lister\r\n");

	for (int i = 0; i < devices.length; i++) {
	    System.out.println(i + ": " + devices[i].description + ")");
	    for (NetworkInterfaceAddress a : devices[i].addresses) {
			System.out.println(a.address.toString().substring(1));
	    }
	    System.out.println("\n");
	}
    }
}*/
