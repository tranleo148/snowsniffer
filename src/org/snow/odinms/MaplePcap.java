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
*/
package org.snow.odinms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

//Decode From File(*.pcap)
public class MaplePcap implements PacketReceiver {

    private MapleAESOFB send;
    private MapleAESOFB recv;
    private ByteArrayOutputStream toClient;
    private ByteArrayOutputStream toServer;
    private int toClientPos = 0;
    private int toServerPos = 0;
    private InetAddress ipclient = null;
    private InetAddress ipserver = null;

    public MaplePcap(InetAddress srcIp) {
	this.ipclient = srcIp;
    }

    public static void main(String args[]) throws IOException {
	if (args.length != 2 && args.length != 1) {
	    System.out.println("Usage: MaplePcap pcapfile [sourceip]");
	} else {
	    JpcapCaptor captor = JpcapCaptor.openFile(args[0]);

	    try {
		InetAddress srcIp = null;
		if (args.length == 2) {
		    srcIp = InetAddress.getByName(args[1]);
		}
		captor.loopPacket(-1, new MaplePcap(srcIp));
	    } catch (UnknownHostException e) {
		e.printStackTrace();
	    }
	}
    }

    @Override
    public void receivePacket(Packet arg0) {
	if (arg0 instanceof TCPPacket) {
	    TCPPacket packet = (TCPPacket) arg0;
	    if (packet.data.length == 15 && packet.data[0] == 0x0d && packet.data[1] == 0) {
		System.out.println("Detected start of maple crypto... (from " + packet.src_ip + ")");
		short version = (short) (((int) packet.data[2] & 0xFF) | (((int) packet.data[3] << 8) & 0xFF00));
		System.out.println("Maple version " + version);
		byte ivsend[] = new byte[4];
		byte ivrecv[] = new byte[4];
		System.arraycopy(packet.data, 10, ivrecv, 0, 4);
		System.arraycopy(packet.data, 6, ivsend, 0, 4);

		send = new MapleAESOFB(MapleAESOFB.MAPLE_AES_KEY, ivsend, version);
		recv = new MapleAESOFB(MapleAESOFB.MAPLE_AES_KEY, ivrecv, (short) (0xFFFF - version));
		ipserver = packet.src_ip;
		if (ipclient == null) {
		    ipclient = packet.dst_ip;
		}
		toClient = new ByteArrayOutputStream();
		toServer = new ByteArrayOutputStream();
		toClientPos = 0;
		toServerPos = 0;
	    } else {
		if (send != null && (packet.src_ip.equals(ipserver) || packet.dst_ip.equals(ipserver))) {

		    if (packet.src_ip.equals(ipserver) && (packet.dst_ip.equals(ipclient) || ipclient == null)) {
			try {
			    toClient.write(packet.data);
			} catch (IOException e) {
			    e.printStackTrace();
			}
			int ret = 0;
			do {
			    byte[] toClientArr = toClient.toByteArray();
			    ret = handleData(toClientArr, toClientPos, recv, packet, false);
			    toClientPos += ret;
			} while (ret != 0);
		    } else if ((packet.src_ip.equals(ipclient) || ipclient == null) && packet.dst_ip.equals(ipserver)) {
			try {
			    toServer.write(packet.data);
			} catch (IOException e) {
			    e.printStackTrace();
			}
			int ret = 0;
			do {
			    byte[] toServerArr = toServer.toByteArray();
			    ret = handleData(toServerArr, toServerPos, send, packet, true);
			    toServerPos += ret;
			} while (ret != 0);
		    }
		}
	    }
	}
    }

    private String lookupRecv(int val) {
	for (RecvPacketOpcode op : RecvPacketOpcode.values()) {
	    if (op.getValue() == val) {
		return op.name();
	    }
	}
	return "UNKNOWN";
    }

    private String lookupSend(int val) {
	for (SendPacketOpcode op : SendPacketOpcode.values()) {
	    if (op.getValue() == val) {
		return op.name();
	    }
	}
	return "UNKNOWN";
    }

    private int readFirstShort(byte[] arr) {
	return new GenericLittleEndianAccessor(new ByteArrayByteStream(arr)).readShort();
    }

    private int handleData(byte[] data, int skip, MapleAESOFB crypto, TCPPacket packet, boolean send) {
	if (data.length < skip + 4) {
	    return 0;
	}
	ByteArrayInputStream bais = new ByteArrayInputStream(data);
	DataInputStream dis = new DataInputStream(bais);
	try {
	    dis.skip(skip);
	} catch (IOException e1) {
	    e1.printStackTrace();
	}
	byte[] header = new byte[4];
	try {
	    dis.readFully(header);
	} catch (IOException e) {
	    e.printStackTrace();
	// I don't know why the exception happens but it doesn't really matter o.o"
	}
	if (crypto.checkPacket(header)) {
	    int packetLen = (((int) (header[0] ^ header[2]) & 0xFF) | (((int) (header[1] ^ header[3]) << 8) & 0xFF00));
	    try {
		if (dis.available() >= packetLen) {
		    byte ddata[] = new byte[packetLen];
		    dis.readFully(ddata);
		    byte unc[] = new byte[ddata.length];
		    System.arraycopy(ddata, 0, unc, 0, ddata.length);
		    crypto.crypt(ddata);
		    MapleCustomEncryption.decryptData(ddata);
		    String op;
		    int pHeader = readFirstShort(ddata);
		    String pHeaderStr = Integer.toHexString(pHeader).toUpperCase();
		    pHeaderStr = StringUtil.getLeftPaddedStr(pHeaderStr, '0', 2);
		    if (send) {
			op = lookupRecv(pHeader);
		    } else {
			op = lookupSend(pHeader);
		    }
		    String start = send ? "Sent " : "Received ";

		    System.out.println(start + op + " [" + pHeaderStr + "] (" + packetLen + ") ");
		    System.out.println(HexTool.toString(ddata));
		    System.out.println(HexTool.toStringFromAscii(ddata));
		    System.out.println();
		    return packetLen + 4;
		}
	    } catch (IOException e) {
		e.printStackTrace();
	    }
	} else {
	    //System.out.println("check packet failed");
	    return 4; // consume the header and hope that it was a retransmission o.o
	}
	return 0;
    }
}


