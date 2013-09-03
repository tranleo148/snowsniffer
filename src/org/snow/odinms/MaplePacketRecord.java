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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;

import jpcap.packet.TCPPacket;

/**
 *
 * @author Raz
 */
public class MaplePacketRecord {

    private int id;
    private TCPPacket packet;
    private long counter;
    private Date time;
    private String direction;
    private String header;
    private int opcode;
    private byte[] packetData;
    private boolean send;
    private boolean dataRecord = true;
    protected static long count = 0;
    protected static List<MaplePacketRecord> records = new ArrayList<MaplePacketRecord>();

    public MaplePacketRecord() {
	this.id = records.size();
	records.add(this);
    }

    public static List<MaplePacketRecord> getRecords() {
	return records;
    }

    public static MaplePacketRecord getById(int id) {
	return records.get(id);
    }

    public static void setRecords(List<MaplePacketRecord> records) {
	MaplePacketRecord.records = records;
    }

    public int getId() {
	return id;
    }

    public void setId(int id) {
	this.id = id;
    }

    public static long getCountAndAdd() {
	count++;
	return count;
    }

    public static void setCount(int newCount) {
	count = newCount;
    }

    public long getCounter() {
	return counter;
    }

    public void setCounter(long counter) {
	this.counter = counter;
    }

    public String getDirection() {
	return direction;
    }

    public void setDirection(String direction) {
	this.direction = direction;
    }

    public String getHeader() {
	return header;
    }

    public void setHeader(String header) {
	this.header = header;
    }

    public Date getTime() {
	return time;
    }

    public void setTime(Date time) {
	this.time = time;
    }

    public String getTimeToString() {
	return new SimpleDateFormat("HH:mm:ss.SSS").format(getTime());
    }

    public byte[] getPacketData() {
	return packetData;
    }

    public void setPacketData(byte[] packetData) {
	this.packetData = packetData;
    }

    public TCPPacket getPacket() {
	return packet;
    }

    public void setPacket(TCPPacket packet) {
	this.packet = packet;
    }

    public boolean isDataRecord() {
	return dataRecord;
    }

    public void setDataRecord(boolean dataRecord) {
	this.dataRecord = dataRecord;
    }

    public int getOpcode() {
	return opcode;
    }

    public void setOpcode(int opcode) {
	this.opcode = opcode;
    }

    public String getOpcodeHex(boolean includePrefix) {
	return (includePrefix ? "0x" : "") + StringUtil.getLeftPaddedStr(Integer.toHexString(opcode).toUpperCase(), '0', 4);
    }

    public boolean isSend() {
	return send;
    }

    public void setSend(boolean send) {
	this.send = send;
    }

    public TreeModel getTreeModel() {
	DefaultMutableTreeNode root = new DefaultMutableTreeNode("Packet");
	root.add(new DefaultMutableTreeNode("PacketType: TCP"));
	root.add(new DefaultMutableTreeNode("Length: " + packetData.length));
	root.add(new DefaultMutableTreeNode("Date: " + getTimeToString()));
	root.add(new DefaultMutableTreeNode("Opcode: " + getOpcodeHex(true)));
	root.add(new DefaultMutableTreeNode("Header-Desc: " + getHeader()));
	DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode("Network-Data");
	root.add(ipNode);
	ipNode.add(new DefaultMutableTreeNode("Src-IP: " + getPacket().src_ip.toString().substring(1)));
	ipNode.add(new DefaultMutableTreeNode("Src-Port: " + getPacket().src_port));
	ipNode.add(new DefaultMutableTreeNode("Dst-IP: " + getPacket().dst_ip.toString().substring(1)));
	ipNode.add(new DefaultMutableTreeNode("Dst-Port: " + getPacket().dst_port));
	ipNode.add(new DefaultMutableTreeNode("Sec: " + getPacket().sec));
	ipNode.add(new DefaultMutableTreeNode("USec: " + getPacket().usec));
	return new DefaultTreeModel(root);
    }

    public Object[] getRowData() {
	Object[] rowData = new Object[6];
	rowData[0] = getCounter();
	rowData[1] = getTimeToString();
	rowData[2] = getDirection();
	rowData[3] = getOpcodeHex(true);
	rowData[4] = getHeader();
	rowData[5] = getPacketData().length;
	return rowData;
    }

    public List<Object[]> getHexRowData() {
	List<Object[]> ret = new ArrayList<Object[]>();
	byte[] buffer = getPacketData();
	int offset = 0;
	while (buffer.length > 15) {
	    byte[] rowBuffer = new byte[16];
	    System.arraycopy(buffer, offset, rowBuffer, 0, 16);
	    Object[] row = new Object[3];
	    row[0] = StringUtil.getLeftPaddedStr(Integer.toHexString(offset).toUpperCase(), '0', 8);
	    row[1] = HexTool.toString(rowBuffer);
	    row[2] = HexTool.toStringFromAscii(rowBuffer);
	    offset += 16;
	}
	return ret;
    }
}
