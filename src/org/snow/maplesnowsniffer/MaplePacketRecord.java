package org.snow.maplesnowsniffer;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import org.jnetpcap.packet.PcapPacket;
import org.snow.odinms.HexTool;
import org.snow.odinms.StringUtil;

/**
 *
 * @author Raz
 */
public class MaplePacketRecord {

    private int id;
    private PcapPacket packet;
    private long counter;
    private Date time;
    private String direction;
    private String header;
    private int opcode;
    private byte[] packetData;
    private String[] treeData;
    private boolean send;
    private boolean dataRecord = true;
    private boolean loadFromFile = false;
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

    public PcapPacket getPacket() {
	return packet;
    }

    public void setPacket(PcapPacket packet) {
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
    
    public void setLoadFromFile(boolean load) {
        this.loadFromFile = load;
    }

    public TreeModel getTreeModel() {
	DefaultMutableTreeNode root = new DefaultMutableTreeNode("Packet");
	root.add(new DefaultMutableTreeNode("PacketType: TCP"));
	root.add(new DefaultMutableTreeNode("Length: " + packetData.length));
	root.add(new DefaultMutableTreeNode("Date: " + getTimeToString()));
	root.add(new DefaultMutableTreeNode("Opcode: " + getOpcodeHex(true)));
	root.add(new DefaultMutableTreeNode("Header-Desc: " + getHeader()));
	/*DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode("Network-Data");
	root.add(ipNode);
        if (loadFromFile) {
        ipNode.add(new DefaultMutableTreeNode("Src-IP: " + treeData[0].toString().substring(1)));
	ipNode.add(new DefaultMutableTreeNode("Src-Port: " + treeData[1]));
	ipNode.add(new DefaultMutableTreeNode("Dst-IP: " + treeData[2].toString().substring(1)));
	ipNode.add(new DefaultMutableTreeNode("Dst-Port: " + treeData[3]));
	ipNode.add(new DefaultMutableTreeNode("Sec: " + treeData[4]));
	ipNode.add(new DefaultMutableTreeNode("USec: " + treeData[5]));
        } else {
	ipNode.add(new DefaultMutableTreeNode("Src-IP: " + getPacket().src_ip.toString().substring(1)));
	ipNode.add(new DefaultMutableTreeNode("Src-Port: " + getPacket().src_port));
	ipNode.add(new DefaultMutableTreeNode("Dst-IP: " + getPacket().dst_ip.toString().substring(1)));
	ipNode.add(new DefaultMutableTreeNode("Dst-Port: " + getPacket().dst_port));
	ipNode.add(new DefaultMutableTreeNode("Sec: " + getPacket().sec));
	ipNode.add(new DefaultMutableTreeNode("USec: " + getPacket().usec));
        }*/
	return new DefaultTreeModel(root);
    }
    
    public void setTreeData(String[] data) {
        this.treeData = data;
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
