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

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Scanner;

import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import org.snow.odinms.MapleServer.MapleServerType;

public class MaplePcapture implements PacketReceiver {

	private MapleAESOFB send;
	private MapleAESOFB recv;
	private ByteArrayOutputStream toClient;
	private ByteArrayOutputStream toServer;
	private int toClientPos = 0;
	private int toServerPos = 0;
	private InetAddress ipclient = null;
	private InetAddress ipserver = null;
	private boolean logging = false;
	private BufferedWriter logStream = null;
	private CaptureType capType;
	private NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	private JpcapCaptor captor;
	private List<MaplePacketRecord> packetRecords = new ArrayList<MaplePacketRecord>();
	private String logFilename;
	private boolean appendLogStream;
	private String currentWriterName = null;
	private boolean addedPrevEntries = false;
	private Properties settings = new Properties();
	private PropertyTool propTool = new PropertyTool(new Properties());
	private Scanner in = new Scanner(System.in);
	private MaplePcaptureGUI packetGUI;
	private boolean useGUI = true;
	private static MaplePcapture instance = new MaplePcapture();
	private static List<Integer> storedShops = new ArrayList<Integer>();
	private ServerOutputType serverOutputType;
	private boolean showHex;
	private boolean showAscii;
	private Map<String, Boolean> blockedOpcodes = new HashMap<String, Boolean>();
	private boolean blockDefault;
	private int deviceIndex;
	private String packetFilter;

	private MaplePcapture() {
	}

	public static MaplePcapture getInstance() {
		return instance;
	}

	public static void main(String args[]) throws IOException {
		getInstance().doMain();
	}

	public void doMain() {
		System.out.print("Snow's Packet Sniffer");
		try {
		loadSettings();
		} catch (Exception e) {
			System.out.println("Error loading settings");
			e.printStackTrace();
		}

			try {
			captor = JpcapCaptor.openDevice(devices[deviceIndex], 65535, false, 20);
			captor.setFilter(packetFilter, true);
			if (useGUI) {
				packetGUI = new MaplePcaptureGUI();
				packetGUI.setCapture(this);
				packetGUI.setVisible(true);
			}
			captor.loopPacket(-1, this);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public boolean loadSettings() {

		try {
			FileInputStream fis = new FileInputStream("settings.properties");
			settings.load(fis);
			fis.close();
		} catch (IOException e) {
			System.out.println("Cannot find: settings.properties");
			return false;
		}
		propTool = new PropertyTool(settings);

		deviceIndex = propTool.getSettingInt("DEVICE", -1);
		if (deviceIndex == -1) {
			deviceIndex = listDevices(true);
			if (deviceIndex == -1) {
				throw new RuntimeException("Error: selecting device index");
			}
		}


		packetFilter = propTool.getSettingStr("FILTER", "");
		appendLogStream = propTool.getSettingInt("APPEND_LOG", 0) > 0;
		logFilename = propTool.getSettingStr("LOG_NAME", null);
		serverOutputType = ServerOutputType.getByName(propTool.getSettingStr("SERVER_TYPE", null));
		logStream = getNewWriter(logFilename, appendLogStream);
		logging = propTool.getSettingInt("LOGGING", 0) > 0;
		useGUI = propTool.getSettingInt("USE_GUI", 1) > 0;
		capType = CaptureType.getByName(propTool.getSettingStr("CAPTURE_TYPE", null));
		showHex = propTool.getSettingInt("SHOW_HEX", 1) > 0;
		showAscii = propTool.getSettingInt("SHOW_ASCII", 1) > 0;
		blockDefault = propTool.getSettingInt("BLOCK_DEF", 0) > 0;
		for(Entry<Object, Object> entry : settings.entrySet()) {
			String property = (String) entry.getKey();
			if (property.startsWith("S_") || property.startsWith("R_")) {
				blockedOpcodes.put(property, propTool.getSettingInt(property, 0) > 0);
			}
		}

		if (capType != CaptureType.PACKET) {
			useGUI = false;
		}
		System.out.println(" | " + serverOutputType.name() + " | " + capType.name());
		return true;
	}

	public int listDevices(boolean chooseNew) {
		for (int i = 0; i < devices.length; i++) {
			System.out.println(i + ": " + devices[i].description + ")");
			for (NetworkInterfaceAddress a : devices[i].addresses) {
				System.out.println(a.address);
			}
			System.out.println();
		}
		if (chooseNew) {
			try {
				System.out.print("Please select a new device: ");
				int newDeviceNum = in.nextInt();
				System.out.println("Device set to: " + newDeviceNum);
				System.out.println("Name: " + devices[newDeviceNum].description);
				for (NetworkInterfaceAddress a : devices[newDeviceNum].addresses) {
					System.out.println("IP: " + a.address);
				}
				settings.setProperty("DEVICE", Integer.toString(newDeviceNum));
				settings.store(new FileOutputStream("settings.properties"), null);
				return newDeviceNum;
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return -1;
	}

	@Override
	public void receivePacket(Packet recvPacket) {
		if (recvPacket instanceof TCPPacket) {
			TCPPacket packet = (TCPPacket) recvPacket;
			SeekableLittleEndianAccessor slea2 = new GenericSeekableLittleEndianAccessor(new ByteArrayByteStream(recvPacket.data));
			SeekableLittleEndianAccessor slea = new GenericSeekableLittleEndianAccessor(new ByteArrayByteStream(packet.data));
			if (slea.readShort() == slea.available()) {
				System.out.println("Detected Maple Crypto - " + packet.src_ip);
                                System.out.println("HELLO THERE! " + HexTool.toString(slea2.read((int)slea2.available())));
				short version = slea.readShort();
				String unknownParameter = slea.readMapleAsciiString();
				byte ivsend[] = slea.read(4);
				byte ivrecv[] = slea.read(4);

				MapleServerType serverType = MapleServerType.getByType(slea.readByte());
				String serverHooked = unknownParameter.length() == 1 ? "Login" : "Channel";
				if (useGUI) {
					//MaplePacketRecord.setCount(-1);
					MaplePacketRecord record = new MaplePacketRecord();
					record.setCounter(MaplePacketRecord.getCountAndAdd());
					record.setDataRecord(false);
					record.setDirection("<NONE>");
					record.setTime(Calendar.getInstance().getTime());
					record.setHeader("Maple Initiated(V" + version + ")");
					record.setOpcode(-1);
					record.setPacket(packet);
					record.setPacketData(new byte[0]);
					
					packetRecords.add(record);
					packetGUI.addRow(record);
					packetGUI.updateAndIncreasePacketTotal();
					packetGUI.setStatusText("Capturing: MapleStory(V" + version + ") | " + serverType.name() + " | " + serverHooked);
				}
				System.out.println("Maple Version " + version + "  | Maple Server " + serverType.name() + " | " + serverHooked);
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
							ret = handleData(toClientArr, toClientPos, recv, packet, false);//ToClient
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
							ret = handleData(toServerArr, toServerPos, send, packet, true);//ToServer
							toServerPos += ret;
						} while (ret != 0);
					}
				}
			}
		}
	}

	public void dumpToFile(String fileName) {
		//TODO: FIX ME
		try {
			JpcapWriter writer = JpcapWriter.openDumpFile(captor, fileName);
			for (MaplePacketRecord packetRecord : packetRecords) {
				Packet packet = packetRecord.getPacket();
				if (packet != null) {
					writer.writePacket(packet);
				}
			}
			writer.close();
		} catch (Exception e) {
			System.out.println("Error: Dumping packets to file");
			e.printStackTrace();
		}
	}

	public void outputWithLogging(String buff) {
		outputWithLogging(buff, true);
	}

	public void outputWithLogging(String buff, boolean toConsole) {
		if (toConsole) {
			System.out.println(buff);
		}

		if (logging) {
			try {
				logStream.write(buff + "\r\n");
				logStream.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private String lookupRecv(int val) {
		return RecvPacketOpcode.getByType(val).name();
	}

	private String lookupSend(int val) {
		return SendPacketOpcode.getByType(val).name();
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
			int packetLen = MapleAESOFB.getPacketLength(header);
			try {
				if (dis.available() >= packetLen) {
					byte ddata[] = new byte[packetLen];
					dis.readFully(ddata);
					byte unc[] = new byte[ddata.length];
					System.arraycopy(ddata, 0, unc, 0, ddata.length);
					crypto.crypt(ddata);
					MapleCustomEncryption.decryptData(ddata);
					SeekableLittleEndianAccessor slea = new GenericSeekableLittleEndianAccessor(new ByteArrayByteStream(ddata));
					String op;
					int pHeader = slea.readShort();

					String pHeaderStr = StringUtil.getLeftPaddedStr(Integer.toHexString(pHeader).toUpperCase(), '0', 4);
					op = send ? lookupRecv(pHeader) : lookupSend(pHeader);
					String start = send ? "Sent " : "Received ";
					String strStart = start.substring(0, 1);
					try {
						//FILTER PACKETS
						switch (capType) {
							case PACKET:
								boolean opcodeBlocked;
								if (op.equals("UNKNOWN")) {
									opcodeBlocked = blockedOpcodes.containsKey(strStart + "_" + pHeaderStr) ? blockedOpcodes.get(strStart + "_" + pHeaderStr) : blockDefault;
								} else {
									opcodeBlocked = blockedOpcodes.containsKey(strStart + "_" + op) ? blockedOpcodes.get(strStart + "_" + op) : blockDefault;
								}
								boolean blockAll = blockedOpcodes.containsKey(strStart + "_ALL") && blockedOpcodes.get(strStart + "_ALL");
								if (!blockAll && !opcodeBlocked) {
									outputWithLogging(start + op + " [" + pHeaderStr + "] (" + packetLen + ") ");
									if (useGUI) {
										MaplePacketRecord record = new MaplePacketRecord();
										record.setCounter(MaplePacketRecord.getCountAndAdd());
										record.setTime(new Date(packet.sec * 1000 + packet.usec / 1000));
										record.setDirection(send ? "ToServer" : "ToClient");
										record.setSend(send);
										record.setOpcode(pHeader);
										record.setHeader(op);
										record.setPacketData(ddata);
										record.setPacket(packet);
										record.setOpcode(pHeader);
										packetGUI.addRow(record);
										packetGUI.updateAndIncreasePacketTotal();
									}
									if (showHex) {
										outputWithLogging(HexTool.toString(ddata));
									}
									if (showAscii) {
										outputWithLogging(HexTool.toStringFromAscii(ddata));
									}
									outputWithLogging("");
								}
								break;
							case NPC:
								if (pHeader == SendPacketOpcode.NPC_TALK.getValue()) {
									addText(slea);
									System.out.println();
								}
								break;
							case SHOP:
								if (pHeader == SendPacketOpcode.OPEN_NPC_SHOP.getValue()) {
									addShopSqlQuery(slea);
									outputWithLogging("");
								}
								break;
                            case SPEED_QUIZ:
                                if (pHeader == SendPacketOpcode.NPC_TALK.getValue()) {
									addText(slea);//////////
									System.out.println();
								}
                                break;
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
					return packetLen + 4;
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			//outputWithLogging("Warning: Packet check failed");
			return 4; // consume the header and hope that it was a retransmission o.o
		}
		return 0;
	}

	public BufferedWriter getNewWriter(String name, boolean append) {
		BufferedWriter ret;
		try {
			File outputFile = new File(name);
			if (outputFile.getParentFile() != null) {
				outputFile.getParentFile().mkdir();
			}
			outputFile.createNewFile();
			currentWriterName = name;
			FileWriter outputFileWriter = new FileWriter(outputFile, append);
			ret = new BufferedWriter(outputFileWriter);
		} catch (Exception e) {
			logging = false;
			e.printStackTrace();
			ret = null;
		}
		return ret;
	}

	public void addText(SeekableLittleEndianAccessor slea) {
		byte[] bytes = new byte[4];
		bytes[0] = slea.readByte();
		int npcId = slea.readInt();
		logStream = getNewWriter("NPCS/" + npcId + ".txt", true);
		bytes[1] = slea.readByte();
		String talk = slea.readMapleAsciiString();
		if (slea.available() == 1) {
			bytes[2] = slea.readByte();
		} else if (slea.available() == 2) {
			bytes[2] = slea.readByte();
			bytes[3] = slea.readByte();
		}
		String prefix = "cm.sendUnknown";
		prefix = getNpcPrefix(HexTool.toString(bytes));
		outputWithLogging(prefix + "(" + talk + ");" + "\r\n");
	}

	public String getNpcPrefix(String bytes) {
		String prefix = null;
		if (bytes.equals("04 00 00 01")) {
			prefix = "cm.sendNext";
		} else if (bytes.equals("04 01 00 00")) {
			prefix = "cm.sendYesNo";
		} else if (bytes.equals("04 04 00 00")) {
			prefix = "cm.sendSimple";
		} else if (bytes.equals("04 00 00 00")) {
			prefix = "cm.sendOk";
		} else if (bytes.equals("04 00 01 00")) {
			prefix = "cm.sendPrev";
		} else if (bytes.equals("04 00 01 01")) {
			prefix = "cm.sendNextPrev";
		} else if (bytes.equals("04 0C 00 00")) {
			prefix = "cm.sendAcceptDecline";
		} else if (bytes.equals("04 03 00 00")) {
			prefix = "cm.sendGetNum";
		} else if (bytes.equals("04 02 00 00")) {
			prefix = "cm.sendGetText";
		} else if (bytes.equals("04 07 00 00")) {
			prefix = "cm.sendStyle";
		}

		return prefix;
	}

	public boolean isRechargable(int itemId) {
		int itemType = itemId / 10000;
		return itemType == 207 || itemType == 233;
	}

	public boolean addPreviousEntries() {
		File file = new File(currentWriterName);
		if (file == null) {
			return false;
		}
		switch (serverOutputType) {
			case ODINMS:
				break;
			case VANA:
				break;
			case TITANMS:
				file = file.getParentFile();
				for (File childFile : file.listFiles()) {
					int id = Integer.parseInt(childFile.getName().substring(0, childFile.getName().length() - 4));
					storedShops.add(id);
					System.out.println("Added Previous Entry: Shop(" + id + ")");
				}

				break;
		}
		return true;
	}

	public void addShopSqlQuery(SeekableLittleEndianAccessor slea) {
		int shopId = slea.readInt();
		int itemSize = slea.readShort();
		switch (serverOutputType) {
			case ODINMS:
				if (!currentWriterName.startsWith(serverOutputType.getReadableName())) {
					logStream = getNewWriter("OdinMS/" + logFilename, false);
				}
				break;
			case VANA:
				if (!currentWriterName.startsWith(serverOutputType.getReadableName())) {
					logStream = getNewWriter("Vana/" + logFilename, false);
				}
				break;
			case TITANMS:
				logStream = getNewWriter("TitanMS/" + shopId + ".xml", false);
				break;
		}
		if (!addedPrevEntries) {
			addedPrevEntries = addPreviousEntries();
		}

		if (storedShops.contains(shopId)) {
			System.out.println("Warning: Shop(" + shopId + ") - Already Stored");
			return;
		}
		switch (serverOutputType) {
			case ODINMS:
				outputWithLogging("-- SHOP_ID " + shopId, false);
				outputWithLogging("-- ITEM_SIZE " + itemSize, false);
				outputWithLogging("INSERT INTO shops", false);
				outputWithLogging("(`shopid`, `npcid`)", false);
				outputWithLogging("VALUES", false);
				outputWithLogging("(" + shopId + ", " + shopId + ");\r\n", false);
				outputWithLogging("INSERT INTO shopitems", false);
				outputWithLogging("(`shopid`, `itemid`, `price`, `position`)", false);
				outputWithLogging("VALUES", false);
				break;
			case VANA:
				outputWithLogging("-- SHOP_ID " + shopId, false);
				outputWithLogging("-- ITEM_SIZE " + itemSize, false);
				outputWithLogging("INSERT INTO shopitemdata", false);
				outputWithLogging("(`shopid`, `itemid`, `price`, `sort`)", false);
				outputWithLogging("VALUES", false);
				break;
			case TITANMS:
				outputWithLogging("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", false);
				outputWithLogging("<!--" + shopId + "-->", false);
				outputWithLogging("<Shop>", false);
				outputWithLogging("\t<NPC>" + shopId + "</NPC>", false);
				outputWithLogging("\t<Items>", false);
				break;
		}
		for (int i = 1; i <= itemSize; i++) {
			int itemId = slea.readInt();
			int price = slea.readInt();
			int position = i;
			slea.read(isRechargable(itemId) ? 10 : 4);
			String lineMarker = (i == itemSize ? ";" : ",");
			switch (serverOutputType) {
				case ODINMS:
					outputWithLogging("(" + shopId + ", " + itemId + ", " + price + ", " + position + ")" + lineMarker, false);
					break;
				case VANA:
					outputWithLogging("(" + shopId + ", " + itemId + ", " + price + ", " + ((itemSize * 4 + 100) - (position * 4)) + ")" + lineMarker, false);
					break;
				case TITANMS:
					outputWithLogging("\t\t<Item>", false);
					outputWithLogging("\t\t\t<ID>" + itemId + "</ID>", false);
					outputWithLogging("\t\t\t<Price>" + price + "</Price>", false);
					outputWithLogging("\t\t</Item>", false);
					break;
			}
		}
		if (serverOutputType == ServerOutputType.TITANMS) {
			outputWithLogging("\t</Items>", false);
			outputWithLogging("</Shop>", false);
		}
		System.out.println("Added: Shop(" + shopId + ")");
		storedShops.add(shopId);
	}

	public Map<String, Boolean> getBlockedOpcodes() {
		return blockedOpcodes;
	}

	public Properties getSettings() {
		return settings;
	}

	public boolean isBlockDefault() {
		return blockDefault;
	}

	public CaptureType getCapType() {
		return capType;
	}

	public boolean isLogging() {
		return logging;
	}

	public String getPacketFilter() {
		return packetFilter;
	}

	public ServerOutputType getServerOutputType() {
		return serverOutputType;
	}

	public enum CaptureType {

		PACKET,
		NPC,
		SHOP,
        SPEED_QUIZ,
		UNDEFINED;

		public static CaptureType getByName(String name) {
			for (CaptureType l : CaptureType.values()) {
				if (l.name().equalsIgnoreCase(name)) {
					return l;
				}
			}
			return UNDEFINED;
		}
	}

	public enum ServerOutputType {

		ODINMS,
		VANA,
		TITANMS;

		public static ServerOutputType getByName(String name) {
			for (ServerOutputType server : ServerOutputType.values()) {
				if (server.name().equalsIgnoreCase(name)) {
					return server;
				}
			}
			return null;
		}

		public String getReadableName() {
			switch (this) {
				case ODINMS:
					return "OdinMS";
				case VANA:
					return "Vana";
				case TITANMS:
					return "TitanMS";
				default:
					return null;
			}
		}
	}
}
