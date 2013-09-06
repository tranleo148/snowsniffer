package org.snow.maplesnowsniffer;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Scanner;
import javax.swing.JTable;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.snow.odinms.ByteArrayByteStream;
import org.snow.odinms.GenericSeekableLittleEndianAccessor;
import org.snow.odinms.HexTool;
import org.snow.odinms.MapleAESOFB;
import org.snow.odinms.MapleCustomEncryption;
import org.snow.odinms.PropertyTool;
import org.snow.odinms.RecvPacketOpcode;
import org.snow.odinms.SeekableLittleEndianAccessor;
import org.snow.odinms.SendPacketOpcode;
import org.snow.odinms.StringUtil;

public class MaplePcapture implements PcapPacketHandler {

    private MapleAESOFB send;
    private MapleAESOFB recv;
    private ByteArrayOutputStream toClient = new ByteArrayOutputStream();
    private ByteArrayOutputStream toServer = new ByteArrayOutputStream();
    private int toClientPos = 0;
    private int toServerPos = 0;
    private InetAddress ipclient = null;
    private InetAddress ipserver = null;
    private static boolean logging = false;
    private static BufferedWriter logStream = null;
    private static CaptureType capType;
    private Pcap pcap;
    private static List<MaplePacketRecord> packetRecords = new ArrayList<MaplePacketRecord>();
    private static String logFilename;
    private static boolean appendLogStream;
    private static String currentWriterName = null;
    private static boolean addedPrevEntries = false;
    private static Properties settings = new Properties();
    private static Properties blockOP = new Properties();
    private static PropertyTool propTool = new PropertyTool(new Properties());
    private static MaplePcaptureGUI packetGUI;
    private static boolean useGUI = true;
    private static boolean resume = true;
    private static List<Integer> storedShops = new ArrayList<Integer>();
    private static ServerOutputType serverOutputType;
    private static boolean showHex;
    private static boolean showAscii;
    private static Map<String, Boolean> blockedOpcodes = new HashMap<String, Boolean>();
    private static boolean blockDefault;
    private static int deviceIndex;
    private static String packetFilter;
    private static String lang;

    public MaplePcapture() {
    }

    public static MaplePcapture getInstance() {
        MaplePcapture instance = new MaplePcapture();
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
            if (useGUI) {
                packetGUI = new MaplePcaptureGUI();
                packetGUI.setCapture(this);
                packetGUI.setVisible(true);
            }
            List<PcapIf> alldevs = new ArrayList<PcapIf>();
            StringBuilder errbuf = new StringBuilder();
            Pcap.findAllDevs(alldevs, errbuf);
            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis
            PcapIf device = alldevs.get(deviceIndex);
            PcapBpfProgram program = new PcapBpfProgram();
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);//captor = JpcapCaptor.openDevice(devices[deviceIndex], 65535, false, 20);
            pcap.compile(program, packetFilter.toLowerCase(), 0, 0xFFFFFF00);
            pcap.setFilter(program);//captor.setFilter(packetFilter.toLowerCase(), true);
            
            Thread thread = new Thread() {
                public void run() {
                    pcap.loop(-1, getInstance(), null);//captor.loopPacket(-1, this);
                }
            };
            thread.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void changeLang(String newLang) {
        settings.setProperty("LANGUAGE", newLang);
        try {
            settings.store(new FileOutputStream("settings.ini"), null);
        } catch (IOException ex) {
            System.out.println("Can't not save settings: " + ex);
        }
    }

    public String getLang() {
        return lang;
    }

    public boolean loadSettings() {
        try {
            FileInputStream fis, blo;
            fis = new FileInputStream("settings.ini");
            blo = new FileInputStream("blockOpcode.ini");
            settings.load(fis);
            blockOP.load(blo);
            fis.close();
            blo.close();
        } catch (IOException e) {
            System.out.println("Cannot find: settings.ini || opcodeTable.ini");
            return false;
        }
        propTool = new PropertyTool(settings);

        deviceIndex = propTool.getSettingInt("DEVICE", 0);
        packetFilter = propTool.getSettingStr("FILTER", "tcp");
        lang = propTool.getSettingStr("LANGUAGE", "EN");
        appendLogStream = propTool.getSettingInt("APPEND_LOG", 0) > 0;
        logFilename = propTool.getSettingStr("LOG_NAME", "log.txt");
        serverOutputType = ServerOutputType.getByName(propTool.getSettingStr("SERVER_TYPE", "ODINMS"));
        logStream = getNewWriter("logs/" + logFilename, appendLogStream);
        logging = propTool.getSettingInt("LOGGING", 0) > 0;
        useGUI = propTool.getSettingInt("USE_GUI", 1) > 0;
        capType = CaptureType.getByName(propTool.getSettingStr("CAPTURE_TYPE", "PACKET"));
        showHex = propTool.getSettingInt("SHOW_HEX", 1) > 0;
        showAscii = propTool.getSettingInt("SHOW_ASCII", 1) > 0;
        blockDefault = propTool.getSettingInt("BLOCK_DEF", 0) > 0;
        for (Entry<Object, Object> entry : blockOP.entrySet()) {
            String property = (String) entry.getKey();
            String value = (String) entry.getValue();
            if (property.startsWith("S_") || property.startsWith("R_")) {
                blockedOpcodes.put(property, ("1".equals(value) ? true : false));
            }
        }

        if (capType != CaptureType.PACKET) {
            useGUI = false;
        }
        System.out.println(" | " + serverOutputType.name() + " | " + capType.name());
        return true;
    }
    //Create packet handler which will receive packets

    @Override
    public void nextPacket(PcapPacket packet, Object t) {
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();
        Payload payload = new Payload();
        if (packet.hasHeader(ip) && packet.hasHeader(tcp) && packet.hasHeader(payload)) {
            byte[] data = payload.getByteArray(0, payload.size());
            byte[] sIP = packet.getHeader(ip).source();//src_ip
            byte[] dIP = packet.getHeader(ip).destination();//dst_ip
            SeekableLittleEndianAccessor slea = new GenericSeekableLittleEndianAccessor(new ByteArrayByteStream(data));
            SeekableLittleEndianAccessor slea2 = new GenericSeekableLittleEndianAccessor(new ByteArrayByteStream(data));
            long packetSize = slea.available();
            int opcode = 0;
            if (packetSize < 2) 
                return;
            else
                opcode = slea.readShort();
            try {
                if (opcode == slea.available()) {
                    System.out.println("Detected Maple Crypto - " + InetAddress.getByAddress(sIP));
                    byte[] getHello = slea2.read((int) slea2.available());
                    System.out.println("HELLO THERE! " + HexTool.toString(getHello));
                    short version = slea.readShort();
                    String maplePatch = slea.readMapleAsciiString();
                    byte ivsend[] = slea.read(4);//localIV
                    byte ivrecv[] = slea.read(4);//remoteIV
                    packetGUI.setSIVStr("SIV: " + HexTool.toString(ivsend));
                    packetGUI.setRIVStr("RIV: " + HexTool.toString(ivrecv));
                    MapleServerType serverType = MapleServerType.getByType(slea.readByte());
                    System.out.println("Maple Version " + version + "." + maplePatch + "  | Maple Server " + serverType.name());
                    if (useGUI) {
                        //MaplePacketRecord.setCount(-1);
                        MaplePacketRecord record = new MaplePacketRecord();
                        record.setCounter(MaplePacketRecord.getCountAndAdd());
                        record.setDataRecord(true);
                        record.setDirection("<NONE>");
                        record.setTime(Calendar.getInstance().getTime());
                        record.setHeader("MapleStory " + serverType.name() + "(V" + version + "." + maplePatch + ")");
                        record.setOpcode(opcode);
                        record.setPacketData(getHello);
                        record.setPacket(packet);

                        packetRecords.add(record);
                        packetGUI.addRow(record);
                        packetGUI.updateAndIncreasePacketTotal();
                        packetGUI.setStatusText("Capturing: MapleStory(V" + version + "." + maplePatch + ") | " + serverType.name());
                    }
                    send = new MapleAESOFB(ivsend, version);
                    recv = new MapleAESOFB(ivrecv, (short) (0xFFFF - version));
                    ipserver = InetAddress.getByAddress(sIP);
                    if (ipclient == null) {
                        ipclient = InetAddress.getByAddress(dIP);
                    }
                } else {
                    if (send != null && (InetAddress.getByAddress(sIP).equals(ipserver) || InetAddress.getByAddress(dIP).equals(ipserver))) {

                        if (InetAddress.getByAddress(sIP).equals(ipserver) && (InetAddress.getByAddress(dIP).equals(ipclient) || ipclient == null)) {
                            toClient.write(data);
                            int ret = 0;
                            do {
                                byte[] toClientArr = toClient.toByteArray();
                                ret = handleData(toClientArr, toClientPos, recv, packet, false);//ToClient
                                toClientPos += ret;
                            } while (ret != 0);
                        } else if ((InetAddress.getByAddress(sIP).equals(ipclient) || ipclient == null) && InetAddress.getByAddress(dIP).equals(ipserver)) {
                            toServer.write(data);
                            int ret = 0;
                            do {
                                byte[] toServerArr = toServer.toByteArray();
                                ret = handleData(toServerArr, toServerPos, send, packet, true);//ToServer
                                toServerPos += ret;
                            } while (ret != 0);
                        }
                    }
                }
            } catch (UnknownHostException ex) {
                ex.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private int handleData(byte[] data, int skip, MapleAESOFB crypto, PcapPacket packet, boolean send) {
        if (data.length < skip + 4) {
            return 0;
        }
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        byte[] header = new byte[4];
        try {
            dis.skip(skip);
            dis.readFully(header);
        } catch (IOException e) {
            e.printStackTrace();// I don't know why the exception happens but it doesn't really matter o.o"
        }

        if (crypto.checkPacket(header)) {//ConfirmHeader
            int packetSize = MapleAESOFB.getPacketLength(header);//GetHeaderLength
            try {
                if (dis.available() >= packetSize) {
                    byte ddata[] = new byte[packetSize];
                    dis.readFully(ddata);

                    byte unc[] = new byte[ddata.length];
                    System.arraycopy(ddata, 0, unc, 0, ddata.length);

                    crypto.crypt(ddata);//TransformAES(pBuffer)

                    MapleCustomEncryption.decryptData(ddata);//ok
                    SeekableLittleEndianAccessor slea = new GenericSeekableLittleEndianAccessor(new ByteArrayByteStream(ddata));

                    int pHeader = slea.readShort();
                    String opCode = StringUtil.getLeftPaddedStr(Integer.toHexString(pHeader).toUpperCase(), '0', 4);
                    String opName = send ? lookupRecv(pHeader) : lookupSend(pHeader);
                    String start = send ? "Sent " : "Received ";
                    String strStart = start.substring(0, 1);
                    try {
                        //FILTER PACKETS
                        switch (capType) {
                            case PACKET:
                                boolean opcodeBlocked;
                                if (opName.equals("UNKNOWN")) {
                                    opcodeBlocked = blockedOpcodes.containsKey(strStart + "_" + opCode) ? blockedOpcodes.get(strStart + "_" + opCode) : blockDefault;
                                } else {
                                    opcodeBlocked = blockedOpcodes.containsKey(strStart + "_" + opName) ? blockedOpcodes.get(strStart + "_" + opName) : blockDefault;
                                }
                                if (!opcodeBlocked && resume) {
                                    outputWithLogging(start + opName + " [" + opCode + "] (" + packetSize + ") ");
                                    if (useGUI) {
                                        MaplePacketRecord record = new MaplePacketRecord();
                                        record.setCounter(MaplePacketRecord.getCountAndAdd());
                                        record.setTime(new Date(System.currentTimeMillis()));
                                        record.setDirection(send ? "ToServer" : "ToClient");
                                        record.setSend(send);
                                        record.setOpcode(pHeader);
                                        record.setHeader(opName);
                                        record.setPacketData(ddata);
                                        record.setPacket(packet);
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
                    return packetSize + 4;
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

    public void loadFromFile(String fileName) {
        //TODO: Not done yet
        try {
            String text = "";
            Scanner input = new Scanner(new File(fileName));
            while (input.hasNextLine()) {
                text += input.nextLine() + "\r\n";
            }
            input.close();
            packetGUI.removeAllRow();
            String[] lines = text.split("\r\n");
            for (int i = 0; i < lines.length; i++) {
                Object[] rowData = new Object[7];
                rowData = lines[i].split("\\|");
                //Load Packet Info
                byte[] dataBytes = HexTool.getByteArrayFromHexString(rowData[6].toString());
                SimpleDateFormat dateFormat = new SimpleDateFormat("hh:mm:ss");
                Date convertedDate = dateFormat.parse(rowData[1].toString());

                MaplePacketRecord record = new MaplePacketRecord();
                record.setDataRecord(true);
                record.setCounter(Long.parseLong(rowData[0].toString()));
                record.setTime(convertedDate);
                record.setDirection(rowData[2].toString());
                record.setOpcode(Integer.parseInt(rowData[3].toString().substring(2), 16));
                record.setHeader(rowData[4].toString());
                record.setPacketData(dataBytes);
                record.setLoadFromFile(true);
                packetRecords.add(record);
                packetGUI.addRow(rowData);
                //Load Packet Tree
                //record.setTreeData(rowData[7].toString().split("-"));
            }
            packetGUI.loadPacketTotal(lines.length);
        } catch (FileNotFoundException ex) {
            System.out.println("Error open packets file: " + ex);
        } catch (ParseException e) {
            System.out.println("Error open packets file: " + e);
        }
    }

    public void dumpToFile(String fileName, JTable table) {
        try {
            BufferedWriter bfw = new BufferedWriter(new FileWriter(fileName));
            for (int i = 0; i < table.getRowCount(); i++) {
                MaplePacketRecord record = MaplePacketRecord.getById(i);
                for (int j = 0; j < table.getColumnCount(); j++) {
                    bfw.write(table.getValueAt(i, j).toString());
                    bfw.write("|");
                }
                bfw.write(HexTool.toString(record.getPacketData()) + "|");
                /*bfw.write(record.getPacket().src_ip.toString().substring(1) + "-");
                 bfw.write(record.getPacket().src_port + "-");
                 bfw.write(record.getPacket().dst_ip.toString().substring(1) + "-");
                 bfw.write(record.getPacket().dst_port + "-");
                 bfw.write(record.getPacket().sec + "-");
                 bfw.write(record.getPacket().usec + "|");*/
                bfw.newLine();
            }
            bfw.close();
            System.out.println("Saved data to file: " + fileName);
        } catch (Exception e) {
            System.out.println("Error dumping packets to file: " + e);
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
                    logStream = getNewWriter("logs/" + logFilename, false);
                }
                break;
            case VANA:
                if (!currentWriterName.startsWith(serverOutputType.getReadableName())) {
                    logStream = getNewWriter("logs/" + logFilename, false);
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

    public Properties getBlockOp() {
        return blockOP;
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

    public void setResume(boolean isResume) {
        resume = isResume;
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

    public enum MapleServerType {

        UNKNOWN(-1),
        JAPAN(3),
        TEST(5),
        SEA(7),
        GLOBAL(8),
        BRAZIL(9);
        final byte type;

        private MapleServerType(int type) {
            this.type = (byte) type;
        }

        public byte getType() {
            return type;
        }

        public static MapleServerType getByType(byte type) {
            for (MapleServerType l : MapleServerType.values()) {
                if (l.getType() == type) {
                    return l;
                }
            }
            return UNKNOWN;
        }
    }
}