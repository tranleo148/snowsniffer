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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Scanner;
import java.util.Properties;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;

//LIVE DECRYPTOR - NO PCAP FILES
public class MaplePcaptureUtil {

	private static NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	private static Properties settings = new Properties();
	private static File settingsFile = new File("settings.properties");
	private static Scanner in = new Scanner(System.in);
	private static PrintStream out = System.out;
	private static PropertyTool propTool = new PropertyTool(new Properties());

	public static void main(String args[]) throws IOException {

		out.println("Snow's Packet Sniffer Utility\r\n");

		try {//LOAD PROP FILE
			settings.load(new FileInputStream(settingsFile.getName()));
		} catch (IOException e) {
			out.println("Cannot find: settings.properties");
			out.println("Creating file settings.properties...");
			if (!settingsFile.exists()) {
				settingsFile.createNewFile();
				out.println("settings.properties created\r\n");
			}
		}
		propTool = new PropertyTool(settings);

		while (!checkSettingsFile()) {
			out.println("\nError during Settings-Check...");
			out.println("Restarting Settings-Check...");
			out.println("0=Try again | 1=Ignore | 2=Close Program");
			int operation = in.nextInt();
			if (operation == 1) {
				break;
			} else if (operation == 2) {
				System.exit(0);
			}
		}

		try {


			out.println("\nENTER COMMAND: ");
			while (true) {//CONSOLE INPUTS

				String line = System.console().readLine();
				String[] splitted = line.split(" ");
				if (splitted[0].equals("stop")) {
					System.exit(0);
				} else if (splitted[0].equals("set")) {
					if (splitted.length > 2) {
						setProperty(settings, splitted[1], splitted[2], true);
						out.println("Set Key: " + splitted[1] + " = " + splitted[2]);
					} else {
						out.println("Invalid parameters");
					}
				} else if (splitted[0].equals("remove")) {
					if (splitted.length > 1) {
						String key = splitted[1];
						settings.remove(key);
						updateFile(settings, "settings.properties");
						out.println("Removed Key: " + key);
					} else {
						out.println("Invalid parameters");
					}
				} else if (splitted[0].equals("save")) {
					updateFile(settings, "settings.properties");
					out.println("Settings file saved");
				} else if (splitted[0].equals("savetoxml")) {
					settings.storeToXML(new FileOutputStream("test.xml"), null);
					out.println("Settings file saved");
				} else if (splitted[0].equals("reload")) {
					settings.clear();
					settings.load(new FileInputStream(settingsFile.getName()));
					out.println("Settings file reloaded");
				} else if (splitted[0].equals("listprops")) {
					settings.list(out);
				} else if (splitted[0].equals("help") || splitted[0].equals("?")) {
					out.println("HELP DESK");
				} else if (splitted[0].equals("debug")) {
					out.println("Splitted-Length: " + splitted.length);
					out.println(line);
				} else {
					out.println("UNKNOWN COMMAND '" + splitted[0] + "'");
				}
			}


		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void listDevices(boolean chooseNew) {

		//Obtain the list of network interfaces
		//for each network interface
		for (int i = 0; i < devices.length; i++) {
			out.println(i + ": " + devices[i].description + ")");
			//print out its IP address, subnet mask and broadcast address
			for (NetworkInterfaceAddress a : devices[i].addresses) {
				out.println(a.address);
			}
		}
		if (chooseNew) {
			try {
				out.print("Please select a new device: ");
				int newDeviceNum = in.nextInt();
				out.println("Device set to: " + newDeviceNum);
				out.println("Name: " + devices[newDeviceNum].description);
				for (NetworkInterfaceAddress a : devices[newDeviceNum].addresses) {
					out.println("IP: " + a.address);
				}
				setProperty(settings, "DEVICE", Integer.toString(newDeviceNum), true);
			} catch (Exception e) {
				out.println(e.getMessage());
			}
		} else {
			return;
		}
	}

	public static boolean checkSettingsFile() {

		boolean success = true;
		int deviceNum = propTool.getSettingInt("DEVICE", -1);
		String filter = propTool.getSettingStr("FILTER", null);
		int logging = propTool.getSettingInt("LOGGING", -1);
		String logName = propTool.getSettingStr("LOG_NAME", null);
		int blockDef = propTool.getSettingInt("BLOCK_DEF", -1);
		int showHex = propTool.getSettingInt("SHOW_HEX", -1);
		int showAscii = propTool.getSettingInt("SHOW_ASCII", -1);

		if (deviceNum == -1) {
			out.println("Device Check - FAIL");
			out.println("Please enter a value for Device");
			int deviceInt = in.nextInt();
			setProperty(settings, "DEVICE", Integer.toString(deviceInt), true);
			success = false;
		} else {
			out.println("Device Check - PASS");
		}

		if (filter == null) {
			out.println("Filter Check - FAIL");
			out.println("Please enter a Pcap filter");
			String filterStr = in.next();
			setProperty(settings, "FILTER", filterStr, true);
			success = false;
		} else {
			out.println("Filter Check - PASS");
		}

		if (logging == -1) {
			out.println("Logging Check - FAIL");
			out.println("Please enter a value for Logging");
			int loggingInt = in.nextInt();
			setProperty(settings, "LOGGING", Integer.toString(loggingInt), true);
			success = false;
		} else {
			out.println("Logging Check - PASS");
		}

		if (logName == null) {
			out.println("Log-Name Check - FAIL");
			out.println("Please enter a Log-Name");
			String logNameStr = in.next();
			if (!logNameStr.endsWith(".txt")) {
				logNameStr += ".txt";
			}

			setProperty(settings, "LOG_NAME", logNameStr, true);
			success = false;
		} else {
			out.println("Log-Name Check - PASS");
		}

		if (blockDef == -1) {
			out.println("Block-Def Check - FAIL");
			out.println("Please enter a value for Block-Def");
			int blockDefInt = in.nextInt();
			setProperty(settings, "BLOCK_DEF", Integer.toString(blockDefInt), true);
			success = false;
		} else {
			out.println("Block-Def Check - PASS");
		}

		if (showHex == -1) {
			out.println("Show-Hex Check - FAIL");
			out.println("Please enter a value for Show-Hex");
			int showHexInt = in.nextInt();
			setProperty(settings, "SHOW_HEX", Integer.toString(showHexInt), true);
			success = false;
		} else {
			out.println("Show-Hex Check - PASS");
		}

		if (showAscii == -1) {
			out.println("Show-Ascii Check - FAIL");
			out.println("Please enter a value for Show-Ascii");
			int showAsciiInt = in.nextInt();
			setProperty(settings, "SHOW_ASCII", Integer.toString(showAsciiInt), true);
			success = false;
		} else {
			out.println("Show-Ascii Check - PASS");
		}

		if (success) {
			out.println("Cleared Settings-Check");
		}

		return success;

	}

	public static boolean setProperty(Properties props, String key, String value, boolean toFile) {
		if (props != null) {
			props.setProperty(key, value);
			if (toFile) {
				return updateFile(settings, "settings.properties");
			} else {
				return false;
			}
		} else {
			return false;
		}
	}

	public static boolean updateFile(Properties props, String fileName) {
		try {
			props.store(new FileOutputStream(fileName), null);
			return true;
		} catch (IOException e) {
			return false;
		}
	}
}