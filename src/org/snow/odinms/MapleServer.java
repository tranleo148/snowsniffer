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

/**
 *
 * @author Raz
 */
public class MapleServer {

	public final static short MAPLE_VERSION = 97;
	public final static MapleServerType MAPLE_SERVER_TYPE = MapleServerType.GLOBAL;
	public final static boolean USE_LIST_WZ = true;
	public final static String RECV_OPS = "recvops.properties";
	public final static String SEND_OPS = "sendops.properties";
	public final static String WZ_PATH = "C:/Nexon/MapleStory";

	/*	static {
	try {
	Properties props = new Properties();
	InputStreamReader is = new FileReader("world.properties");
	props.load(is);
	MAPLE_VERSION = Short.parseShort(props.getProperty("net.sf.odinms.server.version"));
	} catch (Exception e) {
	MAPLE_VERSION = -1;
	e.printStackTrace();
	}
	}*/
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
