/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc> 
                       Matthias Butz <matze@odinms.de>
                       Jan Christian Meyer <vimes@odinms.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General public static License version 3
    as published by the Free Software Foundation. You may not use, modify
    or distribute this program under any other version of the
    GNU Affero General public static License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General public static License for more details.

    You should have received a copy of the GNU Affero General public static License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package org.snow.odinms;

import java.util.Properties;

/**
 *
 * @author Raz
 */
public class PropertyTool {

	private Properties props = new Properties();

	public PropertyTool(Properties props) {
		this.props = props;
	}

	public byte getSettingByte(String key, byte def) {
		String property = props.getProperty(key);
		if (property != null) {
			return Byte.parseByte(property);
		}
		return def;
	}

	public short getSettingShort(String key, short def) {
		String property = props.getProperty(key);
		if (property != null) {
			return Short.parseShort(property);
		}
		return def;
	}

	public int getSettingInt(String key, int def) {
		String property = props.getProperty(key);
		if (property != null) {
			return Integer.parseInt(property);
		}
		return def;
	}

	public long getSettingLong(String key, long def) {
		String property = props.getProperty(key);
		if (property != null) {
			return Long.parseLong(property);
		}
		return def;
	}

	public String getSettingStr(String key, String def) {
		String property = props.getProperty(key);
		if (property != null) {
			return property;
		}
		return def;
	}

	public byte getSettingByte(String key) {
		return getSettingByte(key, (byte) -1);
	}

	public short getSettingShort(String key) {
		return getSettingShort(key, (short) -1);
	}

	public int getSettingInt(String key) {
		return getSettingInt(key, -1);
	}

	public long getSettingLong(String key) {
		return getSettingLong(key, -1);
	}

	public String getSettingStr(String key) {
		return getSettingStr(key, null);
	}
}
