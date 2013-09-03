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
public class MapleWorld {

	private int id;
	private String name;
	private int maxCharacters;
	private WorldStatusType worldStatusType;

	/**
	 * Creates a new instance of MapleWorld
	 */
	public MapleWorld() {
	}

	public int getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public int getMaxCharacters() {
		return maxCharacters;
	}

	public WorldStatusType getWorldStatusType() {
		return worldStatusType;
	}

	public void setId(int id) {
		this.id = id;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setMaxCharacters(int maxCharacters) {
		this.maxCharacters = maxCharacters;
	}

	public void setWorldStatusType(WorldStatusType worldStatusType) {
		this.worldStatusType = worldStatusType;
	}

	public static enum WorldStatusType implements IntValueHolder {

		NONE(0),
		EVENT(1),
		NEW(2),
		HOT(3);
		private int value;

		private WorldStatusType(int value) {
			this.value = value;
		}

		public static WorldStatusType getById(int id) {
			for (WorldStatusType statusType : WorldStatusType.values()) {
				if (statusType.getValue() == id) {
					return statusType;
				}
			}
			return NONE;
		}

		public static WorldStatusType getByName(String name) {
			for (WorldStatusType statusType : WorldStatusType.values()) {
				if (statusType.name().equalsIgnoreCase(name)) {
					return statusType;
				}
			}
			return NONE;
		}

		@Override
		public int getValue() {
			return value;
		}
	}
}
