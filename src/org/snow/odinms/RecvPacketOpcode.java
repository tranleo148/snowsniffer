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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public enum RecvPacketOpcode implements WritableIntValueHolder {
	LOGIN_PASSWORD,//0x01
    GUEST_LOGIN,//0x02
    SERVERLIST_REREQUEST,//0x04
    CHARLIST_REQUEST,//0x05
    SERVERSTATUS_REQUEST,//0x06
    SET_GENDER,//0x08
    AFTER_LOGIN,//0x09
    REGISTER_PIN,//0x0A
    SERVERLIST_REQUEST,//0x0B
    PLAYER_DC,//0xC0
    VIEW_ALL_CHAR,//0x0D
    PICK_ALL_CHAR,//0x0E
    CHAR_SELECT,//0x13
    PLAYER_LOGGEDIN,//0x14
    CHECK_CHAR_NAME,//0x15
    PIC_ASSIGNED, //0x1E
    CREATE_CHAR,//0x16
    CREATE_CYGNUS,//0x17
    DELETE_CHAR,//0x18
    PONG,//0x19
    ERROR,//0x1A
    CLIENT_START,//0x1A
    CLIENT_ERROR,//0x1B
    STRANGE_DATA,//0x1C
    RELOG,//0x1D
    PACKET_ERROR,
    CHANGE_MAP,//0x25
    CHANGE_CHANNEL,//0x26
    ENTER_CASH_SHOP,//0x27
    MOVE_PLAYER,//0x28
    CANCEL_CHAIR,//0x29
    USE_CHAIR,//0x2A
    CLOSE_RANGE_ATTACK,//0x2B
    RANGED_ATTACK,//0x2C
    MAGIC_ATTACK,//0x2D
    ENERGY_ORB_ATTACK,//0x2E
    TAKE_DAMAGE,//0x2F
    GENERAL_CHAT,//0x30
    CLOSE_CHALKBOARD,//0x31
    FACE_EXPRESSION,//0x32
    USE_ITEMEFFECT,//0x33
    USE_DEATHITEM,//0x34
    MONSTER_BOOK_COVER,//0x38
    NPC_TALK,//0x39
    NPC_TALK_MORE,//0x3B
    NPC_SHOP,//0x3C
    STORAGE,//0x3D
    HIRED_MERCHANT_REQUEST,//0x3E
    DUEY_ACTION,//0x40
    ITEM_SORT,//0x44
    ITEM_SORT2,//0x45
    ITEM_MOVE,//0x46
    USE_ITEM,//0x47
    CANCEL_ITEM_EFFECT,//0x48
    USE_SUMMON_BAG,//0x4A
    USE_PET_FOOD,//0x4B
    USE_MOUNT_FOOD,//0x4C
    USE_SCRIPTED_ITEM,//0x4D
    USE_CASH_ITEM,//0x4E
    USE_CATCH_ITEM,//0x50
    USE_SKILL_BOOK,//0x51
    USE_TELEPORT_ROCK,//0x53
    USE_RETURN_SCROLL,//0x54
    USE_UPGRADE_SCROLL,//0x55
    DISTRIBUTE_AP,//0x56
    AUTO_DISTRIBUTE_AP,//0x57
    HEAL_OVER_TIME,//0x58
    DISTRIBUTE_SP,//0x59
    SPECIAL_MOVE,//0x5A
    CANCEL_BUFF,//0x5B
    SKILL_EFFECT,//0x5C
    MESO_DROP,//0x5D
    GIVE_FAME,//0x5E
    CHAR_INFO_REQUEST,//0x60
    SPAWN_PET,//0x61
    CANCEL_DEBUFF,//0x62
    CHANGE_MAP_SPECIAL,//0x63
    USE_INNER_PORTAL,//0x64
    TROCK_ADD_MAP,//0x65
    REPORT,//0x69
    QUEST_ACTION,//0x6A
    SKILL_MACRO,//0x6D
    SPOUSE_CHAT,//0x6E
    USE_FISHING_ITEM,//0x6F
    MAKER_SKILL,//0x70
    USE_REMOTE,//0x73
    PARTYCHAT,//0x75
    WHISPER,//0x76
    MESSENGER,//0x78
    PLAYER_INTERACTION,//0x79
    PARTY_OPERATION,//0x7A
    DENY_PARTY_REQUEST,//0x7B
    GUILD_OPERATION,//0x7C
    DENY_GUILD_REQUEST,//0x7D
    ADMIN_COMMAND,//0x7E
    ADMIN_LOG,//0x7F
    BUDDYLIST_MODIFY,//0x80
    NOTE_ACTION,//0x81
    USE_DOOR,//0x83
    CHANGE_KEYMAP,//0x85
    RING_ACTION,//0x87 #not sure
    OPEN_FAMILY,//0x90
    ADD_FAMILY,//0x91
    ACCEPT_FAMILY,//0x94
    USE_FAMILY,//0x95
    ALLIANCE_OPERATION,//0x96
    BBS_OPERATION,//0x99
    ENTER_MTS,//0x9A
    PET_TALK,//0x9B
    USE_SOLOMON_ITEM,//0x9C
    MOVE_PET,//0xA1
    PET_CHAT,//0xA2
    PET_COMMAND,//0xA3
    PET_LOOT,//0xA4
    PET_AUTO_POT,//0xA5
    PET_EXCLUDE_ITEMS,//0xA6
    MOVE_SUMMON,//0xA9
    MOVE_DRAGON,//0xA9
    SUMMON_ATTACK,//0xAA
    DAMAGE_SUMMON,//0xAB
    BEHOLDER,//0xAC
    MOVE_LIFE,//0xB2
    AUTO_AGGRO,//0xB3
    MOB_DAMAGE_MOB_FRIENDLY,//0xB6
    MONSTER_BOMB,//0xB7
    MOB_DAMAGE_MOB,//0xB8
    NPC_ACTION,//0xBB
    ITEM_PICKUP,//0xC0
    DAMAGE_REACTOR,//0xC3
    TOUCHING_REACTOR,//0xC4
    MONSTER_CARNIVAL,//0xCE
    PARTY_SEARCH_REGISTER,//0xD2
    PARTY_SEARCH_START,//0xD4
    MAPLETV,//0x222
    PLAYER_UPDATE,//0xD5
    TOUCHING_CS,//0xDA
    BUY_CS_ITEM,//0xDB
    COUPON_CODE,//0xDC #not sure
    OPEN_ITEMUI,//0xE1
    CLOSE_ITEMUI,//0xE2
    USE_ITEMUI,//0xE3
    MTS_OP,//0xF1
    USE_MAPLELIFE,//0xF4
    USE_HAMMER,//0xF8
    USE_MAGNIFING_GLASS, // 0x60
    USE_ENHANCEMENT_SCROLL, // 0x5E
    USE_POTENTIAL_SCROLL,
    UNKNOWN;
	private int code = -2;

	public void setValue(int code) {
		this.code = code;
	}

	@Override
	public int getValue() {
		return code;
	}

	public static Properties getDefaultProperties() throws FileNotFoundException, IOException {
		Properties props = new Properties();
		FileInputStream fis = new FileInputStream(System.getProperty("net.sf.odinms.recvops"));
		props.load(fis);
		fis.close();
		return props;
	}

	public static RecvPacketOpcode getByType(int type) {
		for (RecvPacketOpcode l : RecvPacketOpcode.values()) {
			if (l.getValue() == type) {
				return l;
			}
		}
		return UNKNOWN;
	}

	public static RecvPacketOpcode getByName(String name) {
		for (RecvPacketOpcode l : RecvPacketOpcode.values()) {
			if (l.name().equalsIgnoreCase(name)) {
				return l;
			}
		}
		return UNKNOWN;
	}


	static {
		try {
			ExternalCodeTableGetter.populateValues(getDefaultProperties(), values());
		} catch (IOException e) {
			throw new RuntimeException("Failed to load recvops", e);
		}
	}
}
