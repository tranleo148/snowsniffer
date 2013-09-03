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

public enum SendPacketOpcode implements WritableIntValueHolder {
	LOGIN_STATUS,
    SEND_LINK,
    SERVERSTATUS,
    GENDER_DONE,
    TOS,
    PIN_OPERATION,
    PIN_ASSIGNED,
    ALL_CHARLIST,
    SERVERLIST,
    CHARLIST,
    SERVER_IP,
    PIC_ASSIGNED,
    CHAR_NAME_RESPONSE,
    ADD_NEW_CHAR_ENTRY,
    DELETE_CHAR_RESPONSE,
    CHANGE_CHANNEL,
    PING, // v99
    CHANNEL_SELECTED,
    RELOG_RESPONSE,
    ENABLE_RECOMMENDED,
    SEND_RECOMMENDED,
    MODIFY_INVENTORY_ITEM,
    CHARACTER_CREATION_EVENT,
    UPDATE_INVENTORY_SLOTS,
    UPDATE_STATS,
    GIVE_BUFF,
    CANCEL_BUFF,
    UPDATE_SKILLS,
    FAME_RESPONSE,
    SHOW_STATUS_INFO,
    SHOW_NOTES,
    TROCK_LOCATIONS,
    LIE_DETECTOR,
    REPORT_RESPONSE,
    ENABLE_REPORT,
    UPDATE_MOUNT,
    SHOW_QUEST_COMPLETION,
    SEND_TITLE_BOX,
    USE_SKILL_BOOK,
    SHOW_EQUIP_EFFECT,
    FINISH_SORT,
    FINISH_SORT2,
    REPORTREPLY,
    MESO_LIMIT,
    GENDER,
    BBS_OPERATION,
    CHAR_INFO,
    PARTY_OPERATION,
    EXPEDITION_OPERATION,
    BUDDYLIST,
    GUILD_OPERATION,
    ALLIANCE_OPERATION,
    SPAWN_PORTAL,
    SERVERMESSAGE,
    WEDDING_ACTION,
    YELLOW_TIP,
    PLAYER_NPC,
    MONSTERBOOK_ADD,
    MONSTER_BOOK_CHANGE_COVER,
    ENERGY,
    SHOW_PEDIGREE,
    OPEN_FAMILY,
    FAMILY_MESSAGE,
    FAMILY_INVITE,
    FAMILY_JOIN_RESPONSE,
    FAMILY_SENIOR_MESSAGE,
    LOAD_FAMILY,
    FAMILY_GAIN_REP,
    FAMILY_USE_REQUEST,
    BLANK_MESSAGE,
    AVATAR_MEGA,
    NAME_CHANGE_MESSAGE,
    GM_POLICE,
    SILVER_BOX,
    SKILL_MACRO,
    WARP_TO_MAP, // v99
    MTS_OPEN,
    CS_OPEN,
    RESET_SCREEN,
    CS_BLOCKED,
    FORCED_MAP_EQUIP,
    MULTICHAT,
    WHISPER,
    SPOUSE_CHAT,
    BOSS_ENV,
    BLOCK_PORTAL,
    BLOCK_PORTAL_SHOP,
    MAP_EFFECT,
    HPQ_MOON,
    GM_PACKET,
    OX_QUIZ,
    GMEVENT_INSTRUCTIONS,
    CLOCK,
    BOAT_EFFECT,
    STOP_CLOCK,
    ARIANT_SCOREBOARD,
    QUICK_SLOT,
    SPAWN_PLAYER,
    REMOVE_PLAYER_FROM_MAP,
    CHATTEXT,
    CHALKBOARD,
    UPDATE_CHAR_BOX,
    SHOW_SCROLL_EFFECT,//B4 before
    SHOW_ENHANCEMENT_EFFECT,
    SHOW_POTENTIAL_EFFECT,
    SHOW_MAGNIFYING_EFFECT,
    SHOW_CUBE_EFFECT,
    SPAWN_PET,
    MOVE_PET,
    PET_CHAT,
    PET_NAMECHANGE,
    PET_SHOW,
    PET_COMMAND,
    SPAWN_SPECIAL_MAPOBJECT,
    REMOVE_SPECIAL_MAPOBJECT,
    MOVE_SUMMON,
    SUMMON_ATTACK,
    DAMAGE_SUMMON,
    SUMMON_SKILL,
    SPAWN_DRAGON,
    MOVE_DRAGON,
    REMOVE_DRAGON,
    MOVE_PLAYER,
    CLOSE_RANGE_ATTACK,
    RANGED_ATTACK,
    MAGIC_ATTACK,
    SKILL_EFFECT,
    CANCEL_SKILL_EFFECT,
    DAMAGE_PLAYER,
    FACIAL_EXPRESSION,
    SHOW_ITEM_EFFECT,
    SHOW_CHAIR,
    UPDATE_CHAR_LOOK,
    SHOW_FOREIGN_EFFECT,
    GIVE_FOREIGN_BUFF,
    CANCEL_FOREIGN_BUFF,
    UPDATE_PARTYMEMBER_HP,
    CANCEL_CHAIR,
    SHOW_ITEM_GAIN_INCHAT,
    DOJO_WARP_UP,
    LUCKSACK_PASS,
    LUCKSACK_FAIL,
    MESO_BAG_MESSAGE,
    UPDATE_QUEST_INFO,
    PLAYER_HINT,
    KOREAN_EVENT,
    TUTORIAL_INTRO_LOCK,
    TUTORIAL_INTRO_DISABLE_UI,
    ARAN_COMBO_COUNTER,
    COOLDOWN,
    SPAWN_MONSTER,
    KILL_MONSTER,
    SPAWN_MONSTER_CONTROL,
    MOVE_MONSTER,
    MOVE_MONSTER_RESPONSE,
    APPLY_MONSTER_STATUS,
    CANCEL_MONSTER_STATUS,
    DAMAGE_MONSTER,
    ARIANT_THING,
    SHOW_MONSTER_HP,
    SHOW_DRAGGED,
    SHOW_MAGNET,
    CATCH_MONSTER,
    CATCH_ARIANT,
    SPAWN_NPC,
    REMOVE_NPC,
    SPAWN_NPC_REQUEST_CONTROLLER,
    NPC_ACTION,
    SPAWN_HIRED_MERCHANT,
    DESTROY_HIRED_MERCHANT,
    UPDATE_HIRED_MERCHANT,
    DROP_ITEM_FROM_MAPOBJECT, // used to be 0x14D o_o
    REMOVE_ITEM_FROM_MAP, // (always +2 up from DROP_ITEM_FROM_MAPOBJECT)
    KITE_MESSAGE,
    KITE,
    SPAWN_MIST,
    REMOVE_MIST,
    SPAWN_DOOR,
    REMOVE_DOOR,
    REACTOR_HIT,//used to be 159
    REACTOR_SPAWN,//used to be 15B
    REACTOR_DESTROY,//used to be 15C
    ROLL_SNOWBALL,
    HIT_SNOWBALL,
    SNOWBALL_MESSAGE,
    LEFT_KNOCK_BACK,
    UNABLE_TO_CONNECT,
    MONSTER_CARNIVAL_DIED,
    MONSTER_CARNIVAL_SUMMON,
    MONSTER_CARNIVAL_START,
    MONSTER_CARNIVAL_PARTY_CP,
    MONSTER_CARNIVAL_OBTAINED_CP,
    ARIANT_PQ_START,
    ZAKUM_SHRINE,
    NPC_TALK,
    OPEN_NPC_SHOP,
    CONFIRM_SHOP_TRANSACTION,
    OPEN_STORAGE,
    MESSENGER,
    PLAYER_INTERACTION,
    DONALD,
    CS_UPDATE,
    CS_OPERATION,
    KEYMAP,
    AUTO_HP_POT,
    AUTO_MP_POT,
    SEND_TV,
    REMOVE_TV,
    ENABLE_TV,
    MTS_OPERATION,
    MTS_OPERATION2,
    EARN_TITLE_MSG,
    VICIOUS_HAMMER,
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
		FileInputStream fileInputStream = new FileInputStream(System.getProperty("net.sf.odinms.sendops"));
		props.load(fileInputStream);
		fileInputStream.close();
		return props;
	}
	
	public static SendPacketOpcode getByType(int type) {
		for (SendPacketOpcode l : SendPacketOpcode.values()) {
			if (l.getValue() == type) {
				return l;
			}
		}
		return UNKNOWN;
	}
	
	public static SendPacketOpcode getByName(String name) { 
	    for (SendPacketOpcode l : SendPacketOpcode.values()) {
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
			throw new RuntimeException("Failed to load sendops", e);
		}
	}
}
