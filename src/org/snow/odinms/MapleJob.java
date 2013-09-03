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

public enum MapleJob {
	BEGINNER(0),
	WARRIOR(100),
	FIGHTER(110),
	CRUSADER(111),
	HERO(112),
	PAGE(120),
	WHITEKNIGHT(121),
	PALADIN(122),
	SPEARMAN(130),
	DRAGONKNIGHT(131),
	DARKKNIGHT(132),
	MAGICIAN(200),
	FP_WIZARD(210),
	FP_MAGE(211),
	FP_ARCHMAGE(212),
	IL_WIZARD(220),
	IL_MAGE(221),
	IL_ARCHMAGE(222),
	CLERIC(230),
	PRIEST(231),
	BISHOP(232),
	BOWMAN(300),
	HUNTER(310),
	RANGER(311),
	BOWMASTER(312),
	CROSSBOWMAN(320),
	SNIPER(321),
	CROSSBOWMASTER(322),
	THIEF(400),
	ASSASSIN(410),
	HERMIT(411),
	NIGHTLORD(412),
	BANDIT(420),
	CHIEFBANDIT(421),
	SHADOWER(422),
	PIRATE(500),
	BRAWLER(510),
	MARAUDER(511),
	BUCCANEER(512),
	GUNSLINGER(520),
	OUTLAW(521),
	CORSAIR(522),
	GM(900),
	SUPERGM(910),
	;

	final int jobid;

	private MapleJob(int id) {
		jobid = id;
	}

	public int getId() {
		return jobid;
	}

	public static MapleJob getById(int id) {
		for (MapleJob l : MapleJob.values()) {
			if (l.getId() == id) {
				return l;
			}
		}
		return null;
	}
	
	public static MapleJob getBy5ByteEncoding(int encoded) {
		switch (encoded) {
			case 2:
				return WARRIOR;
			case 4:
				return MAGICIAN;
			case 8:
				return BOWMAN;
			case 16:
				return THIEF;
			case 32:
				return PIRATE;
			default:
				return BEGINNER;
		}
	}
	
	public boolean isA (MapleJob basejob) {		
		return getId() >= basejob.getId() && getId() / 100 == basejob.getId() / 100;
	}
	
	public MapleJob getBaseJob() {
	    if (getId() == 0) {
		return MapleJob.BEGINNER;
	    }
	    switch(getId() / 100) {
		case 1:
		    return WARRIOR;
		case 2:
		    return MAGICIAN;
		case 3:
		    return BOWMAN;
		case 4:
		    return THIEF;
		case 5:
		    return PIRATE;
		case 9:
		    return GM;
		default:
		    return null;
	    }
	}
}
