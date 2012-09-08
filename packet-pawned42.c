/* packet-pawned42.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>

#define PROTO_TAG_PAWNED42			"PAWNED42"
#define TCP_PORT_PAWNED42			6664
#define FRAME_HEADER_LEN			1

#define USER_ROOM_JOIN				1
#define USER_ROOM_PART				2
#define USER_ROOM_SEND_MESSAGE		3
#define USER_ROOM_CHANGE_NAME		4
#define USER_ROOM_UPDATE_USER		5
#define USER_ROOM_UPDATE_SLOT		6
#define USER_ROOM_CHANGE_PASS		7

#define USER_SLOT_CREATE			10
#define USER_SLOT_DELETE			11
#define USER_SLOT_SWAP				12
#define USER_SLOT_MOVE				13
#define USER_SLOT_COPY				14
#define USER_SLOT_UPDATE			15

#define USER_SLOT_CHANGE_SKILL		20
#define USER_SLOT_CHANGE_TEMPLATE	21
#define USER_SLOT_CHANGE_PET		22
#define USER_SLOT_CHANGE_INFO		23
#define USER_SLOT_CHANGE_DATA		24
#define USER_SLOT_CHANGE_USER		25
#define USER_SLOT_CHANGE_COMMENT	26

#define USER_STAT					254
#define USER_PING					255

static const value_string PacketActionNames[] = {
	{ USER_ROOM_JOIN,				"USER_ROOM_JOIN"				},
	{ USER_ROOM_PART,				"USER_ROOM_PART"				},
	{ USER_ROOM_SEND_MESSAGE,		"USER_ROOM_SEND_MESSAGE"		},
	{ USER_ROOM_CHANGE_NAME,		"USER_ROOM_CHANGE_NAME"			},
	{ USER_ROOM_UPDATE_USER,		"USER_ROOM_UPDATE_USER"			},
	{ USER_ROOM_UPDATE_SLOT,		"USER_ROOM_UPDATE_SLOT"			},
	{ USER_ROOM_CHANGE_PASS,		"USER_ROOM_CHANGE_PASS"			},

	{ USER_SLOT_CREATE,				"USER_SLOT_CREATE"				},
	{ USER_SLOT_DELETE,				"USER_SLOT_DELETE"				},
	{ USER_SLOT_SWAP,				"USER_SLOT_SWAP"				},
	{ USER_SLOT_MOVE,				"USER_SLOT_MOVE"				},
	{ USER_SLOT_COPY,				"USER_SLOT_COPY"				},
	{ USER_SLOT_UPDATE,				"USER_SLOT_UPDATE"				},

	{ USER_SLOT_CHANGE_SKILL,		"USER_SLOT_CHANGE_SKILL"		},
	{ USER_SLOT_CHANGE_TEMPLATE,	"USER_SLOT_CHANGE_TEMPLATE"		},
	{ USER_SLOT_CHANGE_PET,			"USER_SLOT_CHANGE_PET"			},
	{ USER_SLOT_CHANGE_INFO,		"USER_SLOT_CHANGE_INFO"			},
	{ USER_SLOT_CHANGE_DATA,		"USER_SLOT_CHANGE_DATA"			},
	{ USER_SLOT_CHANGE_USER,		"USER_SLOT_CHANGE_USER"			},
	{ USER_SLOT_CHANGE_COMMENT,		"USER_SLOT_CHANGE_COMMENT"		},

	{ USER_STAT,					"USER_STAT"						},
	{ USER_PING,					"USER_PING"						},

	{ 0,							NULL							}
};

typedef struct value_guint {
  guint32	value;
  guint		guint;
} value_guint;

static const value_guint PacketActionRequestLength[] = {
	{ USER_ROOM_JOIN,				101		},
	{ USER_ROOM_PART,				5		},
	{ USER_ROOM_SEND_MESSAGE,		261		},
	{ USER_ROOM_CHANGE_NAME,		37		},
	{ USER_ROOM_UPDATE_USER,		5		},
	{ USER_ROOM_UPDATE_SLOT,		5		},
	{ USER_ROOM_CHANGE_PASS,		69		},
  
	{ USER_SLOT_CREATE,				6		},
	{ USER_SLOT_DELETE,				6		},
	{ USER_SLOT_SWAP,				7		},
	{ USER_SLOT_MOVE,				7		},
	{ USER_SLOT_COPY,				7		},
	{ USER_SLOT_UPDATE,				366		},

	{ USER_SLOT_CHANGE_SKILL,		16		},
	{ USER_SLOT_CHANGE_TEMPLATE,	40		},
	{ USER_SLOT_CHANGE_PET,			14		},
	{ USER_SLOT_CHANGE_INFO,		294		},
	{ USER_SLOT_CHANGE_DATA,		26		},
	{ USER_SLOT_CHANGE_USER,		38		},
	{ USER_SLOT_CHANGE_COMMENT,		262		},

	{ USER_STAT,					5		},
	{ USER_PING,					5		}
};

static const value_guint PacketActionResponseLength[] = {
	{ USER_ROOM_JOIN,				9		},
	{ USER_ROOM_SEND_MESSAGE,		294		},
	{ USER_ROOM_CHANGE_PASS,		9		},

	{ USER_ROOM_UPDATE_USER,		39		},
	{ USER_ROOM_UPDATE_SLOT,		368		},

	{ USER_STAT,					13		},
	{ USER_PING,					5		}
};

/* Wireshark ID of the PAWNED42 protocol */
static int proto_pawned42 = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_pawned42()
*/

/** Defining the protocol */
static gint hf_pawned42_data = -1;
static gint hf_pawned42_action = -1;
static gint hf_pawned42_result = -1;
static gint hf_pawned42_room = -1;
static gint hf_pawned42_user = -1;
static gint hf_pawned42_userCount = -1;
static gint hf_pawned42_slot = -1;
static gint hf_pawned42_slotCount = -1;
static gint hf_pawned42_slotTarget = -1;
static gint hf_pawned42_roomString = -1;
static gint hf_pawned42_userString = -1;
static gint hf_pawned42_passString = -1;
static gint hf_pawned42_dataString = -1;
static gint hf_pawned42_messageString = -1;
static gint hf_pawned42_commentString = -1;
static gint hf_pawned42_skillCode = -1;
static gint hf_pawned42_templateCode = -1;
static gint hf_pawned42_petList = -1;
static gint hf_pawned42_channels = -1;
static gint hf_pawned42_users = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_pawned42 = -1;


static guint32 dissect_pawned42_request(proto_tree *pawned42_tree, tvbuff_t *tvb, guint32 offset, int length)
{
	guint8 action = tvb_get_guint8(tvb, offset);
	offset += 1;

	switch(action)
	{
		case USER_ROOM_JOIN:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_roomString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_passString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_ROOM_PART:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_SEND_MESSAGE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_messageString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_ROOM_CHANGE_NAME:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_ROOM_UPDATE_USER:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_UPDATE_SLOT:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_CHANGE_PASS:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_passString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_passString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_SLOT_CREATE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_DELETE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_SWAP:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slotTarget, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_MOVE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slotTarget, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_COPY:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slotTarget, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_UPDATE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_skillCode, tvb, offset, 10, FALSE);
			offset += 10;

			proto_tree_add_item(pawned42_tree, hf_pawned42_templateCode, tvb, offset, 34, FALSE);
			offset += 34;

			proto_tree_add_item(pawned42_tree, hf_pawned42_petList, tvb, offset, 8, FALSE);
			offset += 8;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_commentString, tvb, offset, 256, FALSE);
			offset += 256;

			proto_tree_add_item(pawned42_tree, hf_pawned42_dataString, tvb, offset, 20, FALSE);
			offset += 20;
		break;

		case USER_SLOT_CHANGE_SKILL:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_skillCode, tvb, offset, 10, FALSE);
			offset += 10;
		break;

		case USER_SLOT_CHANGE_TEMPLATE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_templateCode, tvb, offset, 34, FALSE);
			offset += 34;
		break;

		case USER_SLOT_CHANGE_PET:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_petList, tvb, offset, 8, FALSE);
			offset += 8;
		break;

		case USER_SLOT_CHANGE_INFO:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_commentString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_SLOT_CHANGE_DATA:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_dataString, tvb, offset, 20, FALSE);
			offset += 20;
		break;

		case USER_SLOT_CHANGE_USER:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_SLOT_CHANGE_COMMENT:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_commentString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_STAT:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_PING:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		default:
			proto_tree_add_item(pawned42_tree, hf_pawned42_data, tvb, offset, length-offset, FALSE);
			offset += length;
		break;
	}
	return offset;
}

static guint32 dissect_pawned42_response(proto_tree *pawned42_tree, tvbuff_t *tvb, guint32 offset, int length)
{
	guint8 action = tvb_get_guint8(tvb, offset);
	offset += 1;

	switch(action)
	{
		case USER_ROOM_JOIN:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_result, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_SEND_MESSAGE:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_user, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_messageString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_ROOM_CHANGE_PASS:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_result, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_UPDATE_USER:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_user, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userCount, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_ROOM_UPDATE_SLOT:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_user, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_slotCount, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned42_tree, hf_pawned42_skillCode, tvb, offset, 10, FALSE);
			offset += 10;

			proto_tree_add_item(pawned42_tree, hf_pawned42_templateCode, tvb, offset, 34, FALSE);
			offset += 34;

			proto_tree_add_item(pawned42_tree, hf_pawned42_petList, tvb, offset, 8, FALSE);
			offset += 8;

			proto_tree_add_item(pawned42_tree, hf_pawned42_commentString, tvb, offset, 256, FALSE);
			offset += 256;

			proto_tree_add_item(pawned42_tree, hf_pawned42_dataString, tvb, offset, 20, FALSE);
			offset += 20;
		break;

		case USER_STAT:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_channels, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned42_tree, hf_pawned42_users, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_PING:
			proto_tree_add_item(pawned42_tree, hf_pawned42_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		default:
			proto_tree_add_item(pawned42_tree, hf_pawned42_data, tvb, offset, length-offset, FALSE);
			offset += length;
		break;
	}
	return offset;
}

static guint get_pawned42_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	guint8 action = tvb_get_guint8(tvb, offset);
	guint32 i;

	if (pinfo->match_port == pinfo->destport || TCP_PORT_PAWNED42 == pinfo->destport) {
		for (i = 0; i < sizeof(PacketActionRequestLength); i++)
			if (PacketActionRequestLength[i].value == action)
				return PacketActionRequestLength[i].guint;
	} else {
		for (i = 0; i < sizeof(PacketActionResponseLength); i++)
			if (PacketActionResponseLength[i].value == action)
				return PacketActionResponseLength[i].guint;
	}

	return (guint)(tvb_length(tvb)-offset);
}


static void dissect_pawned42_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *pawned42_item = NULL;
	proto_tree *pawned42_tree = NULL;
	guint32 offset = 0;
	guint32 length = tvb_length(tvb);
	guint8 action = 0;

	if (length >= 1)
		action = tvb_get_guint8(tvb, 0);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_PAWNED42);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d - %s %s", 
			pinfo->srcport, 
			pinfo->destport, 
				(pinfo->match_port == pinfo->destport || TCP_PORT_PAWNED42 == pinfo->destport) ? "Request" : "Response", 
				val_to_str(action, PacketActionNames, "Unknown Action: 0x%02x")
		);
	}

	if (tree) { /* we are being asked for details */
		pawned42_item = proto_tree_add_item(tree, proto_pawned42, tvb, 0, -1, FALSE);
		pawned42_tree = proto_item_add_subtree(pawned42_item, ett_pawned42);

		proto_tree_add_item(pawned42_tree, hf_pawned42_action, tvb, offset, 1, FALSE);

		if (pinfo->match_port == pinfo->destport || TCP_PORT_PAWNED42 == pinfo->destport)
			offset = dissect_pawned42_request(pawned42_tree, tvb, offset, length);
		else
			offset = dissect_pawned42_response(pawned42_tree, tvb, offset, length);
	}
}

static void dissect_pawned42(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_pawned42_message_len, dissect_pawned42_struct);
}

void proto_register_pawned42(void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_pawned42_data,
			{ "Unknown Data", "pawned42.data", FT_NONE, BASE_NONE, NULL, 0x0, "Unknown Data", HFILL }
		},
		{ &hf_pawned42_action,
			{ "Action", "pawned42.action", FT_UINT8, BASE_DEC, VALS(PacketActionNames), 0x0, "Action ID", HFILL }
		},
		{ &hf_pawned42_result,
			{ "Result", "pawned42.result", FT_UINT32, BASE_DEC, NULL, 0x0, "Result", HFILL }
		},
		{ &hf_pawned42_room,
			{ "Room", "pawned42.room", FT_UINT32, BASE_DEC, NULL, 0x0, "Room ID", HFILL }
		},
		{ &hf_pawned42_user,
			{ "User", "pawned42.user", FT_UINT8, BASE_DEC, NULL, 0x0, "User ID", HFILL }
		},
		{ &hf_pawned42_userCount,
			{ "User Count", "pawned42.userCount", FT_UINT8, BASE_DEC, NULL, 0x0, "User Count", HFILL }
		},
		{ &hf_pawned42_slot,
			{ "Slot", "pawned42.slot", FT_UINT8, BASE_DEC, NULL, 0x0, "Slot ID", HFILL }
		},
		{ &hf_pawned42_slotCount,
			{ "Slot Count", "pawned42.slotCount", FT_UINT8, BASE_DEC, NULL, 0x0, "Slot Count", HFILL }
		},
		{ &hf_pawned42_slotTarget,
			{ "Slot Target", "pawned42.slotTarget", FT_UINT8, BASE_DEC, NULL, 0x0, "Slot Target", HFILL }
		},
		{ &hf_pawned42_roomString,
			{ "Room String", "pawned42.roomString", FT_STRING, BASE_NONE, NULL, 0x0, "Roomname", HFILL }
		},
		{ &hf_pawned42_userString,
			{ "User String", "pawned42.userString", FT_STRING, BASE_NONE, NULL, 0x0, "Username", HFILL }
		},
		{ &hf_pawned42_passString,
			{ "Pass String", "pawned42.passString", FT_STRING, BASE_NONE, NULL, 0x0, "Password", HFILL }
		},
		{ &hf_pawned42_dataString,
			{ "Data String", "pawned42.dataString", FT_STRING, BASE_NONE, NULL, 0x0, "Data", HFILL }
		},
		{ &hf_pawned42_messageString,
			{ "Message String", "pawned42.messageString", FT_STRING, BASE_NONE, NULL, 0x0, "Message", HFILL }
		},
		{ &hf_pawned42_commentString,
			{ "Comment String", "pawned42.commentString", FT_STRING, BASE_NONE, NULL, 0x0, "Comment", HFILL }
		},
		{ &hf_pawned42_skillCode,
			{ "Skill String", "pawned42.skillCode", FT_STRING, BASE_NONE, NULL, 0x0, "Skill", HFILL }
		},
		{ &hf_pawned42_templateCode,
			{ "Template String", "pawned42.templateCode", FT_STRING, BASE_NONE, NULL, 0x0, "Template", HFILL }
		},
		{ &hf_pawned42_petList,
			{ "Pet String", "pawned42.petList", FT_STRING, BASE_NONE, NULL, 0x0, "Pet", HFILL }
		},
		{ &hf_pawned42_channels,
			{ "Channels", "pawned42.channels", FT_UINT32, BASE_DEC, NULL, 0x0, "Channel", HFILL }
		},
		{ &hf_pawned42_users,
			{ "Users", "pawned42.users", FT_UINT32, BASE_DEC, NULL, 0x0, "Users", HFILL }
		}
	};
	static gint *ett[] = {
		&ett_pawned42
	};

	proto_pawned42 = proto_register_protocol("pawned42 Protocol", PROTO_TAG_PAWNED42, "pawned42");
	proto_register_field_array(proto_pawned42, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length (ett));

	register_dissector("pawned42", dissect_pawned42, proto_pawned42);
}

void proto_reg_handoff_pawned42(void)
{
	static int pawned42_initialized = FALSE;
	static dissector_handle_t pawned42_handle;

	if (!pawned42_initialized)
	{
		pawned42_handle = create_dissector_handle(dissect_pawned42, proto_pawned42);
		pawned42_initialized = TRUE;
	}
	else
	{
		dissector_delete("tcp.port", TCP_PORT_PAWNED42, pawned42_handle);
	}

	dissector_add("tcp.port", TCP_PORT_PAWNED42, pawned42_handle);
}
