/* packet-pawned.c
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
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>

#define PROTO_TAG_PAWNED			"PAWNED"
#define TCP_PORT_PAWNED				6665
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
#define USER_SLOT_CHANGE_EQUIPMENT	22
#define USER_SLOT_CHANGE_INFO		23
#define USER_SLOT_CHANGE_DATA		24

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
	{ USER_SLOT_CHANGE_EQUIPMENT,	"USER_SLOT_CHANGE_EQUIPMENT"	},
	{ USER_SLOT_CHANGE_INFO,		"USER_SLOT_CHANGE_INFO"			},
	{ USER_SLOT_CHANGE_DATA,		"USER_SLOT_CHANGE_DATA"			},

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
	{ USER_SLOT_UPDATE,				461		},

	{ USER_SLOT_CHANGE_SKILL,		43		},
	{ USER_SLOT_CHANGE_TEMPLATE,	53		},
	{ USER_SLOT_CHANGE_EQUIPMENT,	57		},
	{ USER_SLOT_CHANGE_INFO,		294		},
	{ USER_SLOT_CHANGE_DATA,		38		},

	{ USER_STAT,					5		},
	{ USER_PING,					5		}
};

static const value_guint PacketActionResponseLength[] = {
	{ USER_ROOM_JOIN,				9		},
	{ USER_ROOM_SEND_MESSAGE,		294		},
	{ USER_ROOM_CHANGE_PASS,		9		},

	{ USER_ROOM_UPDATE_USER,		39		},
	{ USER_ROOM_UPDATE_SLOT,		463		},

	{ USER_STAT,					21		},
	{ USER_PING,					5		}
};

/* Wireshark ID of the PAWNED protocol */
static int proto_pawned = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_pawned()
*/

/** Kts attempt at defining the protocol */
static gint hf_pawned = -1;
static gint hf_pawned_action = -1;
static gint hf_pawned_result = -1;
static gint hf_pawned_room = -1;
static gint hf_pawned_user = -1;
static gint hf_pawned_userCount = -1;
static gint hf_pawned_slot = -1;
static gint hf_pawned_slotCount = -1;
static gint hf_pawned_slotTarget = -1;
static gint hf_pawned_roomString = -1;
static gint hf_pawned_userString = -1;
static gint hf_pawned_passString = -1;
static gint hf_pawned_dataString = -1;
static gint hf_pawned_messageString = -1;
static gint hf_pawned_commentString = -1;
static gint hf_pawned_skillCode = -1;
static gint hf_pawned_templateCode = -1;
static gint hf_pawned_equipmentCode = -1;
static gint hf_pawned_channels = -1;
static gint hf_pawned_users = -1;
static gint hf_pawned_frames = -1;
static gint hf_pawned_requests = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_pawned = -1;
static gint ett_pawned_action = -1;
static gint ett_pawned_result = -1;
static gint ett_pawned_room = -1;
static gint ett_pawned_user = -1;
static gint ett_pawned_userCount = -1;
static gint ett_pawned_slot = -1;
static gint ett_pawned_slotCount = -1;
static gint ett_pawned_slotTarget = -1;
static gint ett_pawned_roomString = -1;
static gint ett_pawned_userString = -1;
static gint ett_pawned_passString = -1;
static gint ett_pawned_dataString = -1;
static gint ett_pawned_messageString = -1;
static gint ett_pawned_commentString = -1;
static gint ett_pawned_skillCode = -1;
static gint ett_pawned_templateCode = -1;
static gint ett_pawned_equipmentCode = -1;
static gint ett_pawned_channels = -1;
static gint ett_pawned_users = -1;
static gint ett_pawned_frames = -1;
static gint ett_pawned_requests = -1;


static guint32 dissect_pawned_request(proto_tree *pawned_tree, tvbuff_t *tvb, guint32 offset, int length)
{
	guint8 action = tvb_get_guint8(tvb, offset);
	offset += 1;

	switch(action)
	{
		case USER_ROOM_JOIN:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_roomString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_passString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_ROOM_PART:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_SEND_MESSAGE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_messageString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_ROOM_CHANGE_NAME:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_ROOM_UPDATE_USER:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_UPDATE_SLOT:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_CHANGE_PASS:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_passString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_passString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_SLOT_CREATE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_DELETE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_SWAP:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_slotTarget, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_MOVE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_slotTarget, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_COPY:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_slotTarget, tvb, offset, 1, FALSE);
			offset += 1;
		break;

		case USER_SLOT_UPDATE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_skillCode, tvb, offset, 37, FALSE);
			offset += 37;

			proto_tree_add_item(pawned_tree, hf_pawned_templateCode, tvb, offset, 47, FALSE);
			offset += 47;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_messageString, tvb, offset, 256, FALSE);
			offset += 256;

			proto_tree_add_item(pawned_tree, hf_pawned_dataString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_SLOT_CHANGE_SKILL:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_skillCode, tvb, offset, 37, FALSE);
			offset += 37;
		break;

		case USER_SLOT_CHANGE_TEMPLATE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_templateCode, tvb, offset, 47, FALSE);
			offset += 47;
		break;

		case USER_SLOT_CHANGE_EQUIPMENT:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;
		break;

		case USER_SLOT_CHANGE_INFO:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_messageString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_SLOT_CHANGE_DATA:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_dataString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_STAT:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_PING:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		default:
			proto_tree_add_item(pawned_tree, hf_pawned, tvb, offset, length-offset, FALSE);
			offset += length;
		break;
	}
	return offset;
}

static guint32 dissect_pawned_response(proto_tree *pawned_tree, tvbuff_t *tvb, guint32 offset, int length)
{
	guint8 action = tvb_get_guint8(tvb, offset);
	offset += 1;

	switch(action)
	{
		case USER_ROOM_JOIN:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_result, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_SEND_MESSAGE:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_user, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_messageString, tvb, offset, 256, FALSE);
			offset += 256;
		break;

		case USER_ROOM_CHANGE_PASS:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_result, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_ROOM_UPDATE_USER:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_user, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_userCount, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_ROOM_UPDATE_SLOT:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_user, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_userString, tvb, offset, 32, FALSE);
			offset += 32;

			proto_tree_add_item(pawned_tree, hf_pawned_slot, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_slotCount, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(pawned_tree, hf_pawned_skillCode, tvb, offset, 37, FALSE);
			offset += 37;

			proto_tree_add_item(pawned_tree, hf_pawned_templateCode, tvb, offset, 47, FALSE);
			offset += 47;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_equipmentCode, tvb, offset, 17, FALSE);
			offset += 17;

			proto_tree_add_item(pawned_tree, hf_pawned_messageString, tvb, offset, 256, FALSE);
			offset += 256;

			proto_tree_add_item(pawned_tree, hf_pawned_dataString, tvb, offset, 32, FALSE);
			offset += 32;
		break;

		case USER_STAT:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_channels, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_users, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_frames, tvb, offset, 4, TRUE);
			offset += 4;

			proto_tree_add_item(pawned_tree, hf_pawned_requests, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		case USER_PING:
			proto_tree_add_item(pawned_tree, hf_pawned_room, tvb, offset, 4, TRUE);
			offset += 4;
		break;

		default:
			proto_tree_add_item(pawned_tree, hf_pawned, tvb, offset, length-offset, FALSE);
			offset += length;
		break;
	}
	return offset;
}

static guint get_pawned_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    guint8 action = tvb_get_guint8(tvb, 0);

	int i;
	if (pinfo->match_port == pinfo->destport || TCP_PORT_PAWNED == pinfo->destport) {
		for (i=0; i<sizeof(PacketActionRequestLength); i++)
			if (PacketActionRequestLength[i].value == action)
				return PacketActionRequestLength[i].guint;
	} else {
		for (i=0; i<sizeof(PacketActionResponseLength); i++)
			if (PacketActionResponseLength[i].value == action)
				return PacketActionResponseLength[i].guint;
	}

	return (guint)(tvb_length(tvb)-offset);
}


static void dissect_pawned_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *pawned_item = NULL;
	proto_tree *pawned_tree = NULL;
	guint32 offset = 0;
	guint32 length = tvb_length(tvb);
	guint8 action = 0;

	if (length >= 1)
		action = tvb_get_guint8(tvb, 0);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_PAWNED);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d - %s %s", 
			pinfo->srcport, 
			pinfo->destport, 
				(pinfo->match_port == pinfo->destport || TCP_PORT_PAWNED == pinfo->destport) ? "Request" : "Response", 
				val_to_str(action, PacketActionNames, "Unknown Action: 0x%02x")
		);
	}

	if (tree) { /* we are being asked for details */
		pawned_item = proto_tree_add_item(tree, proto_pawned, tvb, 0, -1, FALSE);
		pawned_tree = proto_item_add_subtree(pawned_item, ett_pawned);

		proto_tree_add_item(pawned_tree, hf_pawned_action, tvb, offset, 1, FALSE);

		if (pinfo->match_port == pinfo->destport || TCP_PORT_PAWNED == pinfo->destport)
			offset = dissect_pawned_request(pawned_tree, tvb, offset, length);
		else
			offset = dissect_pawned_response(pawned_tree, tvb, offset, length);
	}
}

static void dissect_pawned(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_pawned_message_len, dissect_pawned_struct);
}

void proto_register_pawned(void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_pawned,
			{ "Data", "pawned.data", FT_NONE, BASE_NONE, NULL, 0x0, "Pawned Data", HFILL }
		},
		{ &hf_pawned_action,
			{ "Action", "pawned.action", FT_UINT8, BASE_DEC, VALS(PacketActionNames), 0x0, "Action ID", HFILL }
		},
		{ &hf_pawned_result,
			{ "Result", "pawned.result", FT_UINT32, BASE_DEC, NULL, 0x0, "Result", HFILL }
		},
		{ &hf_pawned_room,
			{ "Room", "pawned.room", FT_UINT32, BASE_DEC, NULL, 0x0, "Room ID", HFILL }
		},
		{ &hf_pawned_user,
			{ "User", "pawned.user", FT_UINT8, BASE_DEC, NULL, 0x0, "User ID", HFILL }
		},
		{ &hf_pawned_userCount,
			{ "User Count", "pawned.userCount", FT_UINT8, BASE_DEC, NULL, 0x0, "User Count", HFILL }
		},
		{ &hf_pawned_slot,
			{ "Slot", "pawned.slot", FT_UINT8, BASE_DEC, NULL, 0x0, "Slot ID", HFILL }
		},
		{ &hf_pawned_slotCount,
			{ "Slot Count", "pawned.slotCount", FT_UINT8, BASE_DEC, NULL, 0x0, "Slot Count", HFILL }
		},
		{ &hf_pawned_slotTarget,
			{ "Slot Target", "pawned.slotTarget", FT_UINT8, BASE_DEC, NULL, 0x0, "Slot Target", HFILL }
		},
		{ &hf_pawned_roomString,
			{ "Room String", "pawned.roomString", FT_STRING, BASE_NONE, NULL, 0x0, "Roomname", HFILL }
		},
		{ &hf_pawned_userString,
			{ "User String", "pawned.userString", FT_STRING, BASE_NONE, NULL, 0x0, "Username", HFILL }
		},
		{ &hf_pawned_passString,
			{ "Pass String", "pawned.passString", FT_STRING, BASE_NONE, NULL, 0x0, "Password", HFILL }
		},
		{ &hf_pawned_dataString,
			{ "Data String", "pawned.dataString", FT_STRING, BASE_NONE, NULL, 0x0, "Data", HFILL }
		},
		{ &hf_pawned_messageString,
			{ "Message String", "pawned.messageString", FT_STRING, BASE_NONE, NULL, 0x0, "Message", HFILL }
		},
		{ &hf_pawned_commentString,
			{ "Comment String", "pawned.commentString", FT_STRING, BASE_NONE, NULL, 0x0, "Comment", HFILL }
		},
		{ &hf_pawned_skillCode,
			{ "Skill String", "pawned.skillCode", FT_STRING, BASE_NONE, NULL, 0x0, "Skill", HFILL }
		},
		{ &hf_pawned_templateCode,
			{ "Template String", "pawned.templateCode", FT_STRING, BASE_NONE, NULL, 0x0, "Template", HFILL }
		},
		{ &hf_pawned_equipmentCode,
			{ "Equipment String", "pawned.equipmentCode", FT_STRING, BASE_NONE, NULL, 0x0, "Equipment", HFILL }
		},
		{ &hf_pawned_channels,
			{ "Channels", "pawned.channels", FT_UINT32, BASE_DEC, NULL, 0x0, "Channel", HFILL }
		},
		{ &hf_pawned_users,
			{ "Users", "pawned.users", FT_UINT32, BASE_DEC, NULL, 0x0, "Users", HFILL }
		},
		{ &hf_pawned_frames,
			{ "Frames", "pawned.frames", FT_UINT32, BASE_DEC, NULL, 0x0, "Frames", HFILL }
		},
		{ &hf_pawned_requests,
			{ "Requests", "pawned.requests", FT_UINT32, BASE_DEC, NULL, 0x0, "Requests", HFILL }
		}
	};
	static gint *ett[] = {
		&ett_pawned,
		&ett_pawned_action,
		&ett_pawned_result,
		&ett_pawned_room,
		&ett_pawned_user,
		&ett_pawned_userCount,
		&ett_pawned_slot,
		&ett_pawned_slotCount,
		&ett_pawned_slotTarget,
		&ett_pawned_roomString,
		&ett_pawned_userString,
		&ett_pawned_passString,
		&ett_pawned_dataString,
		&ett_pawned_messageString,
		&ett_pawned_commentString,
		&ett_pawned_skillCode,
		&ett_pawned_templateCode,
		&ett_pawned_equipmentCode,
		&ett_pawned_channels,
		&ett_pawned_users,
		&ett_pawned_frames,
		&ett_pawned_requests
	};

	proto_pawned = proto_register_protocol("Pawned Protocol", PROTO_TAG_PAWNED, "pawned");
	proto_register_field_array(proto_pawned, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length (ett));

	register_dissector("pawned", dissect_pawned, proto_pawned);
}

void proto_reg_handoff_pawned(void)
{
	static int pawned_initialized = FALSE;
	static dissector_handle_t pawned_handle;

	if(!pawned_initialized)
	{
        pawned_handle = create_dissector_handle(dissect_pawned, proto_pawned);
        pawned_initialized = TRUE;
	}
	else
	{
		dissector_delete("tcp.port", TCP_PORT_PAWNED, pawned_handle);
	}

	dissector_add("tcp.port", TCP_PORT_PAWNED, pawned_handle);
}