-- -*- coding: utf-8 -*-
-- DVRIP Wireshark Dissector for Port 37777
-- Copyright (C) 2020  Thomas Vogt
-- Modified the code to dissect DVRIP/Sofia running on Port 34567 on Xiongmai-based cameras
-- Copyright (C) 2026 Kostas Ereksonas
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- Header length for Xiongmai DVRIP/Sofia is 20 bytes
local HEADER_LEN = 20

-- Load JSON dissector
json = Dissector.get("json")

-- Reassemble multiple TCP packets into a single Protocol Data Unit (PDU)
local tcp_dissect_pdus = Dissector.get("tcp_dissect_pdus")

-- Definition of the overall protocol name
XM_proto = Proto("dvrip", "Xiongmai DVRIP Protocol")

-- DVRIP/Sofia packet header fields
DVRIP_header = ProtoField.uint8("dvrip.header", "Header", base.HEX_DEC)
DVRIP_req_resp = ProtoField.uint8("dvrip.req_resp", "Request/response", base.HEX_DEC)
DVRIP_header_unknown = ProtoField.uint8("dvrip.header_unknown", "Unknown", base.HEX_DEC)
DVRIP_session_id = ProtoField.uint32("dvrip.session_id", "Session ID", base.HEX_DEC)
DVRIP_sequence_id = ProtoField.uint32("dvrip.sequence_id", "Sequence ID", base.HEX_DEC)
DVRIP_unknown = ProtoField.uint16("dvrip.unknown", "Unknown", base.HEX_DEC)
DVRIP_command_code = ProtoField.uint16("dvrip.command_code", "Command Code", base.HEX_DEC)
DVRIP_payload_length = ProtoField.uint32("dvrip.payload_length", "Payload Length", base.HEX_DEC)
DVRIP_payload_JSON_RAW = ProtoField.string("dvrip.data", "Raw JSON Message")
DVRIP_newline = ProtoField.uint16("dvrip.newline", "Newline", base.HEX_DEC)

-- I-Frame fields
DVRIP_iframe_signature = ProtoField.uint32("dvrip.iframe_signature", "I-Frame signature", base.HEX_DEC)
DVRIP_iframe_unknown_1 = ProtoField.uint32("dvrip.iframe_unknown_1", "Unknown 1", base.HEX_DEC)
DVRIP_iframe_unknown_2 = ProtoField.uint32("dvrip.iframe_unknown_2", "Unknown 2", base.HEX_DEC)
DVRIP_iframe_payload_size = ProtoField.uint32("dvrip.iframe_payload_size", "Payload size", base.HEX_DEC)
DVRIP_iframe_unknown_3 = ProtoField.uint32("dvrip.iframe_unknown_3", "Unknown 3", base.HEX_DEC)

-- P-Frame fields
DVRIP_pframe_signature = ProtoField.uint16("dvrip.pframe_signature", "P-Frame signature", base.HEX_DEC)
DVRIP_pframe_payload_length = ProtoField.uint16("dvrip.pframe_payload_length", "P-frame payload length", base.HEX_DEC)
DVRIP_pframe_unknown_1 = ProtoField.uint16("dvrip.pframe_unknown_1", "Unknown 1", base.HEX_DEC)
DVRIP_pframe_unknown_2 = ProtoField.uint32("dvrip.pframe_unknown_2", "Unknown 2", base.HEX_DEC)

-- A-Frame (Audio) packet fields
DVRIP_audio_signature = ProtoField.uint32("dvrip.audio_signature", "Audio signature", base.HEX_DEC)
DVRIP_audio_unknown = ProtoField.uint16("dvrip.audio_unknown", "Audio unknown", base.HEX_DEC)
DVRIP_audio_payload_length = ProtoField.uint16("dvrip.audio_payload_length", "Audio payload length", base.HEX_DEC)

-- E-Frame (Encoding) packet fields
DVRIP_eframe_signature = ProtoField.uint32("dvrip.eframe_signature", "Encoding signature", base.HEX_DEC)
DVRIP_eframe_unknown_1 = ProtoField.uint32("dvrip.eframe_unknown_1", "Unknown Field 1", base.HEX_DEC)
DVRIP_eframe_sequence_id = ProtoField.uint8("dvrip.eframe_sequence_id", "E-Frame sequence ID", base.HEX_DEC)
DVRIP_eframe_unknown_2 = ProtoField.uint32("dvrip.eframe_unknown_2", "Unknown Field 2", base.HEX_DEC)
DVRIP_eframe_unknown_3 = ProtoField.uint16("dvrip.eframe_unknown_3", "Unknown Field 3", base.HEX_DEC)
DVRIP_eframe_unknown_4 = ProtoField.uint16("dvrip.eframe_unknown_4", "Unknown Field 4", base.HEX_DEC)
DVRIP_eframe_unknown_5 = ProtoField.uint32("dvrip.eframe_unknown_5", "Unknown Field 5", base.HEX_DEC)
DVRIP_eframe_unknown_6 = ProtoField.uint32("dvrip.eframe_unknown_6", "Unknown Field 6", base.HEX_DEC)

-- List of DVRIP/Sofia protocol fields
XM_proto.fields = {
	-- DVRIP header fields
	DVRIP_header,
	DVRIP_req_resp,
	DVRIP_header_unknown,
	DVRIP_session_id,
	DVRIP_sequence_id,
	DVRIP_unknown,
	DVRIP_command_code,
	DVRIP_payload_length,
	-- DVRIP JSON payload fields
	DVRIP_payload_JSON_RAW,
	DVRIP_newline,
	-- DVRIP I-Frame fields
	DVRIP_iframe_signature,
	DVRIP_iframe_unknown_1,
	DVRIP_iframe_unknown_2,
	DVRIP_iframe_payload_size,
	DVRIP_iframe_unknown_3,
	-- DVRIP P-Frame fields
	DVRIP_pframe_signature,
	DVRIP_pframe_payload_length,
	DVRIP_pframe_unknown_1,
	DVRIP_pframe_unknown_2,
	-- DVRIP A-Frame (audio) fields
	DVRIP_audio_signature,
	DVRIP_audio_unknown,
	DVRIP_audio_payload_length,
	-- DVRIP E-Frame (encoding) fields
	DVRIP_eframe_signature,
	DVRIP_eframe_unknown_1,
	DVRIP_eframe_sequence_id,
	DVRIP_eframe_unknown_2,
	DVRIP_eframe_unknown_3,
	DVRIP_eframe_unknown_4,
	DVRIP_eframe_unknown_5,
	DVRIP_eframe_unknown_6
}

local function dvrip_get_len(tvb, pinfo, offset)
	-- if header is truncated, get subsequent TCP packet
	if tvb:len() - offset < HEADER_LEN then
		return 0
	end

	-- JSON payload length is at offset 16 (little-endian)
	local payload_length = tvb(offset + 16, 4):le_uint()

	-- total = header + JSON body
	local total_len = HEADER_LEN + payload_length

	return total_len
end

local function dvrip_dissect_one_pdu(tvb, pinfo, tree)
	pinfo.cols.protocol = XM_proto.name

	local subtree = tree:add(XM_proto, tvb(), "Xiongmai DVRIP Protocol")
	local header = subtree:add(XM_proto, tvb(0, 20), "DVRIP Header")
	
	header:add_le(DVRIP_header, tvb(0, 1))
	header:add_le(DVRIP_req_resp, tvb(1, 1))
	header:add_le(DVRIP_header_unknown, tvb(2,2))
	header:add_le(DVRIP_session_id, tvb(4, 4))
	header:add_le(DVRIP_sequence_id, tvb(8, 4))
	header:add_le(DVRIP_unknown, tvb(12, 2))
	header:add_le(DVRIP_command_code, tvb(14, 2))
	header:add_le(DVRIP_payload_length, tvb(16, 4))

	if tvb:len() > HEADER_LEN then
		-- Get JSON payload
		if tvb(HEADER_LEN, 1):uint() == 0x7b and tvb(14, 2):le_uint() ~= 0x0584 then -- 0x7b = {; 0x0584 = 1412
			-- Length of payload
			local payload_length = tvb(16, 4):le_uint()
			
			-- Handle trailing newline (last 1 or 2 bytes of a payload)
			local json_tvb
			if tvb(HEADER_LEN + payload_length - 1, 1):le_uint() ~= 0x0a then
				json_tvb = tvb(HEADER_LEN, payload_length - 2) -- last 2 bytes are newline
			else
				json_tvb = tvb(HEADER_LEN, payload_length - 1) -- last byte is newline
			end

			-- raw JSON text
			subtree:add(DVRIP_payload_JSON_RAW, json_tvb)

			-- decode JSON object using built-in dissector
			json:call(json_tvb:tvb(), pinfo, subtree)

			-- Add newline as a separate protocol subtree entry
			local trailing = HEADER_LEN + json_tvb:len()
			if tvb:len() > trailing then
				subtree:add_le(DVRIP_newline, tvb(trailing, tvb:len() - trailing))
			end
        else
			-- Signature of media payload
			local signature = tvb(HEADER_LEN, 4):uint()
			if signature == 0x000001fa then -- Audio
				local atree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Audio")
				local atree_header = atree:add(XM_proto, tvb(HEADER_LEN, 8), "Audio Header")
				-- Audio frame payload reconstruction
				local aframe_length = tvb(HEADER_LEN + 6, 2):le_uint()
				-- Populate Audio Frame header fields
				atree_header:add(DVRIP_audio_signature, tvb(HEADER_LEN, 4))
				atree_header:add_le(DVRIP_audio_unknown, tvb(HEADER_LEN + 4, 2))
				atree_header:add_le(DVRIP_audio_payload_length, tvb(HEADER_LEN + 6, 2))
				-- Audio Frame payload
				atree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "A-Frame")
			elseif signature == 0x000001fc then -- I-Frame
				-- Add I-Frame to general tree
				local itree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP I-Frame")
				local itree_header = itree:add(XM_proto, tvb(HEADER_LEN, 20), "I-Frame Header")
				-- Populate I-Frame header fields
				itree_header:add(DVRIP_iframe_signature, tvb(HEADER_LEN, 4))
				itree_header:add_le(DVRIP_iframe_unknown_1, tvb(HEADER_LEN + 4, 4))
				itree_header:add_le(DVRIP_iframe_unknown_2, tvb(HEADER_LEN + 8, 4))
				itree_header:add_le(DVRIP_iframe_payload_size, tvb(HEADER_LEN + 12, 4))
				itree_header:add(DVRIP_iframe_unknown_3, tvb(HEADER_LEN + 16, 4))
				-- I-Frame payload
				itree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "I-Frame")
			elseif signature == 0x000001fd then -- P-Frame
				-- Add P-Frame to general tree
				local ptree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP P-Frame")
				local ptree_header = ptree:add(XM_proto, tvb(HEADER_LEN, 12), "P-Frame Header")
				-- P-Frame payload reconstruction
				local pframe_length = tvb(HEADER_LEN + 4, 2):le_uint()
				-- Populate P-Frame header fields
				ptree_header:add(DVRIP_pframe_signature, tvb(HEADER_LEN, 4))
				ptree_header:add_le(DVRIP_pframe_payload_length, tvb(HEADER_LEN + 4, 2))
				ptree_header:add_le(DVRIP_pframe_unknown_1, tvb(HEADER_LEN + 6, 2))
				ptree_header:add(DVRIP_pframe_unknown_2, tvb(HEADER_LEN + 8, 4))
				-- P-Frame payload
				ptree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "P-Frame")
			elseif signature == 0x000001f9 then
				-- Add E-Frame to general tree
				local etree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP E-Frame")
				local etree_header = etree:add(XM_proto, tvb(HEADER_LEN, 24), "E-Frame Header")
				-- Populate E-Frame header fields
				etree_header:add(DVRIP_eframe_signature, tvb(HEADER_LEN, 4))
				etree_header:add(DVRIP_eframe_unknown_1, tvb(HEADER_LEN + 4, 4))
				etree_header:add(DVRIP_eframe_sequence_id, tvb(HEADER_LEN + 8, 1))
				etree_header:add(DVRIP_eframe_unknown_2, tvb(HEADER_LEN + 9, 3))
				etree_header:add(DVRIP_eframe_unknown_3, tvb(HEADER_LEN + 12, 2))
				etree_header:add(DVRIP_eframe_unknown_4, tvb(HEADER_LEN + 14, 2))
				etree_header:add(DVRIP_eframe_unknown_5, tvb(HEADER_LEN + 16, 4))
				etree_header:add(DVRIP_eframe_unknown_6, tvb(HEADER_LEN + 20, 4))
			else
				subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Media (Continuation)")
			end
		end
	end
	return tvb:len() -- amount of bytes consumed
end

function XM_proto.dissector(tvb, pinfo, tree)
	if tvb:len() == 0 then
		return
	end
	dissect_tcp_pdus(tvb, tree, 20, dvrip_get_len, dvrip_dissect_one_pdu, true)
end

-- assigning protocol to port
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(34567, XM_proto)
udp_table = DissectorTable.get("udp.port")
udp_table:add(34569, XM_proto)