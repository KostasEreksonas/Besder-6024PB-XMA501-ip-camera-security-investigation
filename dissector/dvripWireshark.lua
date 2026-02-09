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

-- Protocol tree fields shown in Wireshark
DVRIP_header = ProtoField.uint16("dvrip.header", "Header", base.HEX_DEC)
DVRIP_req_resp = ProtoField.uint16("dvrip.req_resp", "Request/response", base.HEX_DEC)
DVRIP_session_id = ProtoField.uint16("dvrip.session_id", "Session ID", base.HEX_DEC)
DVRIP_sequence_id = ProtoField.uint16("dvrip.sequence_id", "Sequence ID", base.HEX_DEC)
DVRIP_unknown = ProtoField.uint16("dvrip.unknown", "Unknown", base.HEX_DEC)
DVRIP_command_code = ProtoField.uint16("dvrip.command_code", "Command Code", base.HEX_DEC)
DVRIP_payload_length = ProtoField.uint16("dvrip.payload_length", "Payload Length", base.HEX_DEC)
DVRIP_payload_JSON_RAW = ProtoField.string("dvrip.data", "Raw JSON Message")
DVRIP_newline = ProtoField.uint16("dvrip.newline", "Newline", base.HEX_DEC)

XM_proto.fields = {
	DVRIP_header,
	DVRIP_req_resp,
	DVRIP_session_id,
	DVRIP_sequence_id,
	DVRIP_unknown,
	DVRIP_command_code,
	DVRIP_payload_length,
	DVRIP_payload_JSON_RAW,
	DVRIP_newline,
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
	header:add_le(DVRIP_req_resp, tvb(1, 3))
	header:add_le(DVRIP_session_id, tvb(4, 4))
	header:add_le(DVRIP_sequence_id, tvb(8, 4))
	header:add_le(DVRIP_unknown, tvb(12, 2))
	header:add_le(DVRIP_command_code, tvb(14, 2))
	header:add_le(DVRIP_payload_length, tvb(16, 4))

	if tvb:len() > HEADER_LEN then
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
			subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len()-HEADER_LEN), "DVRIP Media")
		end
	end

	return tvb:len() -- amount of bytes consumed
end

function XM_proto.dissector(tvb, pinfo, tree)
	if tvb:len() == 0 then
		return
	end

	-- 0 = initial offset
	-- dvrip_get_len = function that returns full PDU length
	-- dvrip_dissect_one_pdu = function that dissects one complete DVRIP message
	-- true = handle multiple PDUs per TCP segment [web:61][web:63]
	dissect_tcp_pdus(tvb, tree, 0, dvrip_get_len, dvrip_dissect_one_pdu, true)
end

-- assigning protocol to port
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(34567, XM_proto)
udp_table = DissectorTable.get("udp.port")
udp_table:add(34569, XM_proto)
