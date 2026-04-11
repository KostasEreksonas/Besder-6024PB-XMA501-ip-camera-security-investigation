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

-- Signatures of DVRIP/Sofia media messages
local SIG_AUDIO   = 0x000001fa
local SIG_IFRAME  = 0x000001fc
local SIG_PFRAME  = 0x000001fd
local SIG_INFOFRAME = 0x000001f9

-- Load JSON dissector
local json = Dissector.get("json")

-- Definition of the overall protocol name
XM_proto = Proto("dvrip", "Xiongmai DVRIP Protocol")

-- DVRIP/Sofia packet header fields
DVRIP_header = ProtoField.uint8("dvrip.header", "Header", base.DEC_HEX)
DVRIP_req_resp = ProtoField.uint8("dvrip.req_resp", "Request/Response", base.DEC_HEX)
DVRIP_reserved_1 = ProtoField.uint8("dvrip.reserved_1", "Reserved 1", base.DEC_HEX)
DVRIP_reserved_2 = ProtoField.uint8("dvrip.reserved_2", "Reserved 2", base.DEC_HEX)
DVRIP_session_id = ProtoField.uint32("dvrip.session_id", "Session ID", base.DEC_HEX)
DVRIP_sequence_id = ProtoField.uint32("dvrip.sequence_id", "Sequence ID", base.DEC_HEX)
DVRIP_total_packets = ProtoField.uint8("dvrip.total_packets", "Total Packets", base.DEC_HEX)
DVRIP_current_packet = ProtoField.uint8("dvrip.current_packet", "Current Packet", base.DEC_HEX)
DVRIP_command_code = ProtoField.uint16("dvrip.command_code", "Command Code", base.DEC_HEX)
DVRIP_payload_size = ProtoField.uint32("dvrip.payload_size", "Payload Size", base.DEC_HEX)

-- DVRIP/Sofia JSON payload fields
DVRIP_payload_JSON_RAW = ProtoField.string("dvrip.data", "Raw JSON Message")
DVRIP_newline = ProtoField.uint16("dvrip.newline", "Newline", base.DEC_HEX)

-- DVRIP media signature field
DVRIP_signature = ProtoField.uint32("dvrip.signature", "Signature", base.HEX_DEC)

-- Stream type
DVRIP_stream_type = ProtoField.uint8("dvrip.stream_type", "Stream Type", base.HEX_DEC)

-- Framereate
DVRIP_framerate = ProtoField.uint8("dvrip.framerate", "Framerate", base.DEC_HEX)

-- DVRIP image dimensions - used both for I-Frames (FC) and snapshots (FE)
DVRIP_width = ProtoField.uint8("dvrip.width", "Width", base.DEC_HEX)
DVRIP_height = ProtoField.uint8("dvrip.height", "Height", base.DEC_HEX)

-- Start date of a stream
DVRIP_datetime = ProtoField.uint32("dvrip.datetime", "Datetime", base.DEC_HEX)

-- I-Frame (FC) fields
DVRIP_media_payload_size = ProtoField.uint32("dvrip.media_payload_size", "Payload Size", base.DEC_HEX)

-- Audio sampling rate
DVRIP_sampling_rate = ProtoField.uint8("dvrip.sampling_rate", "Audio Sampling Rate", base.DEC_HEX)

-- Unused field in information frame (F9)
DVRIP_unused_field = ProtoField.uint8("dvrip.unused_field", "Unused Field", base.DEC_HEX)

-- List of DVRIP/Sofia protocol fields
XM_proto.fields = {
	-- DVRIP header fields
	DVRIP_header,
	DVRIP_req_resp,
	DVRIP_reserved_1,
	DVRIP_reserved_2,
	DVRIP_session_id,
	DVRIP_sequence_id,
	DVRIP_total_packets,
	DVRIP_current_packet,
	DVRIP_command_code,
	DVRIP_payload_size,
	-- DVRIP JSON payload fields
	DVRIP_payload_JSON_RAW,
	DVRIP_newline,
	-- Media frame payload size
	DVRIP_media_payload_size,
	-- DVRIP media signature
	DVRIP_signature,
	-- Stream type
	DVRIP_stream_type,
	-- Framerate
	DVRIP_framerate,
	-- Image dimensions
	DVRIP_width,
	DVRIP_height,
	-- Stream start date
	DVRIP_datetime,
	-- DVRIP A-Frame (audio) fields
	DVRIP_sampling_rate,
	-- DVRIP E-Frame (encoding) fields
	DVRIP_unused_field
}

local function dvrip_get_len(tvb, pinfo, offset)
	pinfo.cols.info = "JSON command code = " .. string.format("%04d", tvb(14,2):le_uint()) .. " "
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

function build_protocol_tree(tvb, pinfo, subtree, payload_length, json)
	-- Handle trailing newline (last 1 or 2 bytes of a payload)
	local json_tvb
	if tvb(HEADER_LEN + payload_length - 1, 1):le_uint() ~= 0x0a then
		json_tvb = tvb(HEADER_LEN, payload_length - 2) -- last 2 bytes are newline
	else
		json_tvb = tvb(HEADER_LEN, payload_length - 1) -- last byte is newline
	end

	-- Raw JSON text
	subtree:add(DVRIP_payload_JSON_RAW, json_tvb)

	-- Decode JSON object using built-in dissector
	json:call(json_tvb:tvb(), pinfo, subtree)

	-- Add newline as a separate protocol subtree entry
	local trailing = HEADER_LEN + json_tvb:len()
	if tvb:len() > trailing then
		subtree:add_le(DVRIP_newline, tvb(trailing, tvb:len() - trailing))
	end
end

function populate_audio_tree(tvb, subtree)
	local atree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Audio")
	local atree_header = atree:add(XM_proto, tvb(HEADER_LEN, 8), "Header")

	-- Audio frame payload reconstruction
	local aframe_length = tvb(HEADER_LEN + 6, 2):le_uint()

	-- Populate Audio Frame header fields
	atree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	atree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
	atree_header:add_le(DVRIP_sampling_rate, tvb(HEADER_LEN + 5, 1))
	atree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 6, 2))

	-- Audio Frame payload
	local audio_length = tvb(HEADER_LEN + 6, 2):le_uint()
	atree:add(XM_proto, tvb(HEADER_LEN + 8, audio_length), "Payload")
end

function populate_iframe_tree(tvb, subtree)
	-- Add I-Frame to general tree
	local itree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP I-Frame")
	local itree_header = itree:add(XM_proto, tvb(HEADER_LEN, 20), "I-Frame Header")

	-- Populate I-Frame header fields
	itree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	itree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
	itree_header:add_le(DVRIP_framerate, tvb(HEADER_LEN + 5, 1))
	itree_header:add_le(DVRIP_width, tvb(HEADER_LEN + 6, 1))
	itree_header:add_le(DVRIP_height, tvb(HEADER_LEN + 7, 1))
	itree_header:add_le(DVRIP_datetime, tvb(HEADER_LEN + 8, 4))
	itree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 12, 4))

	-- I-Frame payload
	itree:add(XM_proto, tvb(HEADER_LEN + 16, tvb:len() - HEADER_LEN - 16), "I-Frame")
end

function populate_pframe_tree(tvb, subtree)
	-- Add P-Frame to general tree
	local ptree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP P-Frame")
	local ptree_header = ptree:add(XM_proto, tvb(HEADER_LEN, 12), "P-Frame Header")

	-- P-Frame payload reconstruction
	local pframe_length = tvb(HEADER_LEN + 4, 4):le_uint()

	-- Populate P-Frame header fields
	ptree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	ptree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 4, 4))

	-- P-Frame payload
	ptree:add(XM_proto, tvb(HEADER_LEN + 8, tvb:len() - HEADER_LEN - 8), "P-Frame")
end

function populate_infoframe_tree(tvb, subtree)
	-- Add Information Frame to general tree
	local infotree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Information Frame")
	local infotree_header = infotree:add(XM_proto, tvb(HEADER_LEN, 8), "Header")

	-- Populate Information Frame header fields
	infotree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	infotree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
	infotree_header:add_le(DVRIP_unused_field, tvb(HEADER_LEN + 5, 1))
	infotree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 6, 2))

	-- Add information frame payload to the general tree
	infotree:add(XM_proto, tvb(HEADER_LEN + 8, tvb:len() - HEADER_LEN - 8), "Payload")
end

function build_protocol_media_tree(tvb, pinfo, subtree)
	local signature = tvb(HEADER_LEN, 4):uint()
	pinfo.cols.info = "Media signature = " .. string.format("%08x", signature) .. " "
	if signature == SIG_AUDIO then -- Audio
		populate_audio_tree(tvb, subtree)
	elseif signature == SIG_IFRAME then -- I-Frame
		populate_iframe_tree(tvb, subtree)
	elseif signature == SIG_PFRAME then -- P-Frame
		populate_pframe_tree(tvb, subtree)
	elseif signature == SIG_INFOFRAME then -- Information Frame
		populate_infoframe_tree(tvb, subtree)
	else
		subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Media (Continuation)")
	end
end

local function dvrip_dissect_one_pdu(tvb, pinfo, tree)
	pinfo.cols.protocol = XM_proto.name

	local subtree = tree:add(XM_proto, tvb(), "Xiongmai DVRIP Protocol")
	local header = subtree:add(XM_proto, tvb(0, 20), "DVRIP Header")

	header:add_le(DVRIP_header, tvb(0, 1))
	header:add_le(DVRIP_req_resp, tvb(1, 1))
	header:add_le(DVRIP_reserved_1, tvb(2, 1))
	header:add_le(DVRIP_reserved_2, tvb(3, 1))
	header:add_le(DVRIP_session_id, tvb(4, 4))
	header:add_le(DVRIP_sequence_id, tvb(8, 4))
	header:add_le(DVRIP_total_packets, tvb(12, 1))
	header:add_le(DVRIP_current_packet, tvb(13, 1))
	header:add_le(DVRIP_command_code, tvb(14, 2))
	header:add_le(DVRIP_payload_size, tvb(16, 4))

	if tvb:len() > HEADER_LEN then
		-- Lenght of a DVRIP/Sofia message (without 20-bit header)
		local payload_length = tvb(16, 4):le_uint()

		-- Build protocol tree with control flow messages (JSON-based) and media payloads
		if tvb(HEADER_LEN, 1):uint() == 0x7b and tvb(14, 2):le_uint() ~= 0x0584 then -- 0x7b = {; 0x0584 = 1412
			build_protocol_tree(tvb, pinfo, subtree, payload_length, json)
		else
			build_protocol_media_tree(tvb, pinfo, subtree)
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