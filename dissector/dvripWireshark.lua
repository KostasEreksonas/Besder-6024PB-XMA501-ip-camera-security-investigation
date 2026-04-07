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

-- Table to collect media frame data from multiple DVRIP/Sofia packets
frame = {
	key = nil,
	bytes_needed = 0,
	bytes_collected = 0,
	payload = ByteArray.new(),
	sequence_packet_first = 0,
	sequence_packet_last = 0,
}

-- Time of capture start / open
timestamp = os.time(os.date("!*t"))

-- Reassemble multiple TCP packets into a single Protocol Data Unit (PDU)
local tcp_dissect_pdus = Dissector.get("tcp_dissect_pdus")

-- Definition of the overall protocol name
XM_proto = Proto("dvrip", "Xiongmai DVRIP Protocol")

-- DVRIP/Sofia packet header fields
DVRIP_header = ProtoField.uint8("dvrip.header", "Header", base.DEC_HEX)
DVRIP_req_resp = ProtoField.uint8("dvrip.req_resp", "Request/response", base.DEC_HEX)
DVRIP_header_unknown = ProtoField.uint8("dvrip.header_unknown", "Unknown", base.DEC_HEX)
DVRIP_session_id = ProtoField.uint32("dvrip.session_id", "Session ID", base.DEC_HEX)
DVRIP_sequence_id = ProtoField.uint32("dvrip.sequence_id", "Sequence ID", base.DEC_HEX)
DVRIP_unknown = ProtoField.uint16("dvrip.unknown", "Unknown", base.DEC_HEX)
DVRIP_command_code = ProtoField.uint16("dvrip.command_code", "Command Code", base.DEC_HEX)
DVRIP_payload_length = ProtoField.uint32("dvrip.payload_length", "Payload Length", base.DEC_HEX)

-- DVRIP/Sofia JSON payload fields
DVRIP_payload_JSON_RAW = ProtoField.string("dvrip.data", "Raw JSON Message")
DVRIP_newline = ProtoField.uint16("dvrip.newline", "Newline", base.DEC_HEX)

-- DVRIP media signature field
DVRIP_signature = ProtoField.uint32("dvrip.signature", "Signature", base.HEX_DEC)

-- Stream type
DVRIP_stream_type = ProtoField.uint8("dvrip.stream_type", "Stream Type", base.HEX_DEC)

-- Framereate
DVRIP_framerate = ProtoField.uint8("dvrip._framerate", "Framerate", base.DEC_HEX)

-- DVRIP image dimensions - used both for I-Frames (FC) and snapshots (FE)
DVRIP_width = ProtoField.uint8("dvrip.width", "Width", base.DEC_HEX)
DVRIP_height = ProtoField.uint8("dvrip.height", "Height", base.DEC_HEX)

-- Start date of a stream
DVRIP_datetime = ProtoField.uint32("dvrip.datetime", "Datetime", base.DEC_HEX)

-- I-Frame (FC) fields
DVRIP_iframe_payload_size = ProtoField.uint32("dvrip.iframe_payload_size", "Payload size", base.DEC_HEX)
DVRIP_iframe_unknown = ProtoField.uint32("dvrip.iframe_unknown", "Unknown Field", base.DEC_HEX)

-- P-Frame (FD) fields
DVRIP_pframe_payload_length = ProtoField.uint32("dvrip.pframe_payload_length", "Payload Length", base.DEC_HEX)
DVRIP_pframe_unknown = ProtoField.uint32("dvrip.pframe_unknown", "Unknown Field", base.DEC_HEX)

-- A-Frame (Audio - FA) packet fields
DVRIP_sampling_rate = ProtoField.uint8("dvrip.sampling_rate", "Audio sampling rate", base.DEC_HEX)
DVRIP_audio_payload_length = ProtoField.uint16("dvrip.audio_payload_length", "Audio payload length", base.DEC_HEX)

-- Information Frame (F9) packet fields
DVRIP_unused_field = ProtoField.uint8("dvrip.unused_field", "Unused Field", base.DEC_HEX)
DVRIP_information_frame_payload_length = ProtoField.uint16("dvrip.information_frame_payload_length", "Payload Length", base.DEC_HEX)

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
	-- DVRIP I-Frame fields
	DVRIP_iframe_encoded_framerate,
	DVRIP_iframe_payload_size,
	DVRIP_iframe_unknown,
	-- DVRIP P-Frame fields
	DVRIP_pframe_payload_length,
	DVRIP_pframe_unknown,
	-- DVRIP A-Frame (audio) fields
	DVRIP_sampling_rate,
	DVRIP_audio_payload_length,
	-- DVRIP E-Frame (encoding) fields
	DVRIP_unused_field,
	DVRIP_information_frame_payload_length
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
	header:add_le(DVRIP_header_unknown, tvb(2, 2))
	header:add_le(DVRIP_session_id, tvb(4, 4))
	header:add_le(DVRIP_sequence_id, tvb(8, 4))
	header:add_le(DVRIP_unknown, tvb(12, 2))
	header:add_le(DVRIP_command_code, tvb(14, 2))
	header:add_le(DVRIP_payload_length, tvb(16, 4))

	if tvb:len() > HEADER_LEN then
		-- Length of payload
		local payload_length = tvb(16, 4):le_uint()
		-- Get JSON payload
		if tvb(HEADER_LEN, 1):uint() == 0x7b and tvb(14, 2):le_uint() ~= 0x0584 then -- 0x7b = {; 0x0584 = 1412
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
				local atree_header = atree:add(XM_proto, tvb(HEADER_LEN, 8), "Header")
				-- Audio frame payload reconstruction
				local aframe_length = tvb(HEADER_LEN + 6, 2):le_uint()
				-- Populate Audio Frame header fields
				atree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
				atree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
				atree_header:add_le(DVRIP_sampling_rate, tvb(HEADER_LEN + 5, 1))
				atree_header:add_le(DVRIP_audio_payload_length, tvb(HEADER_LEN + 6, 2))
				-- Audio Frame payload
				local audio_length = tvb(HEADER_LEN + 6, 2):le_uint()
				atree:add(XM_proto, tvb(HEADER_LEN + 8, audio_length), "Payload")
				-- Save reconstructed frame in /tmp directory
				local file_name = string.format("/tmp/%d_%d_%s", timestamp, pinfo.number, "A-Frame")
				local file = io.open(file_name, "wb")
				file:write(tvb:raw(HEADER_LEN, tvb:len() - HEADER_LEN))
				file:close()
			elseif signature == 0x000001fc then -- I-Frame
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
				itree_header:add_le(DVRIP_iframe_payload_size, tvb(HEADER_LEN + 12, 4))
				itree_header:add(DVRIP_iframe_unknown, tvb(HEADER_LEN + 16, 4))
				-- I-Frame payload
				itree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "I-Frame")
				-- Reconstruct I-Frame spanning multiple DVRIP/Sofia messages
				local iframe_payload = tvb(HEADER_LEN + 12, 4):le_uint() + 16
				if iframe_payload > payload_length then
					frame.key = "I-Frame"
					frame.bytes_needed = iframe_payload
					frame.bytes_collected = payload_length
					frame.payload:append(tvb(HEADER_LEN, payload_length):bytes())
					local packets_needed = frame.bytes_needed // payload_length + 1
					local sequence_id = tvb(8, 4):le_uint()
					frame.sequence_packet_first = sequence_id
					frame.sequence_packet_last = sequence_id + packets_needed
				else
					-- Save reconstructed frame in /tmp directory
					local file_name = string.format("/tmp/%d_%d_%s", timestamp, pinfo.number, "I-Frame")
					local file = io.open(file_name, "wb")
					file:write(frame.payload:raw())
					file:close()
				end
			elseif signature == 0x000001fd then -- P-Frame
				-- Add P-Frame to general tree
				local ptree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP P-Frame")
				local ptree_header = ptree:add(XM_proto, tvb(HEADER_LEN, 12), "P-Frame Header")
				-- P-Frame payload reconstruction
				local pframe_length = tvb(HEADER_LEN + 4, 2):le_uint()
				-- Populate P-Frame header fields
				ptree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
				ptree_header:add_le(DVRIP_pframe_payload_length, tvb(HEADER_LEN + 4, 4))
				ptree_header:add(DVRIP_pframe_unknown, tvb(HEADER_LEN + 8, 4))
				-- P-Frame payload
				ptree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "P-Frame")
				-- Reconstruct P-Frame spanning multiple DVRIP/Sofia messages
				local pframe_payload = tvb(HEADER_LEN + 4, 2):le_uint() + 8
				if pframe_payload > payload_length then
					frame.key = "P-Frame"
					frame.bytes_needed = pframe_payload
					frame.bytes_collected = payload_length
					frame.payload:append(tvb(HEADER_LEN, payload_length):bytes())
					local packets_needed = frame.bytes_needed // payload_length + 1
					local sequence_id = tvb(8, 4):le_uint()
					frame.sequence_packet_first = sequence_id
					frame.sequence_packet_last = sequence_id + packets_needed
				else
					-- Save reconstructed frame in /tmp directory
					local file_name = string.format("/tmp/%d_%d_%s", timestamp, pinfo.number, "P-Frame")
					local file = io.open(file_name, "wb")
					file:write(frame.payload:raw())
					file:close()
				end
			elseif signature == 0x000001f9 then -- Information Frame
				-- Add Information Frame to general tree
				local infotree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Information Frame")
				local infotree_header = infotree:add(XM_proto, tvb(HEADER_LEN, 8), "Header")
				-- Populate Information Frame header fields
				infotree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
				infotree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
				infotree_header:add_le(DVRIP_unused_field, tvb(HEADER_LEN + 5, 1))
				infotree_header:add_le(DVRIP_information_frame_payload_length, tvb(HEADER_LEN + 6, 2))
				-- Information frame payload
				local infoframe_payload_length = tvb(HEADER_LEN + 6, 2):le_uint()
				infotree:add(XM_proto, tvb(HEADER_LEN + 8, infoframe_payload_length), "Payload")
				-- Save reconstructed frame in /tmp directory
				local file_name = string.format("/tmp/%d_%d_%s", timestamp, pinfo.number, "Information-Frame")
				local file = io.open(file_name, "wb")
				file:write(tvb:raw(HEADER_LEN, tvb:len() - HEADER_LEN))
				file:close()
			elseif signature == 0xffd8ffe0 then -- JPEG file
				subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP JPEG Image")
				-- Save reconstructed image in /tmp directory
				local file_name = string.format("/tmp/%d_%d_%s", timestamp, pinfo.number, "JPEG-Image")
				local file = io.open(file_name, "wb")
				file:write(tvb:raw(HEADER_LEN, tvb:len() - HEADER_LEN))
				file:close()
			else
				if (frame.key == "I-Frame" or frame.key == "P-Frame") and pinfo.visited ~= true then
					frame.bytes_collected = frame.bytes_collected + payload_length
					frame.payload:append(tvb(HEADER_LEN, payload_length):bytes())
					if frame.bytes_collected == frame.bytes_needed then
						-- Save reconstructed frame in /tmp directory
						local file_name = string.format("/tmp/%d_%d_%s", timestamp, pinfo.number, frame.key)
						local file = io.open(file_name, "wb")
						file:write(frame.payload:raw())
						file:close()
						-- Reset variables in frame table
						frame.key = nil
						frame.bytes_needed = 0
						frame.bytes_collected = 0
						frame.sequence_packet_first = 0
						frame.sequence_packet_last  = 0
						frame.payload = ByteArray.new()
					end
				end
				local sequence_id_current = tvb(8, 4):le_uint()
				if sequence_id_current >= frame.sequence_packet_first and sequence_id_current <= frame.sequence_packet_last then
					subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), frame.key)
				else
					subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Media (Continuation)")
				end
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