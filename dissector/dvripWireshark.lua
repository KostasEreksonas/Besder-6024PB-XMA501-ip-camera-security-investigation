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
local SIG_IMAGE		= 0xffd8ffe0
local SIG_AUDIO		= 0x000001fa
local SIG_IFRAME	= 0x000001fc
local SIG_PFRAME	= 0x000001fd
local SIG_INFOFRAME	= 0x000001f9

-- Media frame header length
local IFRAME_HEADER_LEN = 16
local PFRAME_HEADER_LEN = 8
local AFRAME_HEADER_LEN = 8
local INFOFRAME_HEADER_LEN = 8

-- Signatures used to match JSON payload
local JSON_OPEN_BRACE  = 0x7b
local CMD_MEDIA_STREAM = 0x0584  -- Command code 1412: media stream, not JSON

-- Collect video stream
local video_streams = {}

-- Collect audio stream
local audio_streams = {}

-- Table to collect media frame data from multiple DVRIP/Sofia packets
local frames = {}

-- Load JSON dissector
local json = Dissector.get("json")

-- Definition of the overall protocol name
local XM_proto = Proto("dvrip", "Xiongmai DVRIP Protocol")

-- DVRIP/Sofia packet header fields
local DVRIP_header = ProtoField.bytes("dvrip.header", "DVRIP Header")
local DVRIP_header_id = ProtoField.uint8("dvrip.header_id", "Header", base.DEC_HEX)
local DVRIP_req_resp = ProtoField.uint8("dvrip.req_resp", "Request/Response", base.DEC_HEX)
local DVRIP_reserved_1 = ProtoField.uint8("dvrip.reserved_1", "Reserved 1", base.DEC_HEX)
local DVRIP_reserved_2 = ProtoField.uint8("dvrip.reserved_2", "Reserved 2", base.DEC_HEX)
local DVRIP_session_id = ProtoField.uint32("dvrip.session_id", "Session ID", base.DEC_HEX)
local DVRIP_sequence_id = ProtoField.uint32("dvrip.sequence_id", "Sequence ID", base.DEC_HEX)
local DVRIP_total_packets = ProtoField.uint8("dvrip.total_packets", "Total Packets", base.DEC_HEX)
local DVRIP_current_packet = ProtoField.uint8("dvrip.current_packet", "Current Packet", base.DEC_HEX)
local DVRIP_command_code = ProtoField.uint16("dvrip.command_code", "Command Code", base.DEC_HEX)
local DVRIP_payload_size = ProtoField.uint32("dvrip.payload_size", "Payload Size", base.DEC_HEX)

-- DVRIP/Sofia JSON payload fields
local DVRIP_payload_JSON_RAW = ProtoField.string("dvrip.data", "Raw JSON Message")
local DVRIP_newline = ProtoField.uint16("dvrip.newline", "Newline", base.DEC_HEX)

-- DVRIP/Sofia encrypted payload field
local DVRIP_encrypted = ProtoField.string("dvrip.encrypted", "Encrypted Message")

-- DVRIP/Sofia media signature field
local DVRIP_signature = ProtoField.uint32("dvrip.signature", "Signature", base.HEX_DEC)

-- Stream type
local DVRIP_stream_type = ProtoField.uint8("dvrip.stream_type", "Stream Type", base.HEX_DEC)

-- Framerate
local DVRIP_framerate = ProtoField.uint8("dvrip.framerate", "Framerate", base.DEC_HEX)

-- DVRIP image dimensions - used both for I-Frames (FC) and snapshots (FE)
local DVRIP_width = ProtoField.uint8("dvrip.width", "Width", base.DEC_HEX)
local DVRIP_height = ProtoField.uint8("dvrip.height", "Height", base.DEC_HEX)

-- Start date of a stream
local DVRIP_datetime = ProtoField.uint32("dvrip.datetime", "Datetime", base.DEC_HEX)

-- I-Frame (FC) fields
local DVRIP_media_payload_size = ProtoField.uint32("dvrip.media_payload_size", "Payload Size", base.DEC_HEX)

-- Audio sampling rate
local DVRIP_sampling_rate = ProtoField.uint8("dvrip.sampling_rate", "Audio Sampling Rate", base.DEC_HEX)

-- Unused field in information frame (F9)
local DVRIP_unused_field = ProtoField.uint8("dvrip.unused_field", "Unused Field", base.DEC_HEX)

-- List of DVRIP/Sofia protocol fields
XM_proto.fields = {
	-- DVRIP header fields
	DVRIP_header,
	DVRIP_header_id,
	DVRIP_req_resp,
	DVRIP_reserved_1,
	DVRIP_reserved_2,
	DVRIP_session_id,
	DVRIP_sequence_id,
	DVRIP_total_packets,
	DVRIP_current_packet,
	DVRIP_command_code,
	DVRIP_payload_size,
	-- DVRIP/Sofia JSON payload fields
	DVRIP_payload_JSON_RAW,
	DVRIP_newline,
	-- Encrypted data
	DVRIP_encrypted,
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

local function udp_get_len(tvb)
	return tvb(4, 2):uint()
end

local function udp_dissect_one_pdu(tvb, pinfo, tree)
	local json_tvb
	local subtree = tree:add(XM_proto, tvb(), "DVRIP Configuration Message")

	subtree:add(DVRIP_payload_JSON_RAW, tvb(0, tvb:len()))

	-- Decode JSON object using built-in dissector
	json:call(tvb, pinfo, subtree)
	
	pinfo.cols.protocol = "DVRIP/JSON"
    pinfo.cols.info = "DVRIP Configuration Message"
    
	return tvb:len()
end

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

local function build_message_header(tvb, header)
	-- Build DVRIP message header into the protocol tree
	header:add_le(DVRIP_header_id, tvb(0, 1))
	header:add_le(DVRIP_req_resp, tvb(1, 1))
	header:add_le(DVRIP_reserved_1, tvb(2, 1))
	header:add_le(DVRIP_reserved_2, tvb(3, 1))
	header:add_le(DVRIP_session_id, tvb(4, 4))
	header:add_le(DVRIP_sequence_id, tvb(8, 4))
	header:add_le(DVRIP_total_packets, tvb(12, 1))
	header:add_le(DVRIP_current_packet, tvb(13, 1))
	header:add_le(DVRIP_command_code, tvb(14, 2))
	header:add_le(DVRIP_payload_size, tvb(16, 4))
end

local function build_protocol_tree(tvb, pinfo, subtree, payload_length)
	-- Handle trailing newline (last 1 or 2 bytes of a payload)
	local json_tvb
	if tvb:len() < payload_length then
		json_tvb = tvb(HEADER_LEN, tvb:len() - HEADER_LEN)
		subtree:add(DVRIP_payload_JSON_RAW, json_tvb, "Incomplete JSON Payload")
	else
		if tvb(HEADER_LEN + payload_length - 2, 1):uint() == 0x7d then
			json_tvb = tvb(HEADER_LEN, payload_length - 1) -- last byte is newline
		elseif tvb(HEADER_LEN + payload_length - 1, 1):uint() ~= 0x0a then
			json_tvb = tvb(HEADER_LEN, payload_length - 2) -- last 2 bytes are newline
		else
			json_tvb = tvb(HEADER_LEN, payload_length)
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
end

local function populate_audio_tree(tvb, subtree)
	local atree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Audio")
	local atree_header = atree:add(XM_proto, tvb(HEADER_LEN, AFRAME_HEADER_LEN), "Header")

	-- Populate Audio Frame header fields
	atree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	atree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
	atree_header:add_le(DVRIP_sampling_rate, tvb(HEADER_LEN + 5, 1))
	atree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 6, 2))

	-- Audio Frame payload
	atree:add(XM_proto, tvb(HEADER_LEN + AFRAME_HEADER_LEN, tvb:len() - HEADER_LEN - AFRAME_HEADER_LEN), "Payload")
end

local function populate_iframe_tree(tvb, subtree)
	-- Add I-Frame to general tree
	local itree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP I-Frame")
	local itree_header = itree:add(XM_proto, tvb(HEADER_LEN, IFRAME_HEADER_LEN), "I-Frame Header")

	-- Populate I-Frame header fields
	itree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	itree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
	itree_header:add_le(DVRIP_framerate, tvb(HEADER_LEN + 5, 1))
	itree_header:add_le(DVRIP_width, tvb(HEADER_LEN + 6, 1))
	itree_header:add_le(DVRIP_height, tvb(HEADER_LEN + 7, 1))
	itree_header:add_le(DVRIP_datetime, tvb(HEADER_LEN + 8, 4))
	itree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 12, 4))

	-- I-Frame payload
	itree:add(XM_proto, tvb(HEADER_LEN + IFRAME_HEADER_LEN, tvb:len() - HEADER_LEN - IFRAME_HEADER_LEN), "I-Frame")
end

local function populate_pframe_tree(tvb, subtree)
	-- Add P-Frame to general tree
	local ptree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP P-Frame")
	local ptree_header = ptree:add(XM_proto, tvb(HEADER_LEN, PFRAME_HEADER_LEN), "P-Frame Header")

	-- Populate P-Frame header fields
	ptree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	ptree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 4, 4))

	-- P-Frame payload
	ptree:add(XM_proto, tvb(HEADER_LEN + PFRAME_HEADER_LEN, tvb:len() - HEADER_LEN - PFRAME_HEADER_LEN), "P-Frame")
end

local function populate_infoframe_tree(tvb, subtree)
	-- Add Information Frame to general tree
	local infotree = subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Information Frame")
	local infotree_header = infotree:add(XM_proto, tvb(HEADER_LEN, INFOFRAME_HEADER_LEN), "Header")

	-- Populate Information Frame header fields
	infotree_header:add(DVRIP_signature, tvb(HEADER_LEN, 4))
	infotree_header:add_le(DVRIP_stream_type, tvb(HEADER_LEN + 4, 1))
	infotree_header:add_le(DVRIP_unused_field, tvb(HEADER_LEN + 5, 1))
	infotree_header:add_le(DVRIP_media_payload_size, tvb(HEADER_LEN + 6, 2))

	-- Add information frame payload to the general tree
	infotree:add(XM_proto, tvb(HEADER_LEN + INFOFRAME_HEADER_LEN, tvb:len() - HEADER_LEN - INFOFRAME_HEADER_LEN), "Payload")
end

local function get_frame_context(stream_key)
    if frames[stream_key] == nil then
        frames[stream_key] = {
            key = stream_key,
            bytes_needed = 0,
            bytes_collected = 0,
            payload = ByteArray.new()
        }
    end
    return frames[stream_key]
end

local function check_encryption(stream_key, message_length, subtree, tvb, pinfo)
	-- Check if DVRIP/Sofia control message is encrypted
	if (tvb(14, 2):le_uint() ~= 1412) then
		subtree:add(XM_proto, tvb(HEADER_LEN, message_length), "Encrypted Payload")
		subtree:add(DVRIP_encrypted, tvb(HEADER_LEN, message_length))
		pinfo.cols.info = "Encrypted message "
	else
		subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "DVRIP Media (Continuation)")
		pinfo.cols.info = "DVRIP media continuation message "
	end
end

local function build_protocol_media_tree(tvb, pinfo, subtree, stream_key, message_length)
	-- Check whether enough bytes are present to form a media signature
	if tvb:len() >= 24 then
		-- Signature of media payload
		local signature = tvb(HEADER_LEN, 4):uint()
		-- Update pinfo description
		pinfo.cols.info = "DVRIP media signature = " .. string.format("%08x", signature) .. " "
		-- If no signature matches, treat it as media continuation packet in a protocol tree
		-- If signature matches, build a protocol tree for the media frame and save payload to a byte buffer
		if signature == SIG_IMAGE then -- JPEG image
			subtree:add(XM_proto, tvb(HEADER_LEN, tvb:len() - HEADER_LEN), "JPEG Image")
		elseif signature == SIG_AUDIO then -- Audio
			populate_audio_tree(tvb, subtree)
		elseif signature == SIG_IFRAME then -- I-Frame
			populate_iframe_tree(tvb, subtree)
		elseif signature == SIG_PFRAME then -- P-Frame
			populate_pframe_tree(tvb, subtree)
		elseif signature == SIG_INFOFRAME then -- Information Frame
			populate_infoframe_tree(tvb, subtree)
		else
			-- Distinguish between encrypted DVRIP/Sofia message and media continuation packet
			check_encryption(stream_key, message_length, subtree, tvb, pinfo)
		end
	else
		-- Distinguish between encrypted DVRIP/Sofia message and media continuation packet
		check_encryption(stream_key, message_length, subtree, tvb, pinfo)
	end
end

local function get_video_stream(stream_key)
	if video_streams[stream_key] == nil then
		video_streams[stream_key] = {
			payload = ByteArray.new()
		}
	end

	return video_streams[stream_key]
end

local function get_audio_stream(stream_key)
	if audio_streams[stream_key] == nil then
		audio_streams[stream_key] = {
			payload = ByteArray.new()
		}
	end

	return audio_streams[stream_key]
end

local function reset_frame_context(stream_key)
    frames[stream_key] = {
        key = stream_key,
        bytes_needed = 0,
        bytes_collected = 0,
        payload = ByteArray.new(),
    }
end

local function collect_frame(stream_key, payload)
	local video_stream = get_video_stream(stream_key)
	video_stream.payload:append(payload)
end

local function initialize_frame(frame, frame_length, message_length, initial_payload)
	frame.bytes_needed = frame_length -- Length of a full media frame
	frame.bytes_collected = message_length -- Length of current DVRIP/Sofia message
	frame.payload:append(initial_payload)
end

local function check_frame_length(frame_length, message_length, stream_key, payload, frame)
	if frame_length <= message_length then
		collect_frame(stream_key, payload)
	else
		initialize_frame(frame, frame_length, message_length, payload)
	end
end

local function reconstruct_long_media_frames(message_length, tvb, stream_key, frame, pinfo)
	frame.bytes_collected = frame.bytes_collected + message_length
	frame.payload:append(tvb(HEADER_LEN, message_length):bytes())
	if frame.bytes_collected >= frame.bytes_needed then
		-- When a large frame is fully collected, add it to the video stream that is being reconstructed
		local video_stream = get_video_stream(stream_key)
		video_stream.payload:append(frame.payload)
		-- Reset variables in frame table
		reset_frame_context(stream_key)
	end
end

local function save_image(sequence_id, image_buffer)
	local file_name = string.format("/tmp/%d.jpeg", sequence_id)
	local file, err = io.open(file_name, "wb")
	if not file then
  		-- log the error or silently skip
  		print(err)
		return
	end
	file:write(image_buffer:raw())
	file:close()
end

local function reconstruct_streams(tvb, stream_key, pinfo, subtree, message_length)
	local frame = get_frame_context(stream_key)
	if tvb:len() >= 24 then
		local signature = tvb(HEADER_LEN, 4):uint()
		local sequence_id = tvb(8, 4):le_uint()
		if signature == SIG_IMAGE then
			save_image(sequence_id, tvb(HEADER_LEN, message_length):bytes())
		elseif signature == SIG_AUDIO then
			-- Append audio payload to audio stream
			local audio_stream = get_audio_stream(stream_key)
			audio_stream.payload:append(tvb(HEADER_LEN + AFRAME_HEADER_LEN, message_length - AFRAME_HEADER_LEN):bytes())
		elseif signature == SIG_IFRAME then
			local iframe_length = tvb(HEADER_LEN + 12, 4):le_uint() + IFRAME_HEADER_LEN
			local payload = tvb(HEADER_LEN + IFRAME_HEADER_LEN, message_length - IFRAME_HEADER_LEN):bytes()
			-- If frame_length < DVRIP message_length, append frame to video stream
			-- Otherwise, initialize frames table to collect full media frame before appending to video stream
			check_frame_length(iframe_length, message_length, stream_key, payload, frame)
		elseif signature == SIG_PFRAME then
			local pframe_length = tvb(HEADER_LEN + 4, 4):le_uint() + PFRAME_HEADER_LEN
			local payload = tvb(HEADER_LEN + PFRAME_HEADER_LEN, message_length - PFRAME_HEADER_LEN):bytes()
			-- If frame_length < DVRIP message_length, append frame to video stream
			-- Otherwise, initialize frames table to collect full media frame before appending to video stream
			check_frame_length(pframe_length, message_length, stream_key, payload, frame)
		else
			if frame.payload:len() ~= 0 and signature ~= SIG_INFOFRAME then
				reconstruct_long_media_frames(message_length, tvb, stream_key, frame, pinfo)
			end
		end
	else
		if frame.payload:len() ~= 0 then
			reconstruct_long_media_frames(message_length, tvb, stream_key, frame, pinfo)
		end
	end
end

local function save_streams(save_dir)
	-- Save video
	for stream_key, value in pairs(video_streams) do
		local file_name = string.format("/%s/%s_video.h265", save_dir, stream_key)
		print(file_name)
		local f_video, f_video_err = io.open(file_name, "wb")
		if not f_video then
  			-- log the error or silently skip
  			print(f_video_err)
			return
		end
		f_video:write(value.payload:raw())
		f_video:close()
	end
	-- Save audio
	for stream_key, value in pairs(audio_streams) do
		local file_name = string.format("/%s/%s_audio.g711", save_dir, stream_key)
		local f_audio, f_audio_err = io.open(file_name, "wb")
		if not f_audio then
  			-- log the error or silently skip
  			print(f_audio_err)
			return
		end
		f_audio:write(value.payload:raw())
		f_audio:close()
	end
end

-- Define menu entry to save DVRIP/Sofia streams to a file
local function dialog_stream_save()
	local function dialog_window(save_dir)
		-- Remove leading forward slash (/) from the provided save directory
		if save_dir:sub(0, 1) == "/" then
			save_dir = save_dir:sub(2)
		end

		-- Create new dialog on success
		local window = TextWindow.new("DVRIP Save Streams");
		local message = string.format("DVRIP streams saved at /%s.", save_dir);
        window:set(message);
		save_streams(save_dir)
	end
	new_dialog("DVRIP Save Streams", dialog_window, "Save Directory:")
end

local function dvrip_dissect_one_pdu(tvb, pinfo, tree)
	pinfo.cols.protocol = XM_proto.name
	pinfo.cols.info = "Command code = " .. string.format("%04d", tvb(14,2):le_uint()) .. " "

	local subtree = tree:add(XM_proto, tvb(), "Xiongmai DVRIP Protocol")

	subtree:add(DVRIP_header, tvb(0, 20))

	local header = subtree:add(XM_proto, tvb(0, 20), "DVRIP Header")
	build_message_header(tvb, header)

	if tvb:len() > HEADER_LEN then
		-- Length of a DVRIP/Sofia message (without 20-bit header)
		local payload_length = tvb(16, 4):le_uint()

		-- Build protocol tree with control flow messages (JSON-based) and media payloads
		if tvb(HEADER_LEN, 1):uint() == JSON_OPEN_BRACE and tvb(14, 2):le_uint() ~= CMD_MEDIA_STREAM then
			build_protocol_tree(tvb, pinfo, subtree, payload_length)
		else
			local stream_key = tostring(pinfo.src) .. "_" .. tvb(2, 1):le_uint().. "_" .. tvb(3, 1):le_uint()
			
			-- Reconstruct DVRIP/Sofia media frames into byte buffers ready for export
			if not pinfo.visited and tvb(14,2):le_uint() == 1412 then
				reconstruct_streams(tvb, stream_key, pinfo, subtree, payload_length)
			end

			build_protocol_media_tree(tvb, pinfo, subtree, stream_key, payload_length)
		end
	end

	return tvb:len() -- amount of bytes consumed
end

function XM_proto.dissector(tvb, pinfo, tree)
	if tvb:len() == 0 then
		return
	end

	if tvb(0, 1):uint() == JSON_OPEN_BRACE then
		dissect_tcp_pdus(tvb, tree, 0, udp_get_len, udp_dissect_one_pdu, true)
	else
		dissect_tcp_pdus(tvb, tree, HEADER_LEN, dvrip_get_len, dvrip_dissect_one_pdu, true)
	end
end

-- assigning protocol to port
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(34567, XM_proto)
local udp_table = DissectorTable.get("udp.port")
udp_table:add(34569, XM_proto)
udp_table:add(34571, XM_proto)

-- Create the menu entry for saving DVRIP/Sofia media streams
register_menu("DVRIP Save Streams", dialog_stream_save, MENU_TOOLS_UNSORTED)