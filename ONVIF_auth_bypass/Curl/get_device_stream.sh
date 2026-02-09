#!/bin/sh

if [[ $# == 2 ]]; then # Accept only 2 arguments
	if [[ "${1}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then # Match a valid IP address
		curl -s -X POST http://${1}:8899/onvif/media_service \
		-H "Content-Type: application/soap+xml" \
		-d "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
		<s:Envelope xmlns:s=\"[http://www.w3.org/2003/05/soap-envelope](http://www.w3.org/2003/05/soap-envelope)\">
		<s:Body>
		<GetStreamUri xmlns=\"[http://www.onvif.org/ver10/media/wsdl](http://www.onvif.org/ver10/media/wsdl)\">
		<ProfileToken>${2}</ProfileToken>
		<StreamSetup>
		<Stream xmlns=\"[http://www.onvif.org/ver10/schema](http://www.onvif.org/ver10/schema)\">RTP-Unicast</Stream>
		<Transport xmlns=\"[http://www.onvif.org/ver10/schema](http://www.onvif.org/ver10/schema)\">
		<Protocol>RTSP</Protocol>
		</Transport>
		</StreamSetup>
		</GetStreamUri>
		</s:Body>
		</s:Envelope>" > device_stream.xml

		xmllint --format device_stream.xml > tmp

		if [[ "${2}" == "PROFILE_000" ]]; then
			mv tmp device_stream_main.xml && rm device_stream.xml
		elif [[ "${2}" == "PROFILE_001" ]]; then
			mv tmp device_stream_extra.xml && rm device_stream.xml
		else
			mv tmp device_stream.xml
		fi
	else
		printf "Invalid IP address\n"
	fi
else
	printf "Takes exactly 2 arguments - IP address and profile token\n"
fi
