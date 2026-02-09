#!/bin/sh

if [[ $# == 1 ]]; then # Accept only 1 argument
	if [[ ${1} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then # Match a valid IP address
		curl -s -X POST http://${1}:8899/onvif/device_service \
		-H "Content-Type: application/soap+xml" \
		-d '<?xml version="1.0" encoding="UTF-8"?>
		<s:Envelope xmlns:s="[http://www.w3.org/2003/05/soap-envelope](http://www.w3.org/2003/05/soap-envelope)">
		<s:Body>
		<GetDeviceInformation xmlns="[http://www.onvif.org/ver10/device/wsdl](http://www.onvif.org/ver10/device/wsdl)"/>
		</s:Body>
		</s:Envelope>' > device_information.xml

		xmllint --format device_information.xml > tmp

		mv tmp device_information.xml
	else
		printf "Invalid IP address\n"
	fi
else
	printf "Takes only 1 argument - IP address\n"
fi
