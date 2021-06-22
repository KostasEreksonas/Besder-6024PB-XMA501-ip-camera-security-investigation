# Besder 6024PB-XMA501 IP camera security analysis

Table of Contents
=================
* [Besder 6024PB-XMA501 IP camera security analysis](#Besder-6024PB-XMA501-IP-camera-security-analysis)
* [Prerequisite](#Prerequisite)
* [Analysis methodology](#Analysis-methodology)
* [Factory reset](#Factory-reset)
* [Initial Setup](#Initial-Setup)
* [Technical Information](#Technical-Information)
	* [Open ports](#Open-ports)
	* [TCP port scan](#TCP-port-scan)
	* [UDP port scan](#UDP-port-scan)
	* [OS Detection](#OS-Detection)
* [Control Panel in a Web Browser](#Control-Panel-in-a-Web-Browser)
* [Network communication analysis](#Network-communication-analysis)
	* [Communication with a control panel in a web browser](#Communication-with-a-control-panel-in-a-web-browser)
* [Communication With Cloud Services](#Communication-With-Cloud-Services)
	* [Connecting from web interface](#Connecting-from-web-interface)
	* [Connecting to Besder camera from ICSee app on a smartphone](#Connecting-to-Besder-camera-from-ICSee-app-on-a-smartphone)
* [Data security](#Data-security)
* [Potential vulnerabilities](#Potential-vulnerabilities)
* [Camera firmware](#Camera-firmware)
* [Conclusion](#Conclusion)
* [Further work](#Further-work)

# Prerequisite
For the final project of my Bachelor's studies I have chosen to investigate what security vulnerabilities and issues can be found within various IP camera models. And for this purpose I have bought ***Besder 6024PB-XMA501*** IP Camera from AliExpress. It has 5MP sensor is one of the cheaper ones you can find there and I thought to give it a try and bought it with hopes of finding some potentially _"interesting"_ stuff to put into my final project. My hopes were fulfilled and after the security investigation that I have done while writing my final project I decided to do a more troughout research and post it here.

# Analysis methodology
The whole security analysis of the IP camera was conducted within Arch Linux operating system on an Acer laptop. Plan of analysis is as follows:
1. Factory reset of the camera.
2. Initial setup of the camera.
3. Technical information about analyzed camera discovery - open ports, OS version, etc.
4. Test camera control capabilities within a control panel in a web browser.
5. Test camera's communication with cloud services.
6. Check the security of transmited data.
7. Conclusion of analysis' results.

# Factory reset
Tested Besder camera has a separate button installed which, when pressed, defaults settings of the camera.

# Initial Setup
Inside the box that arrived there was the camera itself, a screw to fix a camera to a certain point and ***User Manual*** in english language. Within the user manual there were instructions how to set up the camera for the first time. Turns out, I needed to download ***ICSee*** app to my smartphone to do that. First time configuration requires the user to connect to a Wi-Fi network. By default the IP address of the camera in the Local Area Network is set dynamically, although it is possible to set a static IP address of `192.168.0.10`.

# Technical Information
In this section I am presenting results of gathering technical data and information about tested Besder IP camera.

## Open ports
In this subsection I am presenting found open ports of a tested Besder IP camera. During the analysis search for both ***TCP*** and ***UDP*** open ports was conducted.

### TCP port scan
To discover open ports of the camera I have used `nmap` tool. The command to find TCP ports and determine their purpose was `nmap -v -sS -sV -sC -p- X.X.X.X`, where `X.X.X.X` is IP address of a camera. The scan was conducted with root privilleges. Meaning of flags is commented below:

```
-v		Verbosity. Gives more information about what the scan is doing.
-sS		Stealth scan. Fast, accurate and non-intrusive test of a selected target.
-sV		Version scan. Used to detect versions of services running on IP Camera.
-sC		Scripts scan. Uses a default set of `nmap` scripts.
-p-		Check all 65535 TCP ports if they are open.
```

Results of TCP port scan with `nmap` are presented below:

```
PORT      STATE SERVICE       VERSION
80/tcp    open  http
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Content-type: text/html
|     Expires: 0
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <link rel="stylesheet" type="text/css" media="screen" href="m.css" />
|     <title>NETSurveillance WEB</title>
|     <!-- m.js -->
|     <script type="text/javascript" language="JavaScript">
|     bCrossBrow=false;
|     bnpCheck = false;
|     showemailflag=0;
|     ShowTipFlag=2;
|     //wzy 20190904
|     g_initWidth = document.documentElement.clientWidth;
|     SupportFind=false;
|     if(navigator.platform != "Win32")//
|     userAgent = navigator.userAgent,
|_    rMsie = /(msies|trident.
|_http-favicon: Unknown favicon MD5: EC9D1C872C50DD7DA7D826D9C85FC158
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: NETSurveillance WEB
554/tcp   open  rtsp          H264DVR rtspd 1.0
|_rtsp-methods: OPTIONS, DESCRIBE, SETUP, TEARDOWN, GET_PARAMETER, SET_PARAMETER, PLAY, PAUSE
8899/tcp  open  ospf-lite?
12901/tcp open  unknown
34567/tcp open  dhanalakshmi?
```

The scan found ***5*** open ***TCP*** ports in Besder 6024PB-XMA501 camera:
1. Port `80` is a HTTP port and is used for communicating with `NETSurveillance WEB` web interface, which is intended for managing the IP Camera from an internet browser.
2. Port `554` is a RTSP port with version `H264DVR rtspd 1.0` and could be used for retrieving the video stream from the camera with a specific URL which I have not figured out yet. Although I reckon login credentials would be neccesary there.
3. Port `8899` is detected as `ospf-lite` and as far as I could tell it could be used as an ONVIF-compliant port for.
4. Port `12901` was open during analysis, though `nmap` was not able to determine it's purpose.
5. Port `34567` is used for `dhanalakshmi` service. It is a data port which is used for transmitting and recieving data when the user connects to the camera either from a computer or a smartphone. I will elaborate on this specific port a bit more in later sections.

### UDP port scan
Next is open UDP port scan. For this scan I have used the same `nmap` tool with added `-sU` flag. Although this time I have set the program to scan only 1000 most popular ports as UDP scanning is a lot slower than TCP scan. The command used there was `nmap -v -sU -sV X.X.X.X`, where `X.X.X.X` is IP address of the camera. The scan was run with root privilleges. Results of the scan are presented below.

```
PORT     STATE         SERVICE      VERSION
3702/udp open|filtered ws-discovery
```

The scan found ***1*** open ***UDP*** port - `ws-discovery`, which stands for ***web service discovery***. It is used for locating services within the devices connected via Local Area Network.

## OS Detection
Using `nmap` tool with `-O` flag I was able to determine the Operating System and it's version running on the analyzed Besder IP Camera. The scan result is presented below.

```
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
```

As it can be seen from the result, Besder ip camera is regarded as a `general purpose` device and is running Linux OS with a likely version of `Linux 3.2 - 3.16`.

# Control Panel in a Web Browser
This is the time when some really interesting things start to show up. I have tried to access the control panel of the camera in `Mozilla Firefox` browser within my Arch Linux install... And I was greeted with this nice pop-up window saying that my browser is too new and that some features would not work properly. Also, there was a request that I should download Firefox version `51` from 2017.

![Pop-up saying that my browser is too new for rendering the control panel](/img/Browser_too_new.png)

Indeed, the webpage was not working as intented, displaying only a single line of text and a button to download `NewActive.exe` plugin. It does not look like a good idea to download any .exe files that a webpage, which requires an ancient version of web browser installed, asks me to download... Anyways, I have a `Windows 10` virtual machine installed within a `Virtualbox` environment, so I have switched to that for further testing of a web interface. Tried a few other of the most popular browsers - all gave the same pop-up asking to download old versions of those browsers. Turns out that the `NETSurveillance WEB`, used for controlling the camera, was only functional within the "good old" `Internet Explorer` browser with `ActiveX` plugin installed and activated. Neither of these I would want to constantly run on my main machine...

Anyway, I tried to log into the `NETSurveillance WEB` control panel. After pressing the login button it takes suspiciously long time to start any login activity. So I decided to inspect the webpage's code. And there I had found a `Javascript` login function which had a very _"interesting"_ feature - a 2 second timer, which activates ***after*** pressing the login button. To be honest, I am not sure about the purpose of this delay. One idea that I have is that it is used to make the device look slower than it actually is, especially in comparison to higher end models that the company is offering. But that is just speculation from my side.

# Network communication analysis
For analyzing network traffic associated with the camera I have carried out a `Man in the Middle` cyberattack using `Ettercap` tool and intercepted all the traffic between ip camera, smartphone, Windows 10 virtual computer within Virtualbox and the router. All devices were connected to the internet via ***Wi-Fi*** local area network. The scheme of devices used during analysis is shown below.

![Network analysis scheme](/img/Network_analysis_scheme.png)

## Communication with a control panel in a web browser
After logging in the `NETSurveillance WEB` control panel all the data between laptop and camera is sent through port `34567` and is obfuscated with what looks like a bunch of different length `MD5` hashes and separated by either `+` or `/` symbol. I have not found out yet what is the exact process of data obfuscation but I plan to do it later on.

# Communication With Cloud Services
As I have mentioned before, during the security analysis all network devices were connected to a Wireless Local Area Network. Still, I managed to capture a fair bit of communication with various servers providing cloud services.
Throughout the whole security testing that I have done, the camera sent a bunch of UDP datagrams to various IP addresses. Those datagrams contained camera's serial number. I was not able to determine their purpose.
For cloud services the camera uses ***XMEye Cloud***.
Firstly I have connected to the camera from web interface, then from smartphone.

## Connecting from web interface
Firstly the camera does a DNS resolution with an `Amazon AWS` server located in Germany, although the packages sent have data about some Chinese DNS servers with their IP addresses. I may assume that the DNS address is chosen based on camera's location. I might as well test it with a VPN someday.
After that camera sends a `HTTP POST` request to an `Amazon AWS` server with some data. Besides info about camera's geographical location and communication port, this request contains authentication code and serial number of the camera. Both of these are identical 16 charachter long hexadecimal strings. Thesecan be used for a variety of nefarious purposes.

***This and all of the following requests were formatted by me for better readability.***

```
POST / HTTP/1.1
Host: 3.126.12.232
Content-Length: 287

{
	"AgentProtocol" :
		{
			"Body" :
				{
					"Area" :
						"Europe:Lithuania:Default",
						"AuthCode" : "REDACTED",
						"DevicePort" : "34567",
						"RewriteOemID" : "General",
						"SerialNumber" : "REDACTED"
				},

			"Header" :
				{
					"CSeq" : "1",
					"MessageType" : "MSG_AGENT_REGISTER_REQ",
					"Version" : "1.0"
				}
		}
}

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 175

{
	"AgentProtocol" :
		{
			"Body" :
				{
					"KeepAliveIntervel":"120"
				},

			"Header":
				{
					"CSeq":"1",
					"ErrorNum":"200",
					"ErrorString":"Success Ok",
					"MessageType":"MSG_AGENT_REGISTER_RSP",
					"Version":"1.0"
				}
		}
}
```

Later camera sends this `HTTP POST` request to a `access-dss.secu100.net` server. It contains info about camera's geolocation, it's authentication code and serial number, among other things.

```
POST / HTTP/1.1
Host:access-dss.secu100.net
Connection: keep-alive
Content-Length:380

{
	"DssProtocol" :
		{
			"Body" :
				{
					"Area" :
						"Europe:Lithuania:Default",
						"AuthCode" : "REDACTED",
						"Enable" : "1",
						"LiveStatus" : [ "0", "0" ],
						"RewriteOemID" : "General",
						"SerialNumber" : "REDACTED",
						"StreamLevel" : "0_4:1_1_0",
						"StreamServerIPs" : [ "0.0.0.0", "0.0.0.0" ]
				},

			"Header" :
				{
					"CSeq" : "15",
					"MessageType" : "MSG_DEV_REGISTER_REQ",
					"Version" : "1.0"
				}
		}
}

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 173

{
	"DssProtocol":
		{
			"Body":
				{
					"KeepAliveIntervel":"120"
				},
			"Header":
				{
					"CSeq":"1.0",
					"ErrorNum":"200",
					"ErrorString":"Success Ok",
					"MessageType":"MSG_DEV_REGISTER_RSP",
					"Version":"1.0"
				}
		}
}
```

Later a `HTTP POST` request to `pub-cfg.secu100.net` was sent. It seems to be some kind of configuration server.

```
POST http://pub-cfg.secu100.net:8086/ HTTP/1.1
Accept: */*
Content-Length: 253
Content-Type: text/html
Host: pub-cfg.secu100.net:8086
User-Agent: XAPP

{
	"CfgProtocol":	{
		"Header":	{
			"Version":	"1.0",
			"CSeq":	"1",
			"MessageType":	"MSG_XM_DNS_MULTIQUERY_REQ"
		},
		"Body":	{
			"DomainName":	"pub-dss-hls.secu100.net",
			"Deviceinfo":	[{
					"SerialNumber":	"REDACTED"
				}]
		}
	}
}

HTTP/1.1 200 OK
Server: openresty/1.17.8.2
Date: Fri, 23 Apr 2021 12:29:03 GMT
Content-Type: text/html
Connection: keep-alive
content-length: 214

{
	"CfgProtocol":
		{
			"Body":
				[{
					"ServerIP":"18.194.150.179",
					"SerialNumber":"REDACTED"
				}],

			"Header":
				{
					"ErrorNum":"200",
					"Version":"1.0",
					"CSeq":"1",
					"MessageType":"MSG_XM_DNS_MULTIQUERY_RSP",
					"ErrorString":"Success OK"
				}
		}
}
```

Later the camera sends HTTP POST request to `logsvr.xmcsrv.net` and reports it's capabilities to the server for whatever reason:

```
POST /getcfg HTTP/1.1
Host: logsvr.xmcsrv.net
Content-Length: 30

{ "sn" : "REDACTED" }
HTTP/1.1 200 OK
Server: nginx/1.16.1
Date: Mon, 12 Apr 2021 10:39:31 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 353
Connection: keep-alive

{
	"ret":200,
	"msg":"Success",
	"methods":
		[
			{
				"protocol":"HTTP",
				"params":
					{
						"url":"http://logsvr.xmcsrv.net/upload"
					}
			}
		],
	"modules":
		[
			{
				"module":"runtime",
				"interval":1800,
				"want":["cpu","mem","bat","reboot","wakeup"]
			},
			{
				"module":"xmcloud",
				"interval":3600,
				"want":["pms","rps","wps","css","dss","ip"]
			},
			{
				"module":"config",
				"interval":3600,
				"want":["mcu","pir","timezone"]
			}
		]
}
```

Last thing that I have captured is camera's communication with an update server:

```
/list HTTP/1.1
Connection: Keep-Alive
Host: 120.92.92.241
Content-Length: 159

{
	"UUID":"REDACTED",
	"DevID":"REDACTED",
	"DevType":"IPC",
	"CurVersion":"2020-11-24",
	"Expect":"Latest",
	"Language":"English",
	"Manual":"True"
}

/list HTTP/1.1
Connection: Keep-Alive
Host: 120.92.92.241
Content-Length: 159

{
	"UUID":"REDACTED",
	"DevID":"REDACTED",
	"DevType":"IPC",
	"CurVersion":"2020-11-24",
	"Expect":"Latest",
	"Language":"English",
	"Manual":"True"
}

HTTP/1.1 204
Server: nginx/1.12.2
Date: Mon, 19 Apr 2021 10:28:25 GMT
Content-Type: text/html;charset=utf-8
Connection: keep-alive
X-Application-Context: application:production
```

Since there is no authentication required for sending the request to the update server checking for new firmware versions and downloading them, it makes me wonder if I could impersonate the ip camera and download the firmware from there...

## Connecting to Besder camera from ICSee app on a smartphone

Firstly, `HTTP POST` request is sent from a smartphone to an `Amazon AWS` server. It contains serial number of the camera I wanted to connect to, among other things. Request's purpose is to ask for a new connection with `MSG_CLI_NEED_CON_REQ` query. The AWS server sends `HTTP OK` response to the smartphone. It contains IP address of a ***second*** Amazon AWS server and it's port that is used for communicating.

```
POST / HTTP/1.1
Host: 18.194.150.179
Content-Length: 328

{
	"AgentProtocol" :
		{
			"Body" :
				{
					"Authcode" : "REDACTED",
					"ClientToken" : "REDACTED",
					"DestPort" : "34567",
					"SerialNumber" : "REDACTED",
					"ServiceType" : "RpsCmd",
					"SessionId" : "MD5_HASH"
				},

			"Header" :
				{
					"MessageType" : "MSG_CLI_NEED_CON_REQ",
					"Version" : "1.0"
				}
		}
}

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 203

{
	"AgentProtocol":
		{
			"Body":
				{
					"AgentServerIp":"18.193.69.65",
					"AgentServerPort":"6611"
				},

			"Header":
				{
					"CSeq":"3",
					"ErrorNum":"200",
					"ErrorString":"Success OK",
					"MessageType":"MSG_CLI_NEED_CON_RSP",
					"Version":"1.0"
				}
		}
}
```

The `HTTP POST` request containing IP address and communication port of ***second*** AWS server is sent to the IP camera.

```
POST / HTTP/1.1
Content-Length: 265

{
	"AgentProtocol":
		{
			"Body":
				{
					"AgentServerIp":"18.193.69.65",
					"AgentServerPort":"6611",
					"ClientToken":"SAME_CLIENT_TOKEN",
					"DestPort":"34567",
					"SessionId":"SAME_MD5_HASH"
				},

			"Header":
				{
					"CSeq":"3",
					"MessageType":"MSG_DEV_START_CON",
					"Version":"1.0"
				}
		}
}
```

All further communication is sent through the second AWS server and is encrypted/obfuscated. The communication between smartphone and the second AWS serveris encrypted using `TLS` protocol and communication between the server and camera is obfuscated using MD5 algorithm.

# Data security
As I have mentioned before, all of the data was sent via port `34567` and the data is obfuscated with what looks like a bunch of different length MD5 hashes, separated by `+` or `/` symbol. It might be possible to reverse engineer the function used for data obfuscation, although for that I would need to retrieve the firmware of the camera. I will elaborate on this more in the next section.

# Potential vulnerabilities
In this section I will present potential vulnerabilities within the tested Besder camera. The exploits and their descriptions were taken from [cve.mitre.org](https://cve.mitre.org/) website and the found vulnerabilities were associated with ***Xongmai XMeye P2P*** cloud services.

1. ***CVE-2017-16725*** - A Stack-based Buffer Overflow issue was discovered in Xiongmai Technology IP Cameras and DVRs using the NetSurveillance Web interface. The stack-based buffer overflow vulnerability has been identified, which may allow an attacker to execute code remotely or crash the device. After rebooting, the device restores itself to a more vulnerable state in which Telnet is accessible.
2. ***CVE-2017-7577*** -	XiongMai uc-httpd has directory traversal allowing the reading of arbitrary files via a "GET ../" HTTP request.
3. ***CVE-2018-10088*** - Buffer overflow in XiongMai uc-httpd 1.0.0 has unspecified impact and attack vectors, a different vulnerability than CVE-2017-16725.
4. ***CVE-2018-17915*** - All versions of Hangzhou Xiongmai Technology Co., Ltd XMeye P2P Cloud Server do not encrypt all device communication. This includes the XMeye service and firmware update communication. This could allow an attacker to eavesdrop on video feeds, steal XMeye login credentials, or impersonate the update server with malicious update code.
5. ***CVE-2018-17917*** - All versions of Hangzhou Xiongmai Technology Co., Ltd XMeye P2P Cloud Server may allow an attacker to use MAC addresses to enumerate potential Cloud IDs. Using this ID, the attacker can discover and connect to valid devices using one of the supported apps.
6. ***CVE-2018-17919*** - All versions of Hangzhou Xiongmai Technology Co., Ltd XMeye P2P Cloud Server may allow an attacker to use an undocumented user account "default" with its default password to login to XMeye and access/view video streams.
7. ***CVE-2019-11878*** - An issue was discovered on XiongMai Besder IP20H1 V4.02.R12.00035520.12012.047500.00200 cameras. An attacker on the same local network as the camera can craft a message with a size field larger than 0x80000000 and send it to the camera, related to an integer overflow or use of a negative number. This then crashes the camera for about 120 seconds.

# Camera firmware
As I have mentioned before, in this section I will elaborate on the topic of firmware of Besder camera. There are multiple ways to retrieve the firmware of a IP camera:
1. Download it from the official website of the camera's manufacturer, if the firmware is available there;
2. Retrieve the firmware from the device by some sort of a ***soft*** method, for example:
	* locate the firmware within the camera's control interface - separate program or a web interface, like a `NetSurveillance WEB` used in tested Besder camera;
	* find the firmware by gaining access to the camera's shell by connecting to one of the open ports that have a terminal service running on top of them, if there are any (like `telnet` or a ***telnet-like*** service running on a port `9527` found in some older (mostly those released before [Mirai malware](https://en.wikipedia.org/wiki/Mirai_(malware))) surveillance devices and also giving shell access to a device);
	* find the firmware by exploiting some known vulnerabilities within the device.
3. Retrieve the firmware from the device by some sort of a ***hard*** method, for example:
	* ***JTAG***;
	* ***Serial console***.

Now I will go through the listed possibilities and try to determine what things I could do further to retrieve the firmware of the device:
1. As far as I have checked, there is no posibility to download the firmware for `Besder 6024PB-XMA501` IP camera over the internet. One interesting thing that I have noticed was that I could not find the exact model of my camera. There are some other `Besder 6024PB` cameras, but none ending with `XMA501`.
2. The `NETSurveillance WEB` interface for controlling the camera has option to update the camera's firmware, which downloads the update, if it is available, and then automatically applies it. Also it is possible to apply the update manually with a file from a local drive, although I was not able to find an option to save the firmware file to my local drive, so there's that.
3. Talking about hard _"hacking"_ methods, I do not have the tools for that at the moment, so it is not a possibility as of now.
4. As mentioned in previous section, I was able to find some vulnerabilities that _might_ affect this Besder camera, although I would need to test them against the device to prove if those vulnerabilities could be used for obtaining the firmware.
5. Last part is the part that includes open ports. There are ***no*** open ports that could be used for gaining shell access, namely ports `23`, `9527` and, by some reports that I have found, `9530`. So, no luck there.

Although it might also be possible to retrieve the firmware from the ***update server*** that the camera is communicating with as the `JSON` formatted update request is sent in plain text. For that I will set up a ***VPN*** and come back for further testing.

# Conclusion
During this analysis I have found open ports, running services, OS version and other technical information about the camera. After that I tested camera control capabilities within a control panel in a web browser. Later communication with cloud servers and services was analyzed. Lastly, the security and encryption/obfuscation of sent data was checked.

# Further work
Below I will list the things that I plan to try to further accomplish with the security testing of this camera:
1. Impersonate the IP camera and download the camera's firmware from cloud service.
2. Use special tools to analyze the downloaded firmware and reverse engineer the code.
3. Most importantly - find the function that is used for obfuscating the sent data and reverse engineer the algorithm used for this function.
