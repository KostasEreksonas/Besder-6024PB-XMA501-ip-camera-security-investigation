# Prerequisite
For the final project of my Bachelor's studies I have chosen to investigate what security vulnerabilities and issues can be found within various IP camera models. And for this purpose I have bought ***Besder 6024PB-XMA501*** IP Camera from AliExpress. It has 5MP sensor is one of the cheaper ones you can find there and I thought to give it a try and bought it with hopes of finding some potentially _"interesting"_ stuff to put into my final project. My hopes were fulfilled and after the security investigation that I have done while writing my final project I decided to do a more troughout research and post it here.

# Analysis methodology
The whole security analysis of the IP camera was conducted within Arch Linux operating system on a laptop. Plan of analysis is as follows:
1. Factory reset of the camera.
2. Initial setup of the camera.
3. Technical information about analyzed camera discovery - open ports, OS version, etc.
4. Test camera control capabilities within a control panel in a web browser.
5. Test camera's communication with cloud services.
6. Check the security of transmited data.
7. Conclusion of test results.

# Factory reset
Tested Besder camera has a separate button installed which, when pressed, defaults settings of the camera.

# Initial Setup
	Inside the box that arrived there was the camera itself, a screw to fix a camera to a certain point and ***User Manual*** in english language. Within the user manual there were instructions how to set up the camera for the first time. Turns out, I needed to download ***ICSee*** app to my smartphone to do that.
	First time configuration requires the user to connect to a Wi-Fi network. One thing I have noticed already was that while I was typing the Wi-Fi password inside the app, the password was visible in ***plain text***. Although Wi-Fi credentials ***were not sent trough a Local Area Network (Double check on this one)***.
	By default the IP address of the camera in the Local Area Network is set dynamically, although it is possible to set a static IP address of `192.168.0.10`.

# Technical Information
## Open ports
### TCP scan
To discover open ports of the camera I have used `nmap` tool. The command to find TCP ports and determine their purpose was `nmap -v -sS -sV -sC -p- X.X.X.X`, where `X.X.X.X` is IP address of a camera. The scan was conducted with root privilleges. Meaning of flags is commented below:
```
-v		Verbosity. Gives more information about what the scan is doing.
-sS		Stealth scan. Fast, accurate and non-intrusive test of a selected target.
-sV		Version scan. Used to detect versions of services running on IP Camera.
-sC		Scripts scan. Uses a default set of `nmap` scripts.
-p-		Check all 65536 TCP ports if they are open.
```

Results of TCP scan with `nmap` are presented below:
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
5. Port `34567` is used for `dhanalakshmi` service. It is a data port which is used for transmitting and recieving data when the user connects to camera either from a computer or a smartphone. I will elaborate on this specific port a bit more in later sections.

### UDP scan
Next is UDP scan. For this scan I have used the same `nmap` tool with added `-sU` flag. Although this time I have set the program to scan only 1000 most popular ports as UDP scanning is a lot slower than TCP scan. The command used there was `nmap -v -sU -sV X.X.X.X`, where `X.X.X.X` is IP address of the camera. The scan was run with root privilleges. Results of the scan are presented below.
```
PORT     STATE         SERVICE      VERSION
3702/udp open|filtered ws-discovery
```
The scan found ***1*** open ***UDP*** port - `ws-discovery`, which stands for web service discovery. It is used for locating services on a LAN.

## OS Detection
Using `nmap` tool with `-O` flag I was able to determine the OS running on Besder IP Camera. The scan result is presented below.
```
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
```
As it can be seen from the result, Besder ip camera is regarded as a `general purpose` device and is running Linux OS with a likely version of `Linux 3.2 - 3.16`.

# Control Panel in a Web Browser
(Some text)

# Communication With Cloud Services
(Some text)

# Communication on a Local Area Network
(Some text)

# Firmware
(Some text)

# Reverse Engineering
(Some text)

# Passwords
(Some text)

# Conclusion
(Some text)
