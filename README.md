# Besder 6024PB-XMA501 IP camera security analysis

A cybersecurity analysis of a Besder 6024PB-XMA501 IP camera that started as a project for the final project of Bachelor's studies.

Table of Contents
=================
* [Besder 6024PB-XMA501 IP camera security analysis](#Besder-6024PB-XMA501-IP-camera-security-analysis)
* [Prerequisite](#Prerequisite)
* [Analysis methodology](#Analysis-methodology)
* [Factory reset](#Factory-reset)
* [Initial Setup](#Initial-Setup)
* [Technical Information](#Technical-Information)
	* [Open ports](#Open-ports)
		+ [TCP port scan](#TCP-port-scan)
		+ [UDP port scan](#UDP-port-scan)
		+ [OS Detection](#OS-Detection)
* [Control Panel in a Web Browser](#Control-Panel-in-a-Web-Browser)
* [A further investigation of a control panel of an IP camera](#A-further-investigation-of-a-control-panel-of-an-IP-camera)
* [Network communication analysis](#Network-communication-analysis)
	* [Communication with a control panel in a web browser](#Communication-with-a-control-panel-in-a-web-browser)
* [Communication With Cloud Services](#Communication-With-Cloud-Services)
	* [Connecting from web interface](#Connecting-from-web-interface)
		+ [Connection scheme between virtual machine and IP Camera](#Connection-scheme-between-virtual-machine-and-IP-Camera)
		+ [Exchanged queries between virtual machine and IP Camera](#Exchanged-queries-between-virtual-machine-and-IP-Camera)
	* [Connecting to Besder camera from ICSee app on a smartphone](#Connecting-to-Besder-camera-from-ICSee-app-on-a-smartphone)
		+ [Connection scheme between smartphone and AWS cloud server and IP Camera](#Connection-scheme-between-smartphone-and-AWS-cloud-server-and-IP-Camera)
		+ [Exchanged queries between smartphone and AWS cloud server and IP Camera](#Exchanged-queries-between-smartphone-and-AWS-cloud-server-and-IP-Camera)
* [Data security](#Data-security)
* [Cloud server certificates](#Cloud-server-certificates)
* [Potential vulnerabilities](#Potential-vulnerabilities)
* [Camera firmware](#Camera-firmware)
* [Conclusion](#Conclusion)
* [Further work](#Further-work)

# Prerequisite

For the final project of my Bachelor's studies I have decided to investigate  security vulnerabilities and issues that might be present within various IP camera models. One of the cameras that I have investigated was ***Besder 6024PB-XMA501*** IP Camera - one of the cheaper cameras that can be found from AliExpress. I thought to give it a try and bought it with hopes of finding some potentially _"interesting"_ stuff to put into my final project. My hopes were fulfilled and after the security investigation that I have done while writing my final project I decided to make some minor corrections to the analysis and post the full research here.

![Image of the camera](/img/Besder.jpg)

# Analysis methodology

The whole security analysis of the IP camera was conducted from my custom ***Arch Linux*** operating system installon. Plan of my analysis is as follows:

1. Factory reset of the camera.
2. Initial setup of the camera.
3. Technical and network information discovery about the camera - open ports, OS version, etc.
4. Test camera control capabilities within a control panel in a web browser.
5. Analyze camera's communication with cloud services.
6. Check the security of transmited data.
7. Conclusion of analysis' results.

# Factory reset

Tested Besder camera has a separate button installed which, when pressed, defaults settings of the Besder camera. There is also a port for connecting ethernet cable and a socket for connecting power cord. You can see it in the picture below.

![Camera dongles](/img/Camera_dongles.jpg)

# Initial Setup

Inside the box that arrived there was the camera itself, a screw to fix a camera to a certain place and a ***User Manual*** in english language. Within the user manual there were instructions how to set up the camera for the first time. Turns out, I needed to download ***ICSee*** app to my smartphone to do that. First time configuration requires the user to connect to a Wi-Fi network. By default during the initial install the IP address of the camera in the Local Area Network is set dynamically, although it is possible to set a static IP address of `192.168.0.10`.

# Technical Information

In this section I will present the technical data and networking information about ***Besder 6024PB-XMA501*** IP camera. For gathering this information I have used the `nmap` tool.

## Open ports

In this subsection I am presenting the list of open ports that I have found in a tested Besder IP camera. During the analysis search for both ***TCP*** and ***UDP*** open ports was conducted.

### TCP port scan

As I have mentioned before, `nmap` tool was used for this information gathering procedure. The command to find TCP ports and determine their purpose was `nmap -v -sS -sV -sC -p- X.X.X.X`, where `X.X.X.X` is IP address of the Besder camera. The scan was conducted with ***root*** privilleges. Purpose of used flags is explained below:

```
-v		Verbosity. Gives more information about what the scan is doing.
-sS		Stealth scan. Fast, accurate and non-intrusive test of a selected target.
-sV		Version scan. Used to detect versions of services running on specific open ports of IP Camera.
-sC		Scripts scan. Uses a default set of most common `nmap` scripts.
-p-		Check all 65535 TCP ports for if they are open.
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
1. Port `80` is a ***HTTP*** port and is used for communicating with `NETSurveillance WEB` web interface, which is intended for managing the IP Camera from an instance of preferred internet browser.
2. Port `554` is a ***RTSP*** port with version `H264DVR rtspd 1.0` and could be used for retrieving the video stream from the camera with a specific URL which I have not figured out yet. Although I reckon login credentials would be neccesary there.
3. Port `8899` has a service running that is detected as an  `ospf-lite` service and as far as I could find information about it, it could be used as an ONVIF-compliant port ["for effective interoperability of IP-based physical security products"](https://www.onvif.org/).
4. Port `12901` was also open during analysis, although `nmap` was not able to determine what service was running on this specific port.
5. Port `34567` is controlled by a service called `dhanalakshmi`. It is a data port which is used for transmitting and recieving data when the user connects to the camera either from a computer or a smartphone trough a proxy cloud server. I will elaborate on this specific port a bit more in later sections. For now I will note that most of the communication done via this port is ***encrypted*** or ***obfuscated*** using SSL.

Note: a quick Google search of the `http-favicon: Unknown favicon MD5: EC9D1C872C50DD7DA7D826D9C85FC158` lead to a numerous reports of possible malware and strange behaviour of a few different IP camera models (albeit older than the IP camera model tested in this analysis).

### UDP port scan

For the task of scanning and searching for open UDP ports I have used `-sU` flag within the `nmap` tool. Although this time I have set the program to scan only 1000 most popular ports as UDP port scanning is a lot slower than TCP scan (as for why, one can read part of Nmap documentation about UDP scanning [here](https://nmap.org/book/scan-methods-udp-scan.html)). The command used there was `nmap -v -sU -sV X.X.X.X`, where `X.X.X.X` is IP address of the camera. The scan was run with ***root*** privilleges. Results of the scan are presented below.

```
PORT     STATE         SERVICE      VERSION
3702/udp open|filtered ws-discovery
```

The scan found ***1*** open ***UDP*** port on which `ws-discovery` service was running. The service `ws-discovery` stands for ***web service discovery*** and is used for locating services within the devices connected via Local Area Network.

## OS Detection

Using `nmap` tool with `-O` flag I was able to determine the Operating System and it's version running on the analyzed Besder 6024PB-XMA501 IP Camera. The full command for this scan was `nmap -v -sS -sV -O X.X.X.X`, where `X.X.X.X` is an IP address of the Besder IP camera. The results of this scan are presented below.

```
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
```

As it can be seen from the result, Besder ip camera is regarded as a `general purpose` device and is running Linux OS with a likely version of `Linux 3.2 - 3.16`.

# Control Panel in a Web Browser
This is the time when some really interesting things start to show up. I have tried to access the control panel of the camera in at the time the newest version of `Mozilla Firefox` browser within my Arch Linux install... Just to be greeted with this nice pop-up window saying that my browser is ***too new*** and that some features would not work properly and I was requested to download Firefox browser version `51` or earliear. For a reference, Firefox 51 was released in ***January of 2017***.

![Pop-up saying that my browser is too new for rendering the control panel](/img/Browser_too_new.png)

Indeed, the webpage was not working as intented, displaying only a single line of text and a button to download `NewActive.exe` installerfile. It does not seem like a good idea for me to download any .exe files that a webpage, which requires an ancient version of web browser installed, asks me to download...

Anyways, I have a `Windows 10` virtual machine installed within a `VirtualBox` environment, so I have switched to that for further testing of a Besder camera's web interface. Tried a few other of the most popular browsers like Chrome, Opera and Edge - all gave me the same pop-up asking to download old versions of those browsers. Turns out that the `NETSurveillance WEB`, used for controlling the camera, requires `ActiveX` plugin for proper functioning and the only browser that displayed the `NETSurveillanceWEB` inteface correctly was the "good old" `Internet Explorer` browser with `ActiveX` plugin installed and enabled. That "might" cause some problems with security of this particular camera and computing devices connected to it, but I will not elaborate on this further ***for now***.

So, I have tried to log into the `NETSurveillance WEB` control panel. After pressing the login button it takes a couple of seconds to start any login activity. To figure out why, I decided to inspect the webpage's code. And there I had found a `Javascript` login function which had a very _"interesting"_ feature added - a 2 second timer, which activates ***after*** pressing the login button. To be honest, I am not sure about the purpose of this delay. One idea that I have is that it is used to make this particular device look slower than it actually is, especially in comparison to higher end models that the company is offering. But that is just speculation from my side.

## A further investigation of a control panel of an IP camera
*
***Added on 26/06/2021***

Using ***Wireshark*** tool I have examined the data stream between `Besder 6024PB-XMA501` IP camera and a `NETSurveillanceWEB` web interface within `Windows 10` virtual machine. What I have found is that when the connection request is sent from the browser within the virtual machine to the surveillance camera, the surveillance camera sends multiple `.html`, `.css` and `.js` files of the `NETSurveillance WEB` control panel are sent to the browser. One file that looked the most interesting to me was ***m.jsp*** file, containing some `Javascript` code. In this particular file was the following `packed function`:

```
val(function(p, a, c, k, e, d) {
    e = function(c) {
        return (c < a ? '' : e(parseInt(c / a))) + ((c = c % a) > 35 ? String.fromCharCode(c + 29) : c.toString(36))
    };

    if (!''.replace(/^/, String)) {
        while (c--) {
            d[e(c)] = k[c] || e(c)
        }
        k = [function(e) { return d[e] } ];
        e = function() { return '\\w+' };
        c = 1
    };

    while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
        }
    } 
    return p
} 
('m 9l={9e:\'1.11\'};h $4Z(K){k(K!=7H)};h $C(K){o(!$4Z(K))k X;o(K.3z)k\'J\';m C=56 K;o(C==\'2e\'&&K.9d){1W(K.6n){Y 1:k\'J\';Y 3:k(/\\S/).2B(K.80)?\'9g\':\'9h\'}}o(C==\'2e\'||C==\'h\'){1W(K.7M){Y 1Z:k\'1m\';Y 6f:k\'64\';Y 1i:k\'5A\'}o(56 K.P==\'4n\'){o(K.2G)k\'9p\';o(K.7O)k\'18\'}}k C};h $2c(){m 49={};L(m i=0;i<18.P;i++){L(m F 1a 18[i]){m ap=18[i][F];m 5a=49[F];o(5a&&$C(ap)==\'2e\'&&$C(5a)==\'2e\')49[F]=$2c(5a,ap);19 49[F]=ap}}k 49};m $O=h(){m 1c=18;o(!1c[1])1c=[c,1c[0]];L(m F 1a 1c[1])1c[0][F]=1c[1][F];k 1c[0]};m $3M=h(){L(m i=0,l=18.P;i<l;i++){18[i].O=h(1D){L(m 1G 1a 1D){o(!c.1w[1G])c.1w[1G]=1D[1G];o(!c[1G])c[1G]=$3M.5f(1G)}}}};$3M.5f=h(1G){k h(U){k c.1w[1G].3f(U,1Z.1w.7v.26(18,1))}};$3M(5J,1Z,4Q,7A);h $2d(K){k!!(K||K===0)};h $4D(K,7J){k $4Z(K)?K:7J};h $5U(3m,2r){k 1g.9x(1g.5U()*(2r-3m+1)+3m)};h $2X(){k W 82().7X()};h $6A(23){9u(23);9D(23);k 1j};m 30=h(K){K=K||{};K.O=$O;k K};m 8V=W 30(V);m 8O=W 30(17);17.7I=17.2m(\'7I\')[0];V.3g=!!(17.54);o(V.97)V.2D=V[V.92?\'ai\':\'7L\']=1e;19 o(17.7Y&&!17.a8&&!ab.aj)V.4a=V[V.3g?\'ak\':\'8C\']=1e;19 o(17.aw!=1j)V.5G=1e;V.9M=V.4a;9O.O=$O;o(56 4g==\'7H\'){m 4g=h(){};o(V.4a)17.7D("9F");4g.1w=(V.4a)?V["[[a1.1w]]"]:{}}4g.1w.3z=h(){};o(V.7L)6o{17.9X("9W",X,1e)}6d(e){};m 1i=h(2F){m 4c=h(){k(18[0]!==1j&&c.1C&&$C(c.1C)==\'h\')?c.1C.3f(c,18):c};$O(4c,c);4c.1w=2F;4c.7M=1i;k 4c};1i.1L=h(){};1i.1w={O:h(2F){m 59=W c(1j);L(m F 1a 2F){m 7Q=59[F];59[F]=1i.7P(7Q,2F[F])}k W 1i(59)},3S:h(){L(m i=0,l=18.P;i<l;i++)$O(c.1w,18[i])}};1i.7P=h(33,1R){o(33&&33!=1R){m C=$C(1R);o(C!=$C(33))k 1R;1W(C){Y\'h\':m 5H=h(){c.1A=18.7O.1A;k 1R.3f(c,18)};5H.1A=33;k 5H;Y\'2e\':k $2c(33,1R)}}k 1R};m 8g=W 1i({a2:h(N){c.3s=c.3s||[];c.3s.1f(N);k c},8s:h(){o(c.3s&&c.3s.P)c.3s.7c().22(10,c)},a0:h(){c.3s=[]}});m 2j=W 1i({2t:h(C,N){o(N!=1i.1L){c.$12=c.$12||{};c.$12[C]=c.$12[C]||[];c.$12[C].5T(N)}k c},1B:h(C,1c,22){o(c.$12&&c.$12[C]){c.$12[C].1E(h(N){N.2y({\'U\':c,\'22\':22,\'18\':1c})()},c)}k c},5k:h(C,N){o(c.$12&&c.$12[C])c.$12[C].2x(N);k c}});m 4B=W 1i({3Q:h(){c.B=$2c.3f(1j,[c.B].O(18));o(c.2t){L(m 2S 1a c.B){o($C(c.B[2S]==\'h\')&&(/^66[A-Z]/).2B(2S))c.2t(2S,c.B[2S])}}k c}});1Z.O({57:h(N,U){L(m i=0,j=c.P;i<j;i++)N.26(U,c[i],i,c)},2q:h(N,U){m 3T=[];L(m i=0,j=c.P;i<j;i++){o(N.26(U,c[i],i,c))3T.1f(c[i])}k 3T},2h:h(N,U){m 3T=[];L(m i=0,j=c.P;i<j;i++)3T[i]=N.26(U,c[i],i,c);k 3T},4M:h(N,U){L(m i=0,j=c.P;i<j;i++){o(!N.26(U,c[i],i,c))k X}k 1e},9S:h(N,U){L(m i=0,j=c.P;i<j;i++){o(N.26(U,c[i],i,c))k 1e}k X},3F:h(2G,R){m 3U=c.P;L(m i=(R<0)?1g.2r(0,3U+R):R||0;i<3U;i++){o(c[i]===2G)k i}k-1},7x:h(1l,P){1l=1l||0;o(1l<0)1l=c.P+1l;P=P||(c.P-1l);m 5O=[];L(m i=0;i<P;i++)5O[i]=c[1l++];k 5O},2x:h(2G){m i=0;m 3U=c.P;5N(i<3U){o(c[i]===2G){c.5t(i,1);3U--}19{i++}}k c},1d:h(2G,R){k c.3F(2G,R)!=-1},9I:h(1z){m K={},P=1g.3m(c.P,1z.P);L(m i=0;i<P;i++)K[1z[i]]=c[i];k K},O:h(1m){L(m i=0,j=1m.P;i<j;i++)c.1f(1m[i]);k c},2c:h(1m){L(m i=0,l=1m.P;i<l;i++)c.5T(1m[i]);k c},5T:h(2G){o(!c.1d(2G))c.1f(2G);k c},9G:h(){k c[$5U(0,c.P-1)]||1j},6D:h(){k c[c.P-1]||1j}});1Z.1w.1E=1Z.1w.57;1Z.1E=1Z.57;h $A(1m){k 1Z.7x(1m)};h $1E(3i,N,U){o(3i&&56 3i.P==\'4n\'&&$C(3i)!=\'2e\'){1Z.57(3i,N,U)}19{L(m 1p 1a 3i)N.26(U||3i,3i[1p],1p)}};1Z.1w.2B=1Z.1w.1d;4Q.O({2B:h(5d,2l){k(($C(5d)==\'1T\')?W 6f(5d,2l):5d).2B(c)},2u:h(){k 4o(c,10)},7E:h(){k 4k(c)},6p:h(){k c.2Q(/-\\D/g,h(2o){k 2o.5E(1).7w()})},7V:h(){k c.2Q(/\\w[A-Z]/g,h(2o){k(2o.5E(0)+\'-\'+2o.5E(1).4i())})},6v:h(){k c.2Q(/\\b[a-z]/g,h(2o){k 2o.7w()})},5Z:h(){k c.2Q(/^\\s+|\\s+$/g,\'\')},6e:h(){k c.2Q(/\\s{2,}/g,\' \').5Z()},4T:h(1m){m 2f=c.2o(/\\d{1,3}/g);k(2f)?2f.4T(1m):X},4s:h(1m){m 3p=c.2o(/^#?(\\w{1,2})(\\w{1,2})(\\w{1,2})$/);k(3p)?3p.7v(1).4s(1m):X},1d:h(1T,s){k(s)?(s+c+s).3F(s+1T+s)>-1:c.3F(1T)>-1},83:h(){k c.2Q(/([.*+?^${}()|[\\]\\/\\\\])/g,\'\\\\$1\')}});1Z.O({4T:h(1m){o(c.P<3)k X;o(c.P==4&&c[3]==0&&!1m)k\'a5\';m 3p=[];L(m i=0;i<3;i++){m 3V=(c[i]-0).3O(16);3p.1f((3V.P==1)?\'0\'+3V:3V)}k 1m?3p:\'#\'+3p.1S(\'\')},4s:h(1m){o(c.P!=3)k X;m 2f=[];L(m i=0;i<3;i++){2f.1f(4o((c[i].P==1)?c[i]+c[i]:c[i],16))}k 1m?2f:\'2f(\'+2f.1S(\',\')+\')\'}});5J.O({2y:h(B){m N=c;B=$2c({\'U\':N,\'G\':X,\'18\':1j,\'22\':X,\'3o\':X,\'5h\':X},B);o($2d(B.18)&&$C(B.18)!=\'1m\')B.18=[B.18];k h(G){m 1c;o(B.G){G=G||V.G;1c=[(B.G===1e)?G:W B.G(G)];o(B.18)1c.O(B.18)}19 1c=B.18||18;m 2U=h(){k N.3f($4D(B.U,N),1c)};o(B.22)k a6(2U,B.22);o(B.3o)k aq(2U,B.3o);o(B.5h)6o{k 2U()}6d(ao){k X};k 2U()}},an:h(1c,U){k c.2y({\'18\':1c,\'U\':U})},5h:h(1c,U){k c.2y({\'18\':1c,\'U\':U,\'5h\':1e})()},U:h(U,1c){k c.2y({\'U\':U,\'18\':1c})},al:h(U,1c){k c.2y({\'U\':U,\'G\':1e,\'18\':1c})},22:h(22,U,1c){k c.2y({\'22\':22,\'U\':U,\'18\':1c})()},3o:h(7z,U,1c){k c.2y({\'3o\':7z,\'U\':U,\'18\':1c})()}});7A.O({2u:h(){k 4o(c)},7E:h(){k 4k(c)},1r:h(3m,2r){k 1g.3m(2r,1g.2r(3m,c))},35:h(42){42=1g.2V(10,42||0);k 1g.35(c*42)/42},ax:h(N){L(m i=0;i<c;i++)N(i)}});m M=W 1i({1C:h(q,1D){o($C(q)==\'1T\'){o(V.2D&&1D&&(1D.1p||1D.C)){m 1p=(1D.1p)?\' 1p="\'+1D.1p+\'"\':\'\';m C=(1D.C)?\' C="\'+1D.C+\'"\':\'\';4R 1D.1p;4R 1D.C;q=\'<\'+q+1p+C+\'>\'}q=17.7D(q)}q=$(q);k(!1D||!q)?q:q.1M(1D)}});m 1P=W 1i({1C:h(T){k(T)?$O(T,c):c}});1P.O=h(1D){L(m 1G 1a 1D){c.1w[1G]=1D[1G];c[1G]=$3M.5f(1G)}};h $(q){o(!q)k 1j;o(q.3z)k 1Y.3J(q);o([V,17].1d(q))k q;m C=$C(q);o(C==\'1T\'){q=17.4z(q);C=(q)?\'J\':X}o(C!=\'J\')k 1j;o(q.3z)k 1Y.3J(q);o([\'2e\',\'av\'].1d(q.4F.4i()))k q;$O(q,M.1w);q.3z=h(){};k 1Y.3J(q)};17.4H=17.2m;h $$(){m T=[];L(m i=0,j=18.P;i<j;i++){m 1y=18[i];1W($C(1y)){Y\'J\':T.1f(1y);Y\'at\':1x;Y X:1x;Y\'1T\':1y=17.4H(1y,1e);6i:T.O(1y)}}k $$.4m(T)};$$.4m=h(1m){m T=[];L(m i=0,l=1m.P;i<l;i++){o(1m[i].$5g)4W;m J=$(1m[i]);o(J&&!J.$5g){J.$5g=1e;T.1f(J)}}L(m n=0,d=T.P;n<d;n++)T[n].$5g=1j;k W 1P(T)};1P.4J=h(F){k h(){m 1c=18;m 1k=[];m T=1e;L(m i=0,j=c.P,2U;i<j;i++){2U=c[i][F].3f(c[i],1c);o($C(2U)!=\'J\')T=X;1k.1f(2U)};k(T)?$$.4m(1k):1k}};M.O=h(2F){L(m F 1a 2F){4g.1w[F]=2F[F];M.1w[F]=2F[F];M[F]=$3M.5f(F);m 7S=(1Z.1w[F])?F+\'1P\':F;1P.1w[7S]=1P.4J(F)}};M.O({1M:h(1D){L(m 1G 1a 1D){m 3y=1D[1G];1W(1G){Y\'8t\':c.6E(3y);1x;Y\'12\':o(c.5F)c.5F(3y);1x;Y\'2F\':c.8e(3y);1x;6i:c.52(1G,3y)}}k c},3n:h(q,88){q=$(q);1W(88){Y\'87\':q.2E.6h(c,q);1x;Y\'86\':m 43=q.7T();o(!43)q.2E.6g(c);19 q.2E.6h(c,43);1x;Y\'1o\':m 5W=q.61;o(5W){q.6h(c,5W);1x}6i:q.6g(c)}k c},ac:h(q){k c.3n(q,\'87\')},8E:h(q){k c.3n(q,\'86\')},ah:h(q){k c.3n(q,\'4e\')},ag:h(q){k c.3n(q,\'1o\')},8G:h(){m T=[];$1E(18,h(85){T=T.6l(85)});$$(T).3n(c);k c},2x:h(){k c.2E.7d(c)},ae:h(89){m q=$(c.af(89!==X));o(!q.$12)k q;q.$12={};L(m C 1a c.$12)q.$12[C]={\'1z\':$A(c.$12[C].1z),\'1X\':$A(c.$12[C].1X)};k q.5m()},9v:h(q){q=$(q);c.2E.93(q,c);k q},73:h(2n){c.6g(17.8Z(2n));k c},6j:h(1v){k c.1v.1d(1v,\' \')},8d:h(1v){o(!c.6j(1v))c.1v=(c.1v+\' \'+1v).6e();k c},8a:h(1v){c.1v=c.1v.2Q(W 6f(\'(^|\\\\s)\'+1v+\'(?:\\\\s|$)\'),\'$1\').6e();k c},94:h(1v){k c.6j(1v)?c.8a(1v):c.8d(1v)},2g:h(F,I){1W(F){Y\'21\':k c.8c(4k(I));Y\'9a\':F=(V.2D)?\'99\':\'98\'}F=F.6p();1W($C(I)){Y\'4n\':o(![\'96\',\'84\'].1d(F))I+=\'3B\';1x;Y\'1m\':I=\'2f(\'+I.1S(\',\')+\')\'}c.1u[F]=I;k c},6E:h(3b){1W($C(3b)){Y\'2e\':M.5n(c,\'2g\',3b);1x;Y\'1T\':c.1u.5X=3b}k c},8c:h(21){o(21==0){o(c.1u.4P!="4E")c.1u.4P="4E"}19{o(c.1u.4P!="8b")c.1u.4P="8b"}o(!c.4O||!c.4O.8Q)c.1u.84=1;o(V.2D)c.1u.2q=(21==1)?\'\':"8N(21="+21*7C+")";c.1u.21=c.$3h.21=21;k c},1K:h(F){F=F.6p();m 1t=c.1u[F];o(!$2d(1t)){o(F==\'21\')k c.$3h.21;1t=[];L(m 1u 1a M.31){o(F==1u){M.31[1u].1E(h(s){m 1u=c.1K(s);1t.1f(4o(1u)?1u:\'79\')},c);o(F==\'3c\'){m 4M=1t.4M(h(3V){k(3V==1t[0])});k(4M)?1t[0]:X}k 1t.1S(\' \')}}o(F.1d(\'3c\')){o(M.31.3c.1d(F)){k[\'76\',\'6F\',\'6H\'].2h(h(p){k c.1K(F+p)},c).1S(\' \')}19 o(M.77.1d(F)){k[\'6T\',\'6S\',\'6Z\',\'6Y\'].2h(h(p){k c.1K(\'3c\'+p+F.2Q(\'3c\',\'\'))},c).1S(\' \')}}o(17.7W)1t=17.7W.8X(c,1j).8R(F.7V());19 o(c.4O)1t=c.4O[F]}o(V.2D)1t=M.70(F,1t,c);o(1t&&F.2B(/4G/i)&&1t.1d(\'2f\')){k 1t.4K(\'2f\').5t(1,4).2h(h(4G){k 4G.4T()}).1S(\' \')}k 1t},8u:h(){k M.6a(c,\'1K\',18)},4q:h(4U,1l){4U+=\'8T\';m q=(1l)?c[1l]:c[4U];5N(q&&$C(q)!=\'J\')q=q[4U];k $(q)},9b:h(){k c.4q(\'33\')},7T:h(){k c.4q(\'43\')},9c:h(){k c.4q(\'43\',\'61\')},6D:h(){k c.4q(\'33\',\'9r\')},9s:h(){k $(c.2E)},9w:h(){k $$(c.7Y)},5V:h(q){k!!$A(c.2m(\'*\')).1d(q)},4v:h(F){m 2Y=M.4V[F];o(2Y)k c[2Y];m 6c=M.7o[F]||0;o(!V.2D||6c)k c.9C(F,6c);m 63=c.9A[F];k(63)?63.80:1j},9q:h(F){m 2Y=M.4V[F];o(2Y)c[2Y]=\'\';19 c.az(F);k c},9i:h(){k M.6a(c,\'4v\',18)},52:h(F,I){m 2Y=M.4V[F];o(2Y)c[2Y]=I;19 c.9o(F,I);k c},8e:h(3b){k M.5n(c,\'52\',3b)},78:h(){c.74=$A(18).1S(\'\');k c},9m:h(2n){m 2J=c.3W();o([\'1u\',\'3R\'].1d(2J)){o(V.2D){o(2J==\'1u\')c.72.5X=2n;19 o(2J==\'3R\')c.52(\'2n\',2n);k c}19{c.7d(c.61);k c.73(2n)}}c[$4Z(c.5Y)?\'5Y\':\'75\']=2n;k c},bP:h(){m 2J=c.3W();o([\'1u\',\'3R\'].1d(2J)){o(V.2D){o(2J==\'1u\')k c.72.5X;19 o(2J==\'3R\')k c.4v(\'2n\')}19{k c.74}}k($4D(c.5Y,c.75))},3W:h(){k c.4F.4i()},1L:h(){1Y.5u(c.2m(\'*\'));k c.78(\'\')}});M.70=h(F,1t,J){o($2d(4o(1t)))k 1t;o([\'3e\',\'2L\'].1d(F)){m 1X=(F==\'2L\')?[\'1q\',\'4d\']:[\'1o\',\'4e\'];m 4A=0;1X.1E(h(I){4A+=J.1K(\'3c-\'+I+\'-2L\').2u()+J.1K(\'65-\'+I).2u()});k J[\'1F\'+F.6v()]-4A+\'3B\'}19 o(F.2B(/3c(.+)76|2p|65/)){k\'79\'}k 1t};M.31={\'3c\':[],\'65\':[],\'2p\':[]};[\'6T\',\'6S\',\'6Z\',\'6Y\'].1E(h(6X){L(m 1u 1a M.31)M.31[1u].1f(1u+6X)});M.77=[\'bz\',\'bx\',\'bw\'];M.6a=h(q,2H,1z){m 1t={};$1E(1z,h(1h){1t[1h]=q[2H](1h)});k 1t};M.5n=h(q,2H,69){L(m 1h 1a 69)q[2H](1h,69[1h]);k q};M.4V=W 30({\'5A\':\'1v\',\'L\':\'bG\',\'bH\':\'bF\',\'bY\':\'bC\',\'bD\':\'bX\',\'c0\':\'cf\',\'cg\':\'ch\',\'cb\':\'c3\',\'c2\':\'c1\',\'I\':\'I\',\'5z\':\'5z\',\'5C\':\'5C\',\'6r\':\'6r\',\'5D\':\'5D\'});M.7o={\'c4\':2,\'4t\':2};M.29={4X:{2A:h(C,N){o(c.6q)c.6q(C,N,X);19 c.c5(\'66\'+C,N);k c},3K:h(C,N){o(c.8f)c.8f(C,N,X);19 c.c8(\'66\'+C,N);k c}}};V.O(M.29.4X);17.O(M.29.4X);M.O(M.29.4X);m 1Y={T:[],3J:h(q){o(!q.$3h){1Y.T.1f(q);q.$3h={\'21\':1}}k q},5u:h(T){L(m i=0,j=T.P,q;i<j;i++){o(!(q=T[i])||!q.$3h)4W;o(q.$12)q.1B(\'5u\').5m();L(m p 1a q.$3h)q.$3h[p]=1j;L(m d 1a M.1w)q[d]=1j;1Y.T[1Y.T.3F(q)]=1j;q.3z=q.$3h=q=1j}1Y.T.2x(1j)},1L:h(){1Y.3J(V);1Y.3J(17);1Y.5u(1Y.T)}};V.2A(\'8K\',h(){V.2A(\'5M\',1Y.1L);o(V.2D)V.2A(\'5M\',bs)});m 2i=W 1i({1C:h(G){o(G&&G.$7j)k G;c.$7j=1e;G=G||V.G;c.G=G;c.C=G.C;c.3A=G.3A||G.aR;o(c.3A.6n==3)c.3A=c.3A.2E;c.7c=G.bt;c.aP=G.aT;c.aU=G.aV;c.aN=G.aM;o([\'5I\',\'5s\'].1d(c.C)){c.aE=(G.7b)?G.7b/aC:-(G.aA||0)/3}19 o(c.C.1d(\'1h\')){c.5o=G.7h||G.aB;L(m 1p 1a 2i.1z){o(2i.1z[1p]==c.5o){c.1h=1p;1x}}o(c.C==\'7U\'){m 5x=c.5o-aG;o(5x>0&&5x<13)c.1h=\'f\'+5x}c.1h=c.1h||4Q.aL(c.5o).4i()}19 o(c.C.2B(/(6U|2C|aH)/)){c.3x={\'x\':G.6b||G.7g+17.7f.4u,\'y\':G.6m||G.7l+17.7f.4y};c.b0={\'x\':G.6b?G.6b-V.bk:G.7g,\'y\':G.6m?G.6m-V.bh:G.7l};c.bm=(G.7h==3)||(G.bn==2);1W(c.C){Y\'5L\':c.1Q=G.1Q||G.bo;1x;Y\'62\':c.1Q=G.1Q||G.bf}c.7i()}k c},28:h(){k c.5q().5r()},5q:h(){o(c.G.5q)c.G.5q();19 c.G.b6=1e;k c},5r:h(){o(c.G.5r)c.G.5r();19 c.G.b4=X;k c}});2i.5v={1Q:h(){o(c.1Q&&c.1Q.6n==3)c.1Q=c.1Q.2E},7e:h(){6o{2i.5v.1Q.26(c)}6d(e){c.1Q=c.3A}}};2i.1w.7i=(V.5G)?2i.5v.7e:2i.5v.1Q;2i.1z=W 30({\'bb\':13,\'ba\':38,\'b9\':40,\'1q\':37,\'4d\':39,\'b3\':27,\'bp\':32,\'bq\':8,\'bg\':9,\'4R\':46});M.29.2j={2t:h(C,N){c.$12=c.$12||{};c.$12[C]=c.$12[C]||{\'1z\':[],\'1X\':[]};o(c.$12[C].1z.1d(N))k c;c.$12[C].1z.1f(N);m 5w=C;m 1V=M.2j[C];o(1V){o(1V.5K)1V.5K.26(c,N);o(1V.2h)N=1V.2h;o(1V.C)5w=1V.C}o(!c.6q)N=N.2y({\'U\':c,\'G\':1e});c.$12[C].1X.1f(N);k(M.5R.1d(5w))?c.2A(5w,N):c},5k:h(C,N){o(!c.$12||!c.$12[C])k c;m 1N=c.$12[C].1z.3F(N);o(1N==-1)k c;m 1h=c.$12[C].1z.5t(1N,1)[0];m I=c.$12[C].1X.5t(1N,1)[0];m 1V=M.2j[C];o(1V){o(1V.2x)1V.2x.26(c,N);o(1V.C)C=1V.C}k(M.5R.1d(C))?c.3K(C,I):c},5F:h(3b){k M.5n(c,\'2t\',3b)},5m:h(C){o(!c.$12)k c;o(!C){L(m 5p 1a c.$12)c.5m(5p);c.$12=1j}19 o(c.$12[C]){c.$12[C].1z.1E(h(N){c.5k(C,N)},c);c.$12[C]=1j}k c},1B:h(C,1c,22){o(c.$12&&c.$12[C]){c.$12[C].1z.1E(h(N){N.2y({\'U\':c,\'22\':22,\'18\':1c})()},c)}k c},7a:h(R,C){o(!R.$12)k c;o(!C){L(m 5p 1a R.$12)c.7a(R,5p)}19 o(R.$12[C]){R.$12[C].1z.1E(h(N){c.2t(C,N)},c)}k c}};V.O(M.29.2j);17.O(M.29.2j);M.O(M.29.2j);M.2j=W 30({\'6W\':{C:\'5L\',2h:h(G){G=W 2i(G);o(G.1Q!=c&&!c.5V(G.1Q))c.1B(\'6W\',G)}},\'6V\':{C:\'62\',2h:h(G){G=W 2i(G);o(G.1Q!=c&&!c.5V(G.1Q))c.1B(\'6V\',G)}},\'5s\':{C:(V.5G)?\'5I\':\'5s\'}});M.5R=[\'6U\',\'cc\',\'6G\',\'5e\',\'5s\',\'5I\',\'5L\',\'62\',\'3G\',\'7U\',\'bW\',\'c7\',\'53\',\'5M\',\'8K\',\'aO\',\'aY\',\'bc\',\'bd\',\'8n\',\'b8\',\'b7\',\'34\',\'br\',\'bl\',\'bj\',\'8I\'];5J.O({45:h(U,1c){k c.2y({\'U\':U,\'18\':1c,\'G\':2i})}});1P.O({aD:h(2J){k W 1P(c.2q(h(q){k(M.3W(q)==2J)}))},8v:h(1v,25){m T=c.2q(h(q){k(q.1v&&q.1v.1d(1v,\' \'))});k(25)?T:W 1P(T)},8w:h(3u,25){m T=c.2q(h(q){k(q.3u==3u)});k(25)?T:W 1P(T)},8x:h(1p,5B,I,25){m T=c.2q(h(q){m 1R=M.4v(q,1p);o(!1R)k X;o(!5B)k 1e;1W(5B){Y\'=\':k(1R==I);Y\'*=\':k(1R.1d(I));Y\'^=\':k(1R.8j(0,I.P)==I);Y\'$=\':k(1R.8j(1R.P-I.P)==I);Y\'!=\':k(1R!=I);Y\'~=\':k 1R.1d(I,\' \')}k X});k(25)?T:W 1P(T)}});h $E(1y,2q){k($(2q)||17).8k(1y)};h $bZ(1y,2q){k($(2q)||17).4H(1y)};$$.2W={\'64\':/^(\\w*|\\*)(?:#([\\w-]+)|\\.([\\w-]+))?(?:\\[(\\w+)(?:([!*^$]?=)["\']?([^"\'\\]]*)["\']?)?])?$/,\'3g\':{68:h(1k,2w,15,i){m 2b=[2w.bu?\'5Q:\':\'\',15[1]];o(15[2])2b.1f(\'[@3u="\',15[2],\'"]\');o(15[3])2b.1f(\'[1d(6l(" ", @5A, " "), " \',15[3],\' ")]\');o(15[4]){o(15[5]&&15[6]){1W(15[5]){Y\'*=\':2b.1f(\'[1d(@\',15[4],\', "\',15[6],\'")]\');1x;Y\'^=\':2b.1f(\'[by-bI(@\',15[4],\', "\',15[6],\'")]\');1x;Y\'$=\':2b.1f(\'[bJ(@\',15[4],\', 1T-P(@\',15[4],\') - \',15[6].P,\' + 1) = "\',15[6],\'"]\');1x;Y\'=\':2b.1f(\'[@\',15[4],\'="\',15[6],\'"]\');1x;Y\'!=\':2b.1f(\'[@\',15[4],\'!="\',15[6],\'"]\')}}19{2b.1f(\'[@\',15[4],\']\')}}1k.1f(2b.1S(\'\'));k 1k},67:h(1k,2w,25){m T=[];m 3g=17.54(\'.//\'+1k.1S(\'//\'),2w,$$.2W.8y,bT.bS,1j);L(m i=0,j=3g.bU;i<j;i++)T.1f(3g.bV(i));k(25)?T:W 1P(T.2h($))}},\'8H\':{68:h(1k,2w,15,i){o(i==0){o(15[2]){m q=2w.4z(15[2]);o(!q||((15[1]!=\'*\')&&(M.3W(q)!=15[1])))k X;1k=[q]}19{1k=$A(2w.2m(15[1]))}}19{1k=$$.2W.2m(1k,15[1]);o(15[2])1k=1P.8w(1k,15[2],1e)}o(15[3])1k=1P.8v(1k,15[3],1e);o(15[4])1k=1P.8x(1k,15[4],15[5],15[6],1e);k 1k},67:h(1k,2w,25){k(25)?1k:$$.4m(1k)}},8y:h(8A){k(8A==\'5Q\')?\'bQ://bK.bM.bN/aF/5Q\':X},2m:h(2w,4F){m 6k=[];L(m i=0,j=2w.P;i<j;i++)6k.O(2w[i].2m(4F));k 6k}};$$.2W.2H=(V.3g)?\'3g\':\'8H\';M.29.5y={4C:h(1y,25){m 1k=[];1y=1y.5Z().4K(\' \');L(m i=0,j=1y.P;i<j;i++){m 8D=1y[i];m 15=8D.2o($$.2W.64);o(!15)1x;15[1]=15[1]||\'*\';m 2b=$$.2W[$$.2W.2H].68(1k,c,15,i);o(!2b)1x;1k=2b}k $$.2W[$$.2W.2H].67(1k,c,25)},8k:h(1y){k $(c.4C(1y,1e)[0]||X)},4H:h(1y,25){m T=[];1y=1y.4K(\',\');L(m i=0,j=1y.P;i<j;i++)T=T.6l(c.4C(1y[i],1e));k(25)?T:$$.4m(T)}};M.O({4z:h(3u){m q=17.4z(3u);o(!q)k X;L(m 1A=q.2E;1A!=c;1A=1A.2E){o(!1A)k X}k q},ad:h(1v){k c.4C(\'.\'+1v)}});17.O(M.29.5y);M.O(M.29.5y);M.O({3l:h(){1W(c.3W()){Y\'34\':m 1X=[];$1E(c.B,h(2S){o(2S.5D)1X.1f($4D(2S.I,2S.2n))});k(c.6r)?1X:1X[0];Y\'8r\':o(!(c.5C&&[\'as\',\'ar\'].1d(c.C))&&![\'4E\',\'2n\',\'9N\'].1d(c.C))1x;Y\'8q\':k c.I}k X},8o:h(){k $$(c.2m(\'8r\'),c.2m(\'34\'),c.2m(\'8q\'))},9P:h(){m 5S=[];c.8o().1E(h(q){m 1p=q.1p;m I=q.3l();o(I===X||!1p||q.5z)k;m 5P=h(3y){5S.1f(1p+\'=\'+81(3y))};o($C(I)==\'1m\')I.1E(5P);19 5P(I)});k 5S.1S(\'&\')}});M.O({9J:h(x,y){c.4u=x;c.4y=y},9R:h(){k{\'8I\':{\'x\':c.4u,\'y\':c.4y},\'4A\':{\'x\':c.4h,\'y\':c.3Y},\'a3\':{\'x\':c.a4,\'y\':c.9Z}}},4w:h(2a){2a=2a||[];m q=c,1q=0,1o=0;9Y{1q+=q.9U||0;1o+=q.9T||0;q=q.9V}5N(q);2a.1E(h(J){1q-=J.4u||0;1o-=J.4y||0});k{\'x\':1q,\'y\':1o}},7m:h(2a){k c.4w(2a).y},7n:h(2a){k c.4w(2a).x},4L:h(2a){m 1s=c.4w(2a);m K={\'2L\':c.4h,\'3e\':c.3Y,\'1q\':1s.x,\'1o\':1s.y};K.4d=K.1q+K.2L;K.4e=K.1o+K.3e;k K}});M.2j.6s={5K:h(N){o(V.4x){N.26(c);k}m 3Z=h(){o(V.4x)k;V.4x=1e;V.23=$6A(V.23);c.1B(\'6s\')}.U(c);o(17.4I&&V.4a){V.23=h(){o([\'4x\',\'8p\'].1d(17.4I))3Z()}.3o(50)}19 o(17.4I&&V.2D){o(!$(\'6O\')){m 4t=(V.c9.9z==\'9y:\')?\'://0\':\'9B:8W(0)\';17.9Q(\'<3R 3u="6O" ay 4t="\'+4t+\'"><\\/3R>\');$(\'6O\').9H=h(){o(c.4I==\'8p\')3Z()}}}19{V.2A("53",3Z);17.2A("9K",3Z)}}};V.9L=h(N){k c.2t(\'6s\',N)};m 1b={};1b.2z=W 1i({B:{47:1i.1L,2N:1i.1L,8h:1i.1L,1J:h(p){k-(1g.7k(1g.6N*p)-1)/2},3j:am,1U:\'3B\',44:1e,8m:50},1C:h(B){c.J=c.J||1j;c.3Q(B);o(c.B.1C)c.B.1C.26(c)},1O:h(){m 2X=$2X();o(2X<c.2X+c.B.3j){c.8J=c.B.1J((2X-c.2X)/c.B.3j);c.3D();c.3E()}19{c.28(1e);c.1M(c.Q);c.1B(\'2N\',c.J,10);c.8s()}},1M:h(Q){c.14=Q;c.3E();k c},3D:h(){c.14=c.3I(c.R,c.Q)},3I:h(R,Q){k(Q-R)*c.8J+R},1l:h(R,Q){o(!c.B.44)c.28();19 o(c.23)k c;c.R=R;c.Q=Q;c.8n=c.Q-c.R;c.2X=$2X();c.23=c.1O.3o(1g.35(7u/c.B.8m),c);c.1B(\'47\',c.J);k c},28:h(3k){o(!c.23)k c;c.23=$6A(c.23);o(!3k)c.1B(\'8h\',c.J);k c},1V:h(R,Q){k c.1l(R,Q)},a9:h(3k){k c.28(3k)}});1b.2z.3S(W 8g,W 2j,W 4B);1b.2M={34:h(F,Q){o(F.2B(/4G/i))k c.6H;m C=$C(Q);o((C==\'1m\')||(C==\'1T\'&&Q.1d(\' \')))k c.4J;k c.8i},2k:h(q,F,3L){o(!3L.1f)3L=[3L];m R=3L[0],Q=3L[1];o(!$2d(Q)){Q=R;R=q.1K(F)}m 1n=c.34(F,Q);k{\'R\':1n.2k(R),\'Q\':1n.2k(Q),\'1n\':1n}}};1b.2M.8i={2k:h(I){k 4k(I)},3X:h(R,Q,3P){k 3P.3I(R,Q)},3l:h(I,1U,F){o(1U==\'3B\'&&F!=\'21\')I=1g.35(I);k I+1U}};1b.2M.4J={2k:h(I){k I.1f?I:I.4K(\' \').2h(h(v){k 4k(v)})},3X:h(R,Q,3P){m 14=[];L(m i=0;i<R.P;i++)14[i]=3P.3I(R[i],Q[i]);k 14},3l:h(I,1U,F){o(1U==\'3B\'&&F!=\'21\')I=I.2h(1g.35);k I.1S(1U+\' \')+1U}};1b.2M.6H={2k:h(I){k I.1f?I:I.4s(1e)},3X:h(R,Q,3P){m 14=[];L(m i=0;i<R.P;i++)14[i]=1g.35(3P.3I(R[i],Q[i]));k 14},3l:h(I){k\'2f(\'+I.1S(\',\')+\')\'}};1b.6F=1b.2z.O({1C:h(q,F,B){c.J=$(q);c.F=F;c.1A(B)},8B:h(){k c.1M(0)},3D:h(){c.14=c.1n.3X(c.R,c.Q,c)},1M:h(Q){c.1n=1b.2M.34(c.F,Q);k c.1A(c.1n.2k(Q))},1l:h(R,Q){o(c.23&&c.B.44)k c;m 1I=1b.2M.2k(c.J,c.F,[R,Q]);c.1n=1I.1n;k c.1A(1I.R,1I.Q)},3E:h(){c.J.2g(c.F,c.1n.3l(c.14,c.B.1U,c.F))}});M.O({9E:h(F,B){k W 1b.6F(c,F,B)}});1b.31=1b.2z.O({1C:h(q,B){c.J=$(q);c.1A(B)},3D:h(){L(m p 1a c.R)c.14[p]=c.1n[p].3X(c.R[p],c.Q[p],c)},1M:h(Q){m 1I={};c.1n={};L(m p 1a Q){c.1n[p]=1b.2M.34(p,Q[p]);1I[p]=c.1n[p].2k(Q[p])}k c.1A(1I)},1l:h(K){o(c.23&&c.B.44)k c;c.14={};c.1n={};m R={},Q={};L(m p 1a K){m 1I=1b.2M.2k(c.J,p,K[p]);R[p]=1I.R;Q[p]=1I.Q;c.1n[p]=1I.1n}k c.1A(R,Q)},3E:h(){L(m p 1a c.14)c.J.2g(p,c.1n[p].3l(c.14[p],c.B.1U,p))}});M.O({95:h(B){k W 1b.31(c,B)}});1b.1P=1b.2z.O({1C:h(T,B){c.T=$$(T);c.1A(B)},3D:h(){L(m i 1a c.R){m 4b=c.R[i],36=c.Q[i],2P=c.1n[i],4j=c.14[i]={};L(m p 1a 4b)4j[p]=2P[p].3X(4b[p],36[p],c)}},1M:h(Q){m 1I={};c.1n={};L(m i 1a Q){m 36=Q[i],2P=c.1n[i]={},8l=1I[i]={};L(m p 1a 36){2P[p]=1b.2M.34(p,36[p]);8l[p]=2P[p].2k(36[p])}}k c.1A(1I)},1l:h(K){o(c.23&&c.B.44)k c;c.14={};c.1n={};m R={},Q={};L(m i 1a K){m 6B=K[i],4b=R[i]={},36=Q[i]={},2P=c.1n[i]={};L(m p 1a 6B){m 1I=1b.2M.2k(c.T[i],p,6B[p]);4b[p]=1I.R;36[p]=1I.Q;2P[p]=1I.1n}}k c.1A(R,Q)},3E:h(){L(m i 1a c.14){m 4j=c.14[i],2P=c.1n[i];L(m p 1a 4j)c.T[i].2g(p,2P[p].3l(4j[p],c.B.1U,p))}}});1b.8P=1b.2z.O({B:{1H:\'6J\'},1C:h(q,B){c.J=$(q);c.3v=W M(\'8L\',{\'8t\':$O(c.J.8u(\'2p\'),{\'8S\':\'4E\'})}).8E(c.J).8G(c.J);c.J.2g(\'2p\',0);c.3Q(B);c.14=[];c.1A(c.B);c.41=1e;c.2t(\'2N\',h(){c.41=(c.14[0]===0)});o(V.8C)c.2t(\'2N\',h(){o(c.41)c.J.2x().3n(c.3v)})},3D:h(){L(m i=0;i<2;i++)c.14[i]=c.3I(c.R[i],c.Q[i])},6J:h(){c.2p=\'2p-1o\';c.4f=\'3e\';c.1F=c.J.3Y},6z:h(){c.2p=\'2p-1q\';c.4f=\'2L\';c.1F=c.J.4h},8z:h(1H){c[1H||c.B.1H]();k c.1l([c.J.1K(c.2p).2u(),c.3v.1K(c.4f).2u()],[0,c.1F])},8F:h(1H){c[1H||c.B.1H]();k c.1l([c.J.1K(c.2p).2u(),c.3v.1K(c.4f).2u()],[-c.1F,0])},8B:h(1H){c[1H||c.B.1H]();c.41=X;k c.1M([-c.1F,0])},9j:h(1H){c[1H||c.B.1H]();c.41=1e;k c.1M([0,c.1F])},9n:h(1H){o(c.3v.3Y==0||c.3v.4h==0)k c.8z(1H);k c.8F(1H)},3E:h(){c.J.2g(c.2p,c.14[0]+c.B.1U);c.3v.2g(c.4f,c.14[1]+c.B.1U)}});1b.6I=h(1J,2l){2l=2l||[];o($C(2l)!=\'1m\')2l=[2l];k $O(1J,{c6:h(1N){k 1J(1N,2l)},bE:h(1N){k 1-1J(1-1N,2l)},aS:h(1N){k(1N<=0.5)?1J(2*1N,2l)/2:(2-1J(2*(1-1N),2l))/2}})};1b.2I=W 30({aJ:h(p){k p}});1b.2I.O=h(6t){L(m 1J 1a 6t){1b.2I[1J]=W 1b.6I(6t[1J]);1b.2I.6u(1J)}};1b.2I.6u=h(1J){[\'aI\',\'b1\',\'ce\'].1E(h(6K){1b.2I[1J.4i()+6K]=1b.2I[1J][\'9f\'+6K]})};1b.2I.O({bv:h(p,x){k 1g.2V(p,x[0]||6)},bB:h(p){k 1g.2V(2,8*(p-1))},ca:h(p){k 1-1g.7t(1g.cd(p))},aQ:h(p){k 1-1g.7t((1-p)*1g.6N/2)},aZ:h(p,x){x=x[0]||1.aX;k 1g.2V(p,2)*((x+1)*p-x)},aW:h(p){m I;L(m a=0,b=1;1;a+=b,b/=2){o(p>=(7-4*a)/11){I=-1g.2V((11-6*a-11*p)/4,2)+b*b;1x}}k I},aK:h(p,x){k 1g.2V(2,10*--p)*1g.7k(20*p*1g.6N*(x[0]||1)/3)}});[\'b2\',\'b5\',\'be\',\'bi\'].1E(h(1J,i){1b.2I[1J]=W 1b.6I(h(p){k 1g.2V(p,[i+2])});1b.2I.6u(1J)});m 3a={};3a.2z=W 1i({B:{4r:X,1U:\'3B\',47:1i.1L,7r:1i.1L,2N:1i.1L,7p:1i.1L,6x:1i.1L,1r:X,2O:{x:\'1q\',y:\'1o\'},3r:X,6y:6},1C:h(q,B){c.3Q(B);c.J=$(q);c.4r=$(c.B.4r)||c.J;c.2C={\'14\':{},\'1N\':{}};c.I={\'1l\':{},\'14\':{}};c.2K={\'1l\':c.1l.45(c),\'3H\':c.3H.45(c),\'2T\':c.2T.45(c),\'28\':c.28.U(c)};c.7q();o(c.B.1C)c.B.1C.26(c)},7q:h(){c.4r.2t(\'5e\',c.2K.1l);k c},ci:h(){c.4r.5k(\'5e\',c.2K.1l);k c},1l:h(G){c.1B(\'7r\',c.J);c.2C.1l=G.3x;m 1r=c.B.1r;c.1r={\'x\':[],\'y\':[]};L(m z 1a c.B.2O){o(!c.B.2O[z])4W;c.I.14[z]=c.J.1K(c.B.2O[z]).2u();c.2C.1N[z]=G.3x[z]-c.I.14[z];o(1r&&1r[z]){L(m i=0;i<2;i++){o($2d(1r[z][i]))c.1r[z][i]=($C(1r[z][i])==\'h\')?1r[z][i]():1r[z][i]}}}o($C(c.B.3r)==\'4n\')c.B.3r={\'x\':c.B.3r,\'y\':c.B.3r};17.2A(\'3G\',c.2K.3H);17.2A(\'6G\',c.2K.28);c.1B(\'47\',c.J);G.28()},3H:h(G){m 7s=1g.35(1g.cj(1g.2V(G.3x.x-c.2C.1l.x,2)+1g.2V(G.3x.y-c.2C.1l.y,2)));o(7s>c.B.6y){17.3K(\'3G\',c.2K.3H);17.2A(\'3G\',c.2K.2T);c.2T(G);c.1B(\'7p\',c.J)}G.28()},2T:h(G){c.48=X;c.2C.14=G.3x;L(m z 1a c.B.2O){o(!c.B.2O[z])4W;c.I.14[z]=c.2C.14[z]-c.2C.1N[z];o(c.1r[z]){o($2d(c.1r[z][1])&&(c.I.14[z]>c.1r[z][1])){c.I.14[z]=c.1r[z][1];c.48=1e}19 o($2d(c.1r[z][0])&&(c.I.14[z]<c.1r[z][0])){c.I.14[z]=c.1r[z][0];c.48=1e}}o(c.B.3r[z])c.I.14[z]-=(c.I.14[z]%c.B.3r[z]);c.J.2g(c.B.2O[z],c.I.14[z]+c.B.1U)}c.1B(\'6x\',c.J);G.28()},28:h(){17.3K(\'3G\',c.2K.3H);17.3K(\'3G\',c.2K.2T);17.3K(\'6G\',c.2K.28);c.1B(\'2N\',c.J)}});3a.2z.3S(W 2j,W 4B);M.O({bA:h(B){k W 3a.2z(c,$2c({2O:{x:\'2L\',y:\'3e\'}},B))}});3a.7Z=3a.2z.O({B:{4Y:[],2v:X,2a:[]},1C:h(q,B){c.3Q(B);c.J=$(q);c.4Y=$$(c.B.4Y);c.2v=$(c.B.2v);c.1s={\'J\':c.J.1K(\'1s\'),\'2v\':X};o(c.2v)c.1s.2v=c.2v.1K(\'1s\');o(![\'5i\',\'3C\',\'6C\'].1d(c.1s.J))c.1s.J=\'3C\';m 1o=c.J.1K(\'1o\').2u();m 1q=c.J.1K(\'1q\').2u();o(c.1s.J==\'3C\'&&![\'5i\',\'3C\',\'6C\'].1d(c.1s.2v)){1o=$2d(1o)?1o:c.J.7m(c.B.2a);1q=$2d(1q)?1q:c.J.7n(c.B.2a)}19{1o=$2d(1o)?1o:0;1q=$2d(1q)?1q:0}c.J.6E({\'1o\':1o,\'1q\':1q,\'1s\':c.1s.J});c.1A(c.J)},1l:h(G){c.2s=1j;o(c.2v){m 3w=c.2v.4L();m q=c.J.4L();o(c.1s.J==\'3C\'&&![\'5i\',\'3C\',\'6C\'].1d(c.1s.2v)){c.B.1r={\'x\':[3w.1q,3w.4d-q.2L],\'y\':[3w.1o,3w.4e-q.3e]}}19{c.B.1r={\'y\':[0,3w.3e-q.3e],\'x\':[0,3w.2L-q.2L]}}}c.1A(G)},2T:h(G){c.1A(G);m 2s=c.48?X:c.4Y.2q(c.71,c).6D();o(c.2s!=2s){o(c.2s)c.2s.1B(\'bR\',[c.J,c]);c.2s=2s?2s.1B(\'bL\',[c.J,c]):1j}k c},71:h(q){q=q.4L(c.B.2a);m 14=c.2C.14;k(14.x>q.1q&&14.x<q.4d&&14.y<q.4e&&14.y>q.1o)},28:h(){o(c.2s&&!c.48)c.2s.1B(\'bO\',[c.J,c]);19 c.J.1B(\'au\',c);c.1A();k c}});M.O({9k:h(B){k W 3a.7Z(c,B)}});m 2Z=W 30({B:{5l:X,51:X,3j:X,4l:X},1M:h(1h,I,B){B=$2c(c.B,B);I=81(I);o(B.5l)I+=\'; 5l=\'+B.5l;o(B.51)I+=\'; 51=\'+B.51;o(B.3j){m 4N=W 82();4N.9t(4N.7X()+B.3j*24*60*60*7u);I+=\'; 8U=\'+4N.8M()}o(B.4l)I+=\'; 4l\';17.3t=1h+\'=\'+I;k $O(B,{\'1h\':1h,\'I\':I})},5j:h(1h){m I=17.3t.2o(\'(?:^|;)\\\\s*\'+1h.83()+\'=([^;]*)\');k I?8Y(I[1]):X},2x:h(3t,B){o($C(3t)==\'2e\')c.1M(3t.1h,\'\',$2c(3t,{3j:-1}));19 c.1M(3t,\'\',$2c(B,{3j:-1}))}});m 3N={3O:h(K){1W($C(K)){Y\'1T\':k\'"\'+K.2Q(/(["\\\\])/g,\'\\\\$1\')+\'"\';Y\'1m\':k\'[\'+K.2h(3N.3O).1S(\',\')+\']\';Y\'2e\':m 1T=[];L(m F 1a K)1T.1f(3N.3O(F)+\':\'+3N.3O(K[F]));k\'{\'+1T.1S(\',\')+\'}\';Y\'4n\':o(90(K))1x;Y X:k\'1j\'}k 4Q(K)},54:h(3q,4l){k(($C(3q)!=\'1T\')||(4l&&!3q.2B(/^("(\\\\.|[^"\\\\\\n\\r])*?"|[,:{}\\[\\]0-9.\\-+91-u \\n\\r\\t])+?$/)))?1j:a7(\'(\'+3q+\')\')}};m 2R=W 1i({P:0,1C:h(2e){c.K=2e||{};c.4p()},5j:h(1h){k(c.4S(1h))?c.K[1h]:1j},4S:h(1h){k(1h 1a c.K)},1M:h(1h,I){o(!c.4S(1h))c.P++;c.K[1h]=I;k c},4p:h(){c.P=0;L(m p 1a c.K)c.P++;k c},2x:h(1h){o(c.4S(1h)){4R c.K[1h];c.P--}k c},1E:h(N,U){$1E(c.K,N,U)},O:h(K){$O(c.K,K);k c.4p()},2c:h(){c.K=$2c.3f(1j,[c.K].O(18));k c.4p()},1L:h(){c.K={};c.P=0;k c},1z:h(){m 1z=[];L(m F 1a c.K)1z.1f(F);k 1z},1X:h(){m 1X=[];L(m F 1a c.K)1X.1f(c.K[F]);k 1X}});h $H(K){k W 2R(K)};2R.2Z=2R.O({1C:h(1p,B){c.1p=1p;c.B=$O({\'7R\':1e},B||{});c.53()},7B:h(){o(c.P==0){2Z.2x(c.1p,c.B);k 1e}m 3q=3N.3O(c.K);o(3q.P>aa)k X;2Z.1M(c.1p,3q,c.B);k 1e},53:h(){c.K=3N.54(2Z.5j(c.1p),1e)||{};c.4p()}});2R.2Z.29={};[\'O\',\'1M\',\'2c\',\'1L\',\'2x\'].1E(h(2H){2R.2Z.29[2H]=h(){2R.1w[2H].3f(c,18);o(c.B.7R)c.7B();k c}});2R.2Z.3S(2R.2Z.29);m 6P=W 1i({B:{7N:1i.1L,2N:1i.1L,6Q:h(1N){c.3d.2g(c.p,1N)},1H:\'6z\',5b:7C,1F:0},1C:h(q,3d,B){c.J=$(q);c.3d=$(3d);c.3Q(B);c.6R=-1;c.6M=-1;c.1O=-1;c.J.2t(\'5e\',c.7y.45(c));m 5c,1F;1W(c.B.1H){Y\'6z\':c.z=\'x\';c.p=\'1q\';5c={\'x\':\'1q\',\'y\':X};1F=\'4h\';1x;Y\'6J\':c.z=\'y\';c.p=\'1o\';5c={\'x\':X,\'y\':\'1o\'};1F=\'3Y\'}c.2r=c.J[1F]-c.3d[1F]+(c.B.1F*2);c.7G=c.3d[1F]/2;c.7F=c.J[\'5j\'+c.p.6v()].U(c.J);c.3d.2g(\'1s\',\'5i\').2g(c.p,-c.B.1F);m 6w={};6w[c.z]=[-c.B.1F,c.2r-c.B.1F];c.2T=W 3a.2z(c.3d,{1r:6w,2O:5c,6y:0,47:h(){c.55()}.U(c),6x:h(){c.55()}.U(c),2N:h(){c.55();c.3k()}.U(c)});o(c.B.1C)c.B.1C.26(c)},1M:h(1O){c.1O=1O.1r(0,c.B.5b);c.58();c.3k();c.1B(\'6Q\',c.7K(c.1O));k c},7y:h(G){m 1s=G.3x[c.z]-c.7F()-c.7G;1s=1s.1r(-c.B.1F,c.2r-c.B.1F);c.1O=c.6L(1s);c.58();c.3k();c.1B(\'6Q\',1s)},55:h(){c.1O=c.6L(c.2T.I.14[c.z]);c.58()},58:h(){o(c.6R!=c.1O){c.6R=c.1O;c.1B(\'7N\',c.1O)}},3k:h(){o(c.6M!==c.1O){c.6M=c.1O;c.1B(\'2N\',c.1O+\'\')}},6L:h(1s){k 1g.35((1s+c.B.1F)/c.2r*c.B.5b)},7K:h(1O){k c.2r*1O/c.B.5b}});6P.3S(W 2j);6P.3S(W 4B);', 62, 764, '||||||||||||this|||||function|||return||var||if||el|||||||||||options|type|||property|event||value|element|obj|for|Element|fn|extend|length|to|from||elements|bind|window|new|false|case||||events||now|param||document|arguments|else|in|Fx|args|contains|true|push|Math|key|Class|null|items|start|array|css|top|name|left|limit|position|result|style|className|prototype|break|selector|keys|parent|fireEvent|initialize|props|each|offset|prop|mode|parsed|transition|getStyle|empty|set|pos|step|Elements|relatedTarget|current|join|string|unit|custom|switch|values|Garbage|Array||opacity|delay|timer||nocash|call||stop|Methods|overflown|temp|merge|chk|object|rgb|setStyle|map|Event|Events|parse|params|getElementsByTagName|text|match|margin|filter|max|overed|addEvent|toInt|container|context|remove|create|Base|addListener|test|mouse|ie|parentNode|properties|item|method|Transitions|tag|bound|width|CSS|onComplete|modifiers|iCss|replace|Hash|option|drag|returns|pow|shared|time|index|Cookie|Abstract|Styles||previous|select|round|iTo||||Drag|source|border|knob|height|apply|xpath|tmp|iterable|duration|end|getValue|min|inject|periodical|hex|str|grid|chains|cookie|id|wrapper|cont|page|val|htmlElement|target|px|absolute|setNow|increase|indexOf|mousemove|check|compute|collect|removeListener|fromTo|native|Json|toString|fx|setOptions|script|implement|results|len|bit|getTag|getNow|offsetHeight|domReady||open|precision|next|wait|bindWithEvent||onStart|out|mix|webkit|iFrom|klass|right|bottom|layout|HTMLElement|offsetWidth|toLowerCase|iNow|parseFloat|secure|unique|number|parseInt|setLength|walk|handle|hexToRgb|src|scrollLeft|getProperty|getPosition|loaded|scrollTop|getElementById|size|Options|getElements|pick|hidden|tagName|color|getElementsBySelector|readyState|Multi|split|getCoordinates|every|date|currentStyle|visibility|String|delete|hasKey|rgbToHex|brother|Properties|continue|Listeners|droppables|defined||path|setProperty|load|evaluate|draggedKnob|typeof|forEach|checkStep|proto|mp|steps|mod|regex|mousedown|generic|included|attempt|relative|get|removeEvent|domain|removeEvents|setMany|code|evType|stopPropagation|preventDefault|mousewheel|s']))
```

After I have done some research, I have found that this is a javascript ***packer*** function, which is used for, well, packing the code and reduce the ammount of space it consumes, probably.

Anyway, I have found [Strictly Software's Javascript unpacker tool](https://www.strictly-software.com/unpacker/), which I have used to previously mentioned code and it unpacked to a javascript code, which was well over a couple of thousand lines.

Turns out, it is a ***Javascript framework*** called `MooTools` and it is used within the control panel of the Besder 6024PB-XMA501 IP camera. In this particular camera, a standart collection of [MooTools v1.11](https://searchcode.com/total-file/3397713/%20festos/admin/includes/tiny_mce/plugins/kfm/j/mootools.v1.11/mootools.v1.11.js/) utilities is used. It is mostly different functions of Javascript, but one is particualrly interesting for me and it is a function called `Hash`, which is presented below:

```
var Hash = new Class({
	length: 0,
	initialize: function (object) {
		this.obj = object || {};
		this.setLength()
	},
	get: function (key) {
		return (this.hasKey(key)) ? this.obj[key] : null
	},
	hasKey: function (key) {
		return (key in this.obj)
	},
	set: function (key, value) {
		if (!this.hasKey(key)) this.length++;
		this.obj[key] = value;
		return this
	},
	setLength: function () {
		this.length = 0;
		for (var p in this.obj) this.length++;
		return this
	},
	remove: function (key) {
		if (this.hasKey(key)) {
			delete this.obj[key];
			this.length--
		}
		return this
	},
	each: function (fn, bind) {
		$each(this.obj, fn, bind)
	},
	extend: function (obj) {
		$extend(this.obj, obj);
		return this.setLength()
	},
	merge: function () {
		this.obj = $merge.apply(null, [this.obj].extend(arguments));
		return this.setLength()
	},
	empty: function () {
		this.obj = {};
		this.length = 0;
		return this
	},
	keys: function () {
		var keys = [];
		for (var property in this.obj) keys.push(property);
		return keys
	},
	values: function () {
		var values = [];
		for (var property in this.obj) values.push(this.obj[property]);
		return values
	}
});
function $H(obj) {
	return new Hash(obj)
};
Hash.Cookie = Hash.extend({
	initialize: function (name, options) {
		this.name = name;
		this.options = $extend({
			'autoSave': true
		},
		options || {});
		this.load()
	},
	save: function () {
		if (this.length == 0) {
			Cookie.remove(this.name, this.options);
			return true
		}
		var str = Json.toString(this.obj);
		if (str.length > 4096) return false;
		Cookie.set(this.name, str, this.options);
		return true
	},
	load: function () {
		this.obj = Json.evaluate(Cookie.get(this.name), true) || {};
		this.setLength()
	}
});
Hash.Cookie.Methods = {};
['extend', 'set', 'merge', 'empty', 'remove'].each(function (method) {
	Hash.Cookie.Methods[method] = function () {
		Hash.prototype[method].apply(this, arguments);
		if (this.options.autoSave) this.save();
		return this
	}
});
Hash.Cookie.implement(Hash.Cookie.Methods);
```

There are a few ***hash-related*** sub-functions, although I have not yet figured how exactly do they work or how they are used when I actually connect to the IP camera and start communicating with it from my virtual machine. One of my guesses from inspecting the code are that this `Hash` function might be used to craft login session cookies.

This might be useful later on, if I try to figure out the exact way of how the data sent between devices is encrypted or obfuscated.

# Network communication analysis

For analyzing network traffic associated with the camera I have carried out a ***Man in the Middle*** cyberattack using `Ettercap` tool and intercepted all the traffic between a Besder 6024PB-XMA501 IP camera, a smartphone, Windows 10 virtual computer within Virtualbox and the TPLINK TL-WR841N router (for which I have conducted a separate cybersecurity research [here](https://github.com/KostasEreksonas/tp-link-tl-wr841n-security-analysis)). All devices were connected to the internet via ***Wireless Local Area Network (WLAN)***. The scheme of devices used during analysis is shown below.

![Network analysis scheme](/img/MITM_analysis_scheme.png)

You can find a [drawio scheme file for this here](/schematics/MITM_analysis_scheme.drawio)

## Communication with a control panel in a web browser

After logging in the `NETSurveillance WEB` control panel, the further information can be seen in ***plain text***:

All the further communication between the laptop and Besder IP camera is encrypted with SSL protocol and formatted in Base64 format (one can read more about this in [data security](#Data-security) section).

# Communication With Cloud Services

As I have mentioned before, during the security analysis all network devices were connected to a Wireless Local Area Network. Still, I managed to capture a fair bit of communication with various servers providing cloud services.
Throughout the whole security testing that I have done, the camera sent a bunch of UDP datagrams to various remote IP addresses. Those datagrams contained camera's serial number for some reason and I was not able to determine their purpose yet.
As a cloud services provider for the camera ***XMEye Cloud*** is used.
Firstly I have connected to the camera from web interface within virtual machine with `Windows 10` guest OS installed, then from a smartphone with ***ICSee*** app.

## Connecting from web interface

### Connection scheme between virtual machine and IP Camera

In this subsection I will present the schema for connecting to the Besder IP Camera from the `NETSurveillance WEB` network interface. For this purpose I have used `Virtualbox` virtualization software, where I have installed ***Windows 10*** as a Guest OS. The schematics of the connection between the Windows 10 virtual machine and Besder IP Camera is presented below:

![Connection_between_VM_and_IP_Camera_in_LAN](/img/Connection_between_VM_and_IP_Camera_in_LAN.png)

You can find a [drawio scheme file for this here](/schematics/Connection_between_VM_and_IP_Camera_in_LAN.drawio)

### Exchanged queries between virtual machine and IP Camera

Firstly the camera does a DNS resolution with an `Amazon AWS` server located in Germany, although the packages sent have data about some Chinese DNS servers with their IP addresses. I may assume that the DNS address is chosen based on camera's location. I might as well test it with a VPN someday.
After that camera sends a `HTTP POST` request to an `Amazon AWS` server with some data. Besides info about camera's geographical location and communication port, this request contains authentication code and a serial number of the Besder camera. Both of these are identical 16 charachter long hexadecimal strings. These can be used for a variety of nefarious purposes, for example DDoS'ing the specific device, connected to the cloud server or illegaly connecting to camera's video feed and viewing it and / or tampering with it.

***This and all of the following HTTP requests were formatted by me for better readability.***

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

Later the camera sends `HTTP POST` request to `logsvr.xmcsrv.net` and reports it's capabilities to the server for whatever reason:

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

Since there is no authentication required for sending the request to the update server checking for new firmware versions and downloading them, it makes me wonder if I could impersonate the IP camera and download the camera's firmware from there for some reverse engineering attempts...

## Connecting to Besder camera from ICSee app on a smartphone

### Connection scheme between smartphone and AWS cloud server and IP Camera

In this subsection I will present the schema of communication between the smartphone, Besder camera and Amazon AWS servers sitting between these devices.

![Communication between smartphone and IP Camera via cloud](/img/Communication_between_smartphone_and_IP_Camera_via_cloud.png)

You can find a [drawio scheme file for this here](/schematics/Communication_between_smartphone_and_IP_Camera_via_cloud.drawio)

### Exchanged queries between smartphone and AWS cloud server and IP Camera

Firstly, `HTTP POST` request is sent from a smartphone to an `Amazon AWS` server. It contains serial number of the camera I wanted to connect to, among other things. Request's purpose is to ask for a new connection with a different `Amazon AWS`server by calling `MSG_CLI_NEED_CON_REQ` query. The AWS server sends `HTTP OK` response to the smartphone. It contains IP address of a ***second*** Amazon AWS server and it's port that is used for communicating.

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

The `HTTP POST` request containing IP address and communication port of ***second*** AWS server is also sent to the IP camera.

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

All further communication between the smartphone and the Besder IP camera is carried out through the second Amazon AWS server and is encrypted. Communication between the smartphone and Amazon AWS server is encrypted by using `TLS v1.2` protocol and communication between the AWS server and Besder IP camera is encrypted using `SSL` protocol (although I am not sure about the protocol's version used on this end of communication and whether an older SSL or a more updated TLS protocol is used).

# Data security
***Updated 25/09/2021***

While analyzing domain information of an Amazon AWS server with an IP address of `3.126.12.232`, which Besder 6024PB-XMA501 IP camera connects to, I have found a couple of Base64 encoded SSL certificates, the formatting of which ***matches*** the formatting of the data sent via Besder IP camera's TCP port `34567`. So it is probably safe to assume that some form of SSL encryption is used to hide the data that is being sent.

Note: for analyzing domain information I was using utility called `whois`.

# Cloud server certificates

In this section I will present the information about the certificates on all of the cloud servers to whom the Besder 6024PB-XMA501 IP camera connects.

# Potential vulnerabilities

In this section I will present potential vulnerabilities within the tested Besder 6024PB-XMA501 camera. The exploits and their descriptions were found and taken from [cve.mitre.org](https://cve.mitre.org/) website and the found vulnerabilities were associated with ***Xongmai XMeye P2P*** cloud services.

1. ***[CVE-2017-16725](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16725)*** - A Stack-based Buffer Overflow issue was discovered in Xiongmai Technology IP Cameras and DVRs using the NetSurveillance Web interface. The stack-based buffer overflow vulnerability has been identified, which may allow an attacker to execute code remotely or crash the device. After rebooting, the device restores itself to a more vulnerable state in which Telnet is accessible.
2. ***[CVE-2017-7577](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7577)*** -	XiongMai uc-httpd has directory traversal allowing the reading of arbitrary files via a "GET ../" HTTP request.
3. ***[CVE-2018-10088](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10088)*** - Buffer overflow in XiongMai uc-httpd 1.0.0 has unspecified impact and attack vectors, a different vulnerability than CVE-2017-16725.
4. ***[CVE-2018-17915](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17915)*** - All versions of Hangzhou Xiongmai Technology Co., Ltd XMeye P2P Cloud Server do not encrypt all device communication. This includes the XMeye service and firmware update communication. This could allow an attacker to eavesdrop on video feeds, steal XMeye login credentials, or impersonate the update server with malicious update code.
5. ***[CVE-2018-17917](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17917)*** - All versions of Hangzhou Xiongmai Technology Co., Ltd XMeye P2P Cloud Server may allow an attacker to use MAC addresses to enumerate potential Cloud IDs. Using this ID, the attacker can discover and connect to valid devices using one of the supported apps.
6. ***[CVE-2018-17919](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17919)*** - All versions of Hangzhou Xiongmai Technology Co., Ltd XMeye P2P Cloud Server may allow an attacker to use an undocumented user account "default" with its default password to login to XMeye and access/view video streams.
7. ***[CVE-2019-11878](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11878)*** - An issue was discovered on XiongMai Besder IP20H1 V4.02.R12.00035520.12012.047500.00200 cameras. An attacker on the same local network as the camera can craft a message with a size field larger than 0x80000000 and send it to the camera, related to an integer overflow or use of a negative number. This then crashes the camera for about 120 seconds.

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

Below I will provide a list of the things that I plan to further accomplish with the security testing of Besder camera:
1. Analyze encryption certificate information on all the cloud servers to whom the Besder IP camera connects.
2. Impersonate the IP camera and download the camera's firmware from cloud service provider.
2. Use special tools to analyze the downloaded firmware and try to reverse engineer the code.
3. Find the function that is used for encrypting the sent data and reverse engineer the algorithm used for this function.
4. Inspect the code for potential security risks.
5. Verify if the found security risks have valid cyber attack vectors.
6. Provide a solution to mitigate the proven security risks if there are any.
