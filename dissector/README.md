# DVRIP_analysis
A Wireshark dissector for DVRIP/Sofia protocol found in Xiongmai based IP cameras

Table of Contents
=================
* [Test Device](#test-device)
* [DVRIP/Sofia Commnd Message](#dvripsofia-command-message)
* [Audio Header](#audio-header)
* [I-Frame Header](#i-frame-header)
* [P-Frame Header](#p-frame-header)
* [E-Frame Header](#e-frame-header)

# Test Device

This dissector is based on a DVRIP Wireshark Dissector for Port 37777 (Dahua IP camera), which can be found here: https://github.com/r4bit999/dvrip-analysis/tree/master

Tested on Besder 6024PB-XMA501 IP camera:

```
Model: XM530_50X50-WG_8M
Firmware version: V5.00.R02.00030747.10010.349f17
```

# DVRIP/Sofia Command Message

![DVRIP header](images/DVRIP_header.png)

![DVRIP header in Wireshark](images/DVRIP_header_wireshark.png)

# Audio Header

![DVRIP audio header](images/Audio_header.png)

![DVRIP audio header in Wireshark](images/Audio_header_wireshark.png)

# I-Frame Header

![DVRIP I-Frame header](images/Iframe_header.png)

![DVRIP I-Frame in Wireshark](images/Iframe_header_wireshark.png)

# P-Frame Header

![DVRIP P-Frame header](images/Pframe_header.png)

![DVRIP P-Frame in Wireshark](images/Pframe_header_wireshark.png)

# E-Frame Header

![DVRIP E-Frame header](images/Eframe_header.png)

![DVRIP E-Frame in Wireshark](images/Eframe_header_wireshark.png)