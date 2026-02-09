# CVE-2025-65856 - ONVIF authentication bypass on XM 530 IP cameras
Proof-of-concept code (Bash and Python) for CVE-2025-65856 where ONVIF implementation in in Xiongmai XM530 IP cameras allows for unauthenticated  access to sensitive device information and live video streams:

## Proof-of-concepts
* [Curl proof-of-concept](Curl)
* [Python proof-of-concept](Python)

## Test setup
```
Model: XM530_50X50-WG_8M
Firmware version: V5.00.R02.00030747.10010.349f17
```