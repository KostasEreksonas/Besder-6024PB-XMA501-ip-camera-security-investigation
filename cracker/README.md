# DVRIP_hash_cracker
Python script for cracking DVRIP/Sofia password hash. Existing vulnerabilities are being exploited for hash retrieval. Only dictionary attack is supported as of now.

## Usage
`uv run xm_hash_cracker.py`

## Test setup
This script was tested on Besder 6024PB-XMA51 IP camera:

```
Model: XM530_50X50-WG_8M
Firmware version: V5.00.R02.00030747.10010.349f17
```

## Exploited vulnerabilities
* CVE-2024-3765 - authentication bypass vulnerability in proprietary Sofia protocol found on Xiongmai based IP cameras. Sending a crafted payload with the command code f103 (little-endian hex for 1009) allows unauthorized access. [A writeup by netsecfish is available on Github](https://github.com/netsecfish/xiongmai_incorrect_access_control)
* CVE-2025-65856 - authentication bypass vulnerability in the ONVIF implementation found on Xiongmai XM530 chipset based IP cameras. This vulnerability allows unauthenticated access on 31 critical endpoints, including unauthorized video stream access. [Vulnerability writeup on NIST database](https://nvd.nist.gov/vuln/detail/CVE-2025-65856)