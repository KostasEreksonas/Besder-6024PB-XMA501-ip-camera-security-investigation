# DVRIP/Sofia response and command codes

Command and response codes are referenced from a [Digital Video Recorder Interface Protocol, which can be found by following this link to python-dvr repository](https://github.com/OpenIPC/python-dvr/blob/master/doc/%E9%9B%84%E8%BF%88%E6%95%B0%E5%AD%97%E8%A7%86%E9%A2%91%E5%BD%95%E5%83%8F%E6%9C%BA%E6%8E%A5%E5%8F%A3%E5%8D%8F%E8%AE%AE_V1.0.0.pdf)

Table of Contents
=================
* [Return Code Definitions](#return-code-definitions)
* [Command Code Definitions](#command-code-definitions)
    * [Login/Logout Keep-alive Agreement (C1 Message Number)](#loginlogout-keep-alive-agreement-c1-message-number)
    * [Get device information (C2 message number)](#get-device-information-c2-message-number)
    * [Request message numbers (C3~C11) to set/get configuration-related information](#request-message-numbers-c3c11-to-setget-configuration-related-information)
    * [Get capability level request (C12 message number)](#get-capability-level-request-c12-message-number)
    * [PTZ control (C13 message number)](#ptz-control-c13-message-number)
    * [Monitoring and control (C14 message number)](#monitoring-and-control-c14-message-number)
    * [Playback control (C15 message number)](#playback-control-c15-message-number)
    * [Voice intercommunications (C16 Message Number)](#voice-intercommunications-c16-message-number)
    * [Document Query (C17 Message Number)](#document-query-c17-message-number)
    * [System Management (C18 Message Number)](#system-management-c18-message-number)
    * [Disk Management (C19 Message Number)](#disk-management-c19-message-number)
    * [User Management C20 Message Number](#user-management-c20-message-number)
    * [Alarm Report (C21 Message Number)](#alarm-report-c21-message-number)
    * [System Upgrade (C22 Message Number)](#system-upgrade-c22-message-number)
    * [Automatic Device Discovery (C23 Message Number)](#automatic-device-discovery-c23-message-number)
    * [System Information Import/Export (C24 Message Number)](#system-information-importexport-c24-message-number)
    * [Keyboard Control (C25 Message Number)](#keyboard-control-c25-message-number)
    * [Snapshot Capture (C26 Message Number)](#snapshot-capture-c26-message-number)
    * [Serial Port Controls (C27 message number)](#serial-port-controls-c27-message-number)
    * [Time Synchronization](#time-synchronization)
    * [Screenshot Upload Message](#screenshot-upload-message)
    * [Version List](#version-list)
    * [FTP test](#ftp-test)

# Return Code Definitions

|Return Code|Definition|
|-----------|----------|
|100|OK|
|101|unknown error|
|102|Version not supported|
|103|Illegal request|
|104|This user is already logged in|
|105|This user is not logged in|
|106|Incorrect username and password|
|107|No permission|
|108|time out|
|109|The search failed and the corresponding file was not found.|
|110|Search successful, return all files|
|111|The search was successful and some files were returned.|
|112|This user already exists|
|113|This user does not exist|
|114|This user group already exists|
|115|This user group does not exist|
|116|No description provided|
|117|Message format error|
|118|PTZ protocol not set|
|119|No files found|
|120|configured to enable|
|121|MEDIA_CHN_NOTCONNECT digital channel is not connected|
|150|Success, the device needs to be restarted|
|202|User is not logged in|
|203|Password is incorrect|
|204|Illegal user|
|205|User is locked|
|206|User is in blacklist|
|207|Username has already logged in|
|208|Input is illegal|
|209|Index duplication, such as the user to be added already exists, etc.|
|210|Object does not exist, when used for query|
|211|Object does not exist|
|212|Account is in use|
|213|The subset exceeds the scope (such as the group's permissions exceed the permissions table, the user's permissions exceed the group's permissions, etc.)|
|214|Password is invalid|
|215|Password does not match|
|216|Keep account|
|502|The command is illegal|
|503|Intercom is on|
|504|Intercom is not enabled|
|511|Upgrade has started|
|512|Upgrade not started|
|513|Upgrade data error|
|514|Upgrade failed|
|515|Upgrade successful|
|521|Restore default failed|
|522|Need to restart the device|
|523|The default configuration is illegal|
|602|Need to restart the application|
|603|Need to restart the system|
|604|Error writing file|
|605|Feature not supported|
|606|Authentication failed|
|607|Configuration does not exist|
|608|Configuration parsing error|

# Command Code Definitions

## Login/Logout Keep-alive Agreement (C1 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|LOGIN_REQ|999/1000|Login request|[Login request body](payloads/1000_login_request.json)|
|LOGIN_RESP|1001|Login response|[Login response body](payloads/1001_login_response/)|
|LOGOUT_REQ|1002|Logout request|Not yet observed|
|LOGOUT_RESP|1003|Logout response|Not yet observed|
|FORCELOGOUT_REQ|1004|Force logout request|Not yet observed|
|FORCELOGOUT_RESP|1005|Force logout response|Not yet observed|
|KEEPALIVE_REQ|1006|Keep-alive request|[Keep alive request](payloads/1006_keep_alive_request.json)|
|KEEPALIVE_RESP|1007|Keep-alive response|[Keep alive response](payloads/1007_keep_alive_response.json)|

## Get device information (C2 message number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|SYSINFO_REQ|1020|System information request|[System info request body](payloads/1020_system_info_request/)|
|SYSINFO_RESP|1021|System information response|[System info response body](payloads/1021_system_info_response/)|

## Request message numbers (C3~C11) to set/get configuration-related information

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|CONFIG_SET|1040|Set configuration info requests|[Set config info requests](payloads/1040_set_config_info_requests/)|
|CONFIG_SET_RSP|1041|Set configuration info responses|[Set config info responses](payloads/1041_set_config_info_responses/)|
|CONFIG_GET|1042|Get configuration info requests|[Get config info requests](payloads/1042_get_config_info_requests/)|
|CONFIG_GET_RESP|1043|Get configuration info responses|[Get config info responses](payloads/1043_get_config_info_responses/)|
|DEFAULT_CONFIG_GET|1044|Get Default Configuration Request|Not yet observed|
|DEFAULT_CONFIG_GET_RSP|1045|Get the default configuration response|Not yet observed|
|CONFIG_CHANNELTILE_SET|1046|Set channel name|Not yet observed|
|CONFIG_CHANNELTILE_SET_RSP|1047|Set channel name response|Not yet observed|
|CHANNELTITLE_REQ|1048|Channel title request|[Channel title request](payloads/1048_channel_title_request.json)|
|CHANNELTITLE_RESP|1049|Channel title response|[Channel title response](payloads/1049_channel_title_response.json)|
|CONFIG_CHANNELTILE_DOT_SET|1050|Set channel name matrix request|[Set channel name matrix request](payloads/1050_CONFIG_CHANNELTILE_DOT_SET.json)|
|CONFIG_CHANNELTILE_DOT_SET_RSP|1051|Set channel name matrix response|[Set channel name matrix response](payloads/1051_CONFIG_CHANNELTILE_DOT_SET_RSP.json)|
|SYSTEM_DEBUG_REQ|1052|System debugging request|Not yet observed|
|SYSTEM_DEBUG_RESP|1053|System debugging response|Not yet observed|

## Get capability level request (C12 message number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|ABILITY_GET|1360|System ability request|[System ability request](payloads/1360_system_function_request/)|
|ABILITY_GET_RESP|1361|System ability response|[System ability response](payloads/1361_system_function_response/)|
|SMARTH264_REQ|1362|Smart H264 request|[Smart H264 request](payloads/1362_SMARTH264_REQ/)|
|SMARTH264_RESP|1363|Smart H264 response|[Smart H264 response](payloads/1363_SMARTH264_RESP/)|

## PTZ control (C13 message number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|PTZ_REQ|1400|PTZ control request|Not yet observed|
|PTZ_RESP|1401|PTZ control response|Not yet observed|

## Monitoring and control (C14 message number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|MONITOR_REQ|1410|OP monitor request|[OP monitor request](payloads/1410_op_monitor_request/)|
|MONITOR_RSP|1411|OP monitor response|[OP monitor response](payloads/1411_op_monitor_response/)|
|MONITOR_DATA|1412|OP monitor data|JSON data not observed|
|MONITOR_CLAIM|1413|OP monitor claim request|[OP monitor claim request](payloads/1413_op_monitor_claim_request/)|
|MONITOR_CLAIM_RSP|1414|OP monitor claim response|[OP monitor claim response](payloads/1414_op_monitor_claim_response.json)|

## Playback control (C15 message number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|PLAY_REQ|1420|Playback request|Not yet observed|
|PLAY_RSP|1421|Playback response|Not yet observed|
|PLAY_DATA|1422|Playback data|Not yet observed|
|PLAY_EOF|1423|Playback end|Not yet observed|
|PLAY_CLAIM|1424|Playback stream claim request|Not yet observed|
|PLAY_CLAIM_RSP|1425|Playback stream claim response|Not yet observed|
|DOWNLOAD_DATA|1426|Download playback data|Not yet observed|

## Voice intercommunications (C16 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|TALK_REQ|1430|Intercom request|Not yet observed|
|TALK_RESP|1431|Intercom response|Not yet observed|
|TALK_CU_PU_DATA|1432|CU to PU intercom data|Not yet observed|
|TALK_PU_CU_DATA|1433|PU to CU intercom data|Not yet observed|
|TALK_CLAIM|1434|Intercom stream claim request|Not yet observed|
|TALK_CLAIM_RSP|1435|Intercom stream claim response|Not yet observed|

## Document Query (C17 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|FILESEARCH_REQ|1440|OP file query request|[OP file query request](payloads/1440_OPFileQuery_request.json)|
|FILESEARCH_RSP|1441|OP file query response|[OP file query response](payloads/1441_OPFileQuery_response.json)|
|LOGSEARCH_REQ|1442|OP log query request|[OP log query request](payloads/1442_OPLogQuery_request/)|
|LOGSEARCH_RSP|1443|OP log query response|[OP log query response](payloads/1443_OPLogQuery_response/)|
|FILESEARCH_BYTIME_REQ|1444|Request to search for files by time|Not yet observed|
|FILESEARCH_BYTIME_RESP|1445|Response to search for files by time|Not yet observed|

## System Management (C18 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|SYSMANAGER_REQ|1450|System management request|[OP default config request](payloads/1450_OPDefaultConfig_request.json)|
|SYSMANAGER_RESP|1451|System management response|[OP default config response](payloads/1451_OPDefaultConfig_response.json)|
|OPTIMESETTING_REQ|1450|OP time setting request|[OP time setting request](payloads/1450_OPTimeSetting_request.json)|
|OPTIMESETTING_RESP|1451|OP time setting response|[OP time setting response](payloads/1451_OPTimeSetting_response.json)|
|TIMEQUERY_REQ|1452|OP time query request|[OP time query request](payloads/1452_op_time_query_request.json)|
|TIMEQUERY_RSP|1453|OP time query response|[OP time query response](payloads/1453_op_time_query_response.json)|

## Disk Management (C19 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|DSIKMANAGER_REQ|1460|OP storage manager request|[OP storage manager request](payloads/1460_OPStorageManager_request.json)|
|DSIKMANAGER_RSP|1461|OP storage manager response|[OP storage manager response](payloads/1461_OPStorageManager_response.json)|

## User Management (C20 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|FULLAUTHORITYLIST_GET|1470|OP authority list request|[OP authority list request](payloads/1470_OPAuthorityList_request.json)|
|FULLAUTHORITYLIST_GET_RESP|1471|OP authority list response|[OP authority list response](payloads/1471_OPAuthorityList_response.json)|
|USERS_GET|1472|OP users list request|[OP users list request](payloads/1472_OPUsersList_request.json)|
|USERS_GET_RESP|1473|OP users list response|[OP users list response](payloads/1473_OPUsersList_response.json)|
|GROUPS_GET|1474|OP groups list request|[OP groups list request](payloads/1474_OPGroupsList_request.json)|
|GROUPS_GET_RESP|1475|OP groups list response|[OP groups list response](payloads/1475_OPGroupsList_response.json)|
|ADDGROUP_REQ|1476|Add group request|Not yet observed|
|ADDGROUP_RSP|1477|Add group response|Not yet observed|
|MODIFYGROUP_REQ|1478|Modify group request|Not yet observed|
|MODIFYGROUP_RSP|1479|Modify group response|Not yet observed|
|DELETEGROUP_REQ|1480|Delete group request|Not yet observed|
|DELETEGROUP_RSP|1481|Delete group response|Not yet observed|
|ADDUSER_REQ|1482|OP user info request|[OP user info request](payloads/1482_OPUserInfo_request.json)|
|ADDUSER_RSP|1483|OP user info response|[OP user info respnose](payloads/1483_OPUserInfo_response.json)|
|MODIFYUSER_REQ|1484|Modify user request|Not yet observed|
|MODIFYUSER_RSP|1485|Modify user response|Not yet observed|
|OPDELUSER_REQ|1486|OP delete user request|[OP delete user request](payloads/1486_OPUserDelete_request.json)|
|OPDELUSER_RESP|1487|OP delete user response|[OP delete user response](payloads/1487_OPUserDelete_response.json)|
|MODIFYPASSWORD_REQ|1488|Modify password request|Not yet observed|
|MODIFYPASSWORD_RSP|1489|Modify password response|Not yet observed|

## Alarm Report (C21 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|GUARD_REQ|1500|Guard request|[Guard request](payloads/1500_guard_request.json)|
|GUARD_RSP|1501|Guard response|[Guard response](payloads/1501_guard_response.json)|
|UNGUARD_REQ|1502|Unguard request|[Unguard request](payloads/1502_unguard_request.json)|
|UNGUARD_REQ|1503|Unguard response|Not yet observed|
|ALARM_REQ|1504|Alarm request (the only message proactively reported by the PU to the CU)|Not yet observed|
|ALARM_RSP|1505|Alarm response|Not yet observed|
|NET_ALARM_REQ|1506|Network alert request|Not yet observed|
|NET_ALARM_RSP|1507|Network alert response|Not yet observed|
|ALARMCENTER_MSG_REQ|1508|Alarm reporting request|Not yet observed|

## System Upgrade (C22 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|UPGRADE_REQ|1520|Upgrade request|Not yet observed|
|UPGRADE_RSP|1521|Upgrade response|Not yet observed|
|UPGRADE_DATA|1522|Upgrade data request|Not yet observed|
|UPGRADE_DATA_RSP|1523|Upgrade data response|Not yet observed|
|UPGRADE_PROGRESS|1524|Upgrade progress|Not yet observed|
|UPGRADE_INFO_REQ|1525|System update info request|[System update info request](payloads/1525_op_system_upgrade_request.json)|
|UPGRADE_INFO_RSP|1526|System upgrade info response|[System update info response](payloads/1526_op_system_upgrade_response.json)|

## Automatic Device Discovery (C23 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|IPSEARCH_REQ|1530|IP auto search request|Not yet observed|
|IPSEARCH_RSP|1531|IP auto search response|Not yet observed|
|IP_SET_REQ|1532|IP set request|Not yet observed|
|IP_SET_RSP|1533|IP set response|Not yet observed|

## System Information Import/Export (C24 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|CONFIG_IMPORT_REQ|1540|Configure import request|Not yet observed|
|CONFIG_IMPORT_RSP|1541|Configure import response|Not yet observed|
|CONFIG_EXPORT_REQ|1542|Configure export request|[Configure export request](payloads/1542_empty_request.json)|
|CONFIG_EXPORT_RSP|1543|Configure export request|[Configure export request](payloads/1543_empty_response.json)|
|LOG_EXPORT_REQ|1544|Log export request|Not yet observed|
|LOG_EXPORT_RSP|1545|Log export response|Not yet observed|

## Keyboard Control (C25 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|NET_KEYBOARD_REQ|1550|Keyboard control request|Not yet observed|
|NET_KEYBOARD_RSP|1551|Keyboard control response|Not yet observed|

## Snapshot Capture (C26 Message Number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|NET_SNAP_REQ|1560|OP snapshot request|[OP snapshot request](payloads/1560_op_snapshot_request.json)|
|NET_SNAP_RSP|1561|OP snapshot response|Saved as jpeg image|
|SET_IFRAME_REQ|1562|Set iframe request|Not yet observed|
|SET_IFRAME_RSP|1563|Set iframe response|Not yet observed|

## Serial Port Controls (C27 message number)

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|RS232_READ_REQ|1570|RS232 read request|Not yet observed|
|RS232_READ_RSP|1571|RS232 read response|Not yet observed|
|RS232_WRITE_REQ|1572|RS232 write request|Not yet observed|
|RS232_WRITE_RSP|1573|RS232 write response|Not yet observed|
|RS485_READ_REQ|1574|RS485 read request|Not yet observed|
|RS485_READ_RSP|1575|RS485 read response|Not yet observed|
|RS485_WRITE_REQ|1576|RS485 write request|Not yet observed|
|RS485_WRITE_RSP|1577|RS485 write response|Not yet observed|
|TRANSPARENT_COMM_REQ|1578|Transparent serial port communication request|Not yet observed|
|TRANSPARENT_COMM_RSP|1579|Transparent serial port communication response|Not yet observed|
|RS485_TRANSPARENT_DATA_REQ|1580|Transparent data request from RS485 serial port|Not yet observed|
|RS485_TRANSPARENT_DATA_RSP|1581|Transparent data response from RS485 serial port|Not yet observed|
|RS232_TRANSPARENT_DATA_REQ|1582|Transparent data request from RS232 serial port|Not yet observed|
|RS232_TRANSPARENT_DATA_RSP|1583|Transparent data response from RS232 serial port|Not yet observed|

## Time Synchronization

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|OPTimeSettingNoRTC_REQ|1590|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1590_op_time_setting_no_rtc_request.json)|
|OPTimeSettingNoRTC_RESP|1591|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1591_op_time_setting_no_rtc_response.json)|

## Screenshot Upload Message

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|PHOTO_GET_REQ|1600|Screenshot upload request|Not yet observed|
|PHOTO_GET_RSP|1601|Screenshot upload response|Not yet observed|

## Version List

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|OPVERSIONLIST_REQ|2000|OP version list request|[OP version list request](payloads/2000_OPVersionList.request.json)|
|OPVERSIONLIST_RESP|2001|OP version list response|[OP version list response](payloads/2001_OPVersionList.response.json)|

## FTP Test

|Name|Code|Description|Payload|
|----|----|-----------|-------|
|OPFTPTEST_REQ|2008|OP FTP test request|[OP FTP test request](payloads/2008_OPFTPTest_request.json)|
|OPFTPTEST_RESP|2009|OP FTP test response|[OP FTP test response](payloads/2009_OPFTPTest_response.json)|