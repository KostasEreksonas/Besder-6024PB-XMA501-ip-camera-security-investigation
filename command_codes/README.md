# DVRIP/Sofia response and command codes

# Response codes

|Return Code|Definition|
|-----------|----------|
|100|Success|
|102|Version Not Supported|
|103|Illegal Request|
|119|No query to file|
|136|Not Support|
|203|Incorrect Password|
|205|Incorrect Username|
|514|Update Failed|
|603|System Restart Required|
|607|Configuration Does Not Exist|

# Command codes

|Command Name|Command Code|Description|Payload|
|------------|------------|-----------|-------|
|LOGIN_REQ|1000|Login request|[Login request body](payloads/1000_login_request.json)|
|LOGIN_RESP|1001|Login response|[Login response body](payloads/1001_login_response/)|
|KEEPALIVE_REQ|1006|Keep-alive request|[Keep alive request](payloads/1006_keep_alive_request.json)|
|KEEPALIVE_RESP|1007|Keep-alive response|[Keep alive response](payloads/1007_keep_alive_response.json)|
|SYSTEM_INFO_REQ|1020|System info request|[System info request body](payloads/1020_system_info_request/)|
|SYSTEM_INFO_RESP|1021|System info response|[System info response body](payloads/1021_system_info_response/)|
|SET_CONFIG_REQ|1040|Set configuration info requests|[Set config info requests](payloads/1040_set_config_info_requests/)|
|SET_CONFIG_RESP|1041|Set configuration info responses|[Set config info responses](payloads/1041_set_config_info_responses/)|
|GET_CONFIG_REQ|1042|Get configuration info requests|[Get config info requests](payloads/1042_get_config_info_requests/)|
|GET_CONFIG_RESP|1043|Get configuration info responses|[Get config info responses](payloads/1043_get_config_info_responses/)|
|CHANNELTITLE_REQ|1048|Channel title request|[Channel title request](payloads/1048_channel_title_request.json)|
|CHANNELTITLE_RESP|1049|Channel title response|[Channel title response](payloads/1049_channel_title_response.json)|
|LOGOUT_REQ|1050|Logout request|[Logout request](payloads/1050_logout_request.json)|
|LOGOUT_RESP|1051|Logout response|[Logout response](payloads/1051_logout_response.json)|
|SYSTEMFUNCTION_REQ|1360|System function request|[System function request](payloads/1360_system_function_request/)|
|SYSTEMFUNCTION_RESP|1361|System function response|[System function response](payloads/1361_system_function_response/)|
|SMARTH264_REQ|1362|Smart H264 request|[Smart H264 request](payloads/1362/)|
|SMARTH264_RESP|1363|Smart H264 response|[Smart H264 response](payloads/1363/)|
|OPMONITOR_REQ|1410|OP monitor request|[OP monitor request](payloads/1410_op_monitor_request/)|
|OPMONITOR_RESP|1411|OP monitor response|[OP monitor response](payloads/1411_op_monitor_response/)|
|OPMONITOR_DATA|1412|OP monitor data|-|
|OPMONITOR_CLAIM_REQ|1413|OP monitor claim request|[OP monitor claim request](payloads/1413_op_monitor_claim_request/)|
|OPMONITOR_CLAIM_RESP|1414|OP monitor claim response|[OP monitor claim response](payloads/1414_op_monitor_claim_response.json)|
|OPFILEQUERY_REQ|1440|OP file query request|[OP file query request](payloads/1440_OPFileQuery_request.json)|
|OPFILEQUERY_RESP|1441|OP file query response|[OP file query response](payloads/1441_OPFileQuery_response.json)|
|OPLOGQUERY_REQ|1442|OP log query request|[OP log query request](payloads/1442_OPLogQuery_request/)|
|OPLOGQUERY_RESP|1443|OP log query response|[OP log query response](payloads/1443_OPLogQuery_response/)|
|OPDEFAULTCONFIG_REQ|1450|OP default config request|[OP default config request](payloads/1450_OPDefaultConfig_request.json)|
|OPDEFAULTCONFIG_RESP|1451|OP default config response|[OP default config response](payloads/1451_OPDefaultConfig_response.json)|
|OPTIMESETTING_REQ|1450|OP time setting request|[OP time setting request](payloads/1450_OPTimeSetting_request.json)|
|OPTIMESETTING_RESP|1451|OP time setting response|[OP time setting response](payloads/1451_OPTimeSetting_response.json)|
|OPTIMEQUERY_REQ|1452|OP time query request|[OP time query request](payloads/1452_op_time_query_request.json)|
|OPTIMEQUERY_RESP|1453|OP time query response|[OP time query response](payloads/1453_op_time_query_response.json)|
|OPSTORAGEMANAGER_REQ|1460|OP storage manager request|[OP storage manager request](payloads/1460_OPStorageManager_request.json)|
|OPSTORAGEMANAGER_RESP|1461|OP storage manager response|[OP storage manager response](payloads/1461_OPStorageManager_response.json)|
|OPAUTHORITYLIST_REQ|1470|OP authority list request|[OP authority list request](payloads/1470_OPAuthorityList_request.json)|
|OPAUTHORITYLIST_REQ|1471|OP authority list response|[OP authority list response](payloads/1471_OPAuthorityList_response.json)|
|OPUSERS_REQ|1472|OP users list request|[OP users list request](payloads/1472_OPUsersList_request.json)|
|OPUSERS_RESP|1473|OP users list response|[OP users list response](payloads/1473_OPUsersList_response.json)|
|OPGROUPS_REQ|1474|OP groups list request|[OP groups list request](payloads/1474_OPGroupsList_request.json)|
|OPGROUPS_RESP|1475|OP groups list response|[OP groups list response](payloads/1475_OPGroupsList_response.json)|
|OPUSER_REQ|1482|OP user info request|[OP user info request](payloads/1482_OPUserInfo_request.json)|
|OPUSER_REQ|1483|OP user info response|[OP user info respnose](payloads/1483_OPUserInfo_response.json)|
|OPDELUSER_REQ|1486|OP delete user request|[OP delete user request](payloads/1486_OPUserDelete_request.json)|
|OPDELUSER_RESP|1487|OP delete user response|[OP delete user response](payloads/1487_OPUserDelete_response.json)|
|EMPTY_REQ|1500|Empty request|[Empty request](payloads/1500_empty_request.json)|
|EMPTY_RESP|1501|Empty response|[Empty response](payloads/1501_empty_response.json)|
|LOGOUT_REQ|1502|Logout request|[Logout request](payloads/1502_logout_request.json)|
|OPSYSTEMUPGRADE_REQ|1525|System update request|[System update request](payloads/1525_op_system_upgrade_request.json)|
|OPSYSTEMUPGRADE_RESP|1526|System upgrade response|[System update response](payloads/1526_op_system_upgrade_response.json)|
|EMPTY_REQ|1542|Empty request|[Empty request](payloads/1542_empty_request.json)|
|EMPTY_RESP|1543|Empty response|[Empty response](payloads/1543_empty_response.json)|
|OPSNAP_REQ|1560|OP snapshot request|[OP snapshot request](payloads/1560_op_snapshot_request.json)|
|OPSNAP_RESP|1561|OP snapshot response|Saved as jpeg image|
|OPTimeSettingNoRTC_REQ|1590|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1590_op_time_setting_no_rtc_request.json)|
|OPTimeSettingNoRTC_RESP|1591|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1591_op_time_setting_no_rtc_response.json)|
|OPVERSIONLIST_REQ|2000|OP version list request|[OP version list request](payloads/2000_OPVersionList.request.json)|
|OPVERSIONLIST_RESP|2001|OP version list response|[OP version list response](payloads/2001_OPVersionList.response.json)|
|OPFTPTEST_REQ|2008|OP FTP test request|[OP FTP test request](payloads/2008_OPFTPTest_request.json)|
|OPFTPTEST_RESP|2009|OP FTP test response|[OP FTP test response](payloads/2009_OPFTPTest_response.json)|