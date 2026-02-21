# DVRIP/Sofia response and command codes

# Response codes

|Return Code|Definition|
|-----------|----------|
|100|Success|
|103|Illegal Request|
|136|Not Support|
|203|Incorrect Password|
|205|Incorrect Username|

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
|SYSTEMFUNCTION_REQ|1360|System function request|[System function request](payloads/1360_system_function_request/)|
|SYSTEMFUNCTION_RESP|1361|System function response|[System function response](payloads/1361_system_function_response/)|
|OPMONITOR_REQ|1410|OP monitor request|[OP monitor request](payloads/1410_op_monitor_request/)|
|OPMONITOR_RESP|1411|OP monitor response|[OP monitor response](payloads/1411_op_monitor_response/)|
|OPMONITOR_DATA|1412|OP monitor data|-|
|OPMONITOR_CLAIM_REQ|1413|OP monitor claim request|[OP monitor claim request](payloads/1413_op_monitor_claim_request/)|
|OPMONITOR_CLAIM_RESP|1414|OP monitor claim response|[OP monitor claim response](payloads/1414_op_monitor_claim_response.json)|
|OPTIMEQUERY_REQ|1452|OP time query request|[OP time query request](payloads/1452_op_time_query_request.json)|
|OPTIMEQUERY_RESP|1453|OP time query response|[OP time query response](payloads/1453_op_time_query_response.json)|
|EMPTY_REQ|1500|Empty request|[Empty request](payloads/1500_empty_request.json)|
|EMPTY_RESP|1501|Empty response|[Empty response](payloads/1501_empty_response.json)|
|EMPTY_REQ|1502|Empty request|[Empty request](payloads/1502_empty_request.json)|
|OPTimeSettingNoRTC_REQ|1590|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1590_op_time_setting_no_rtc_request.json)|
|OPTimeSettingNoRTC_RESP|1591|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1591_op_time_setting_no_rtc_response.json)|