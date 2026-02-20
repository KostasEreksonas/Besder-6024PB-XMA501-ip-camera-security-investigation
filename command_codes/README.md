# DVRIP/Sofia response and command codes

# Response codes

|Return Code|Definition|
|-----------|----------|
|100|Success|
|136|Not Support|
|203|Incorrect password|
|205|Incorrect username|

# Command codes

|Command Name|Command Code|Description|Payload|
|------------|------------|-----------|-------|
|LOGIN_REQ|1000|Login request|[Login request body](payloads/1000_login_request.json)|
|LOGIN_RESP|1001|Login response|[Login response body](payloads/1001_login_response/)|
|KEEPALIVE_REQ|1006|Keep-alive request|[Keep alive request](payloads/1006_keep_alive_request.json)|
|KEEPALIVE_RESP|1007|Keep-alive response|[Keep alive response](payloads/1007_keep_alive_response.json)|
|SYSTEM_INFO_REQ|1020|System info request|[System info request body](payloads/1020_system_info_request.json)|
|SYSTEM_INFO_RESP|1021|System info response|[System info response body](payloads/1021_system_info_response.json)|
|WORKSTATE_REQ|1020|Workstate request|[Workstate request](payloads/1020_workstate_request.json)|
|WORKSTATE_RESP|1021|Workstate response|[Workstate response](payloads/1021_workstate_response.json)|
|CHANNELTITLE_REQ|1048|Channel title request|[Channel title request]()|
|CHANNELTITLE_RESP|1049|Channel title response|[Channel title response]()|
|EMPTY_REQ|1500|Empty request|[Empty request](payloads/1500_empty_request.json)|
|EMPTY_RESP|1501|Empty response|[Empty response](payloads/1501_empty_response.json)|
|OPTimeSettingNoRTC_REQ|1590|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1590_op_time_setting_no_rtc_request.json)|
|OPTimeSettingNoRTC_RESP|1591|OP time setting (no RTC)|[OP time setting w/o RTC](payloads/1591_op_time_setting_no_rtc_response.json)|