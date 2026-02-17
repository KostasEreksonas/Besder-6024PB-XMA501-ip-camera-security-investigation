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