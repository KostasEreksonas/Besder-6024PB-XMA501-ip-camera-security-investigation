function currentThreadId(Thread) {
    return Thread.currentThread().getId().toString();
}

Java.perform(function () {
    const PglCryptUtils = Java.use("com.bytedance.sdk.component.pglcrypt.PglCryptUtils");

    try {
        const cypher4Decrypt = PglCryptUtils.cypher4Decrypt.overload(
            "java.lang.String"
        );

        cypher4Decrypt.implementation = function(str) {
            console.log("cypher4Decrypt Input string: " + str);

            const result = cypher4Decrypt.call(this, str);

            console.log("cypher4Decrypt result: " + result);

            return result;
        };
    } catch (e) {
        console.log("Error with cypher4Decrypt: " + e.message);
    }

    try {
        const cypher4Encrypt = PglCryptUtils.cypher4Encrypt.overload(
            "org.json.JSONObject"
        );

        cypher4Encrypt.implementation = function(JsonObject) {
            try {
                console.log("cypher4Encrypt JSON input: " + JsonObject.toString());
            } catch (e) {
                console.log("cypher4Encrypt Failed to capture JSON input object: " + e.message);
            }

            const result = cypher4Encrypt.call(this, JsonObject);

            console.log("cypher4Encrypt result: " + result);

            return result;
        };
    } catch (e) {
        console.log("Error with cypher4Encrypt: " + e.message);
    }
});