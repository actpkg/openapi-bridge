GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$.std.name" "openapi_bridge"
jsonpath "$.std.version" isString
