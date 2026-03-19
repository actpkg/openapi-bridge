GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$['std:name']" == "openapi-bridge"
jsonpath "$['std:version']" isString
