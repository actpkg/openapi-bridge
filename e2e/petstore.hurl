# Swagger Petstore 3.0 — public OpenAPI spec

# List tools from petstore spec
POST {{baseurl}}/tools
{"metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.tools" count >= 10
jsonpath "$.tools[*].name" contains "find_pets_by_status"
jsonpath "$.tools[*].name" contains "get_inventory"
jsonpath "$.tools[*].name" contains "add_pet"
jsonpath "$.tools[*].name" contains "get_pet_by_id"
jsonpath "$.tools[*].name" contains "login_user"
jsonpath "$.tools[*].name" contains "place_order"
jsonpath "$.tools[*].name" contains "delete_order"

# --- GET with query parameter ---

# Find pets by status
POST {{baseurl}}/tools/find_pets_by_status
{"arguments": {"status": "sold"}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content" count >= 1
jsonpath "$.content[0].mime_type" == "application/json"

# Login user (multiple query params)
POST {{baseurl}}/tools/login_user
{"arguments": {"username": "test", "password": "test"}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "Logged in"

# --- POST with request body ---

# Add a pet
POST {{baseurl}}/tools/add_pet
{"arguments": {"id": 99887, "name": "TestDog", "status": "available", "photoUrls": ["http://example.com/dog.jpg"]}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "TestDog"
jsonpath "$.content[0].data" contains "99887"

# --- PUT with request body ---

# Update the pet
POST {{baseurl}}/tools/update_pet
{"arguments": {"id": 99887, "name": "TestDogUpdated", "status": "sold", "photoUrls": ["http://example.com/dog2.jpg"]}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "TestDogUpdated"
jsonpath "$.content[0].data" contains "sold"

# --- GET with path parameter ---

# Verify the update
POST {{baseurl}}/tools/get_pet_by_id
{"arguments": {"petId": 99887}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "TestDogUpdated"

# --- DELETE with path parameter ---

# Delete the pet
POST {{baseurl}}/tools/delete_pet
{"arguments": {"petId": 99887}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200

# --- Store: POST + GET + DELETE cycle ---

# Place an order
POST {{baseurl}}/tools/place_order
{"arguments": {"id": 77788, "petId": 1, "quantity": 1, "status": "placed", "complete": true}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "77788"
jsonpath "$.content[0].data" contains "placed"

# Get the order
POST {{baseurl}}/tools/get_order_by_id
{"arguments": {"orderId": 77788}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" contains "77788"

# Delete the order
POST {{baseurl}}/tools/delete_order
{"arguments": {"orderId": 77788}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 200

# --- Error cases ---

# Non-existent tool returns 404
POST {{baseurl}}/tools/doesNotExist
{"arguments": {}, "metadata": {"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"}}
HTTP 404
[Asserts]
jsonpath "$.error.kind" == "std:not-found"

# Missing metadata returns error
POST {{baseurl}}/tools/find_pets_by_status
{"arguments": {"status": "sold"}}
HTTP 422
[Asserts]
jsonpath "$.error.kind" == "std:invalid-args"
