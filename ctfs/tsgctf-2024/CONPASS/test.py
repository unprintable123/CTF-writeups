import requests
import json
import time

#rewite the host to the server address
host = "http://localhost:8000/"

data = {}

response = requests.get(host+"sat0")
data["sat0"] = response.json()

response = requests.get(host+"sat1")
data["sat1"] = response.json()

response = requests.get(host+"sat2")
data["sat2"] = response.json()

response = requests.get(host+"sat3")
data["sat3"] = response.json()

json_data = json.dumps(data)
response = requests.post(
    host+"auth",
    data=json_data,
    headers={"Content-Type": "application/json"}
    )
print(response.json())
#{'error': 'you are not with the flag'}