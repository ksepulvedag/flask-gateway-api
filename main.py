from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

# JWT imports
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
cors = CORS(app)

# JWT config
app.config["JWT_SECRET_KEY"]="UbehNfatFhNKfBhwmoohYlodDmgzdsRF" # Secret Key, change it
jwt = JWTManager(app)

# Load configuration file
def load_config_file():
    with open('config.json') as file:
        data = json.load(file)
    return data

#################### Validation funtions ####################
@app.before_request
def before_request_callback():
    endpoint=clean_url(request.path)
    excluded_routes=["/login"]
    if excluded_routes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        user = get_jwt_identity()
        if user["role"]is not None:
            has_permission=permission_validate(endpoint,request.method,user["role"]["_id"])
            if not has_permission:
                return jsonify({"msg": "Permission denied"}), 401
        else:
            return jsonify({"msg": "Permission denied"}), 401

def clean_url(url):
    fragments = url.split("/")
    for fragment in fragments:
        if re.search('\\d', fragment):
            url = url.replace(fragment, "?")
    return url

def permission_validate(endpoint,method,role_id):
    url=config_data["url-backend-security"]+"/permissions-roles/validate-permission/role/"+str(role_id)
    has_permission=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body =  {
                "url":endpoint,
                "method": method
            }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            has_permission=True
    except:
        pass
    return has_permission

#################### ROOT URL ####################
@app.route("/", methods = ["GET"])
def test():
    json = {}
    json["message"] = "Server running..."
    return jsonify(json)

#################### Login URL ####################
@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=config_data["url-backend-security"]+'/user/validate'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"message": "Bad username or password"}), 401

#################### BEGIN GATEWAY URLS ####################

########## USER URLS ##########
@app.route("/user",methods=['GET'])
def get_users():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/user'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/user",methods=['POST'])
def create_user():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/user'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/user/<string:id>",methods=['GET'])
def get_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/user/'+id
    response = requests.get(url, headers=headers)
    if response.content == b'':
        return jsonify({"msg":"User not found"})
    else:
        json = response.json()
        return jsonify(json)

@app.route("/user/<string:id>",methods=['PUT'])
def update_user(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/user/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/user/<string:id>",methods=['DELETE'])
def delete_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/user/' + id
    response = requests.delete(url, headers=headers)
    return jsonify([{"msg":"User has been succesfully deleted"},{"status_code":response.status_code}])



#################### END GATEWAY URLS ####################


# Main function
if __name__ == '__main__':
    config_data = load_config_file()
    print("Server running: "+"http://"+config_data["url-backend"]+":" +
    str(config_data["port"]))
    serve(app,host=config_data["url-backend"],port=config_data["port"])