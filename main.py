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

######################## BEGIN GATEWAY URLS ########################

#################### SECURITY URLS ####################

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
    if response.content == b'':
        return jsonify({"msg":"User not found"})
    else:
        json = response.json()
        return jsonify(json)

@app.route("/user/<string:id>",methods=['DELETE'])
def delete_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/user/' + id
    requests.delete(url, headers=headers)
    return jsonify({"msg":"User has been succesfully deleted"})

########## ROLE URLS ##########
@app.route("/role",methods=['GET'])
def get_roles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/role'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/role",methods=['POST'])
def create_role():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/role'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/role/<string:id>",methods=['GET'])
def get_role(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/role/'+id
    response = requests.get(url, headers=headers)
    if response.content == b'':
        return jsonify({"msg":"Role not found"})
    else:
        json = response.json()
        return jsonify(json)

@app.route("/role/<string:id>",methods=['PUT'])
def update_role(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/role/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.content == b'':
        return jsonify({"msg":"Role not found"})
    else:
        json = response.json()
        return jsonify(json)

@app.route("/role/<string:id>",methods=['DELETE'])
def delete_role(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/role/' + id
    requests.delete(url, headers=headers)
    return jsonify({"msg":"Role has been succesfully deleted"})

########## PERMISSION URLS ##########
@app.route("/permission",methods=['GET'])
def get_permissions():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permission'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permission",methods=['POST'])
def create_permission():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permission'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permission/<string:id>",methods=['PUT'])
def update_permission(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permission/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.content == b'':
        return jsonify({"msg":"Permission not found"})
    else:
        json = response.json()
        return jsonify(json)

@app.route("/permission/<string:id>",methods=['DELETE'])
def delete_permission(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permission/' + id
    requests.delete(url, headers=headers)
    return jsonify({"msg":"Permission has been succesfully deleted"})

########## PERMISSIONS-ROLES URLS ##########
@app.route("/permissions-roles",methods=['GET'])
def get_permissions_roles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permissions-roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permissions-roles/role/<string:role_id>/permission/<string:permission_id>",methods=['POST'])
def create_permissions_roles(role_id, permission_id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permissions-roles/role/'+role_id+'/permission/'+permission_id
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permissions-roles/<string:id>",methods=['GET'])
def get_permission_role(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permissions-roles/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permissions-roles/<string:id>",methods=['PUT'])
def update_permission_role(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permissions-roles/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.content == b'':
        return jsonify({"msg":"permission-role not found"})
    else:
        json = response.json()
        return jsonify(json)

@app.route("/permissions-roles/<string:id>",methods=['DELETE'])
def delete_permission_role(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permissions-roles/' + id
    requests.delete(url, headers=headers)
    return jsonify({"msg":"Permission has been succesfully deleted"})

@app.route("/permissions-roles/validate-permission/role/<string:id>",methods=['GET'])
def validate_permission_role(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/permissions-roles/validate-permission/role/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


#################### ADMINISTRATION URLS ####################

########## CANDIDATES URLS ##########
# List all candidates
@app.route("/candidate",methods=['GET'])
def get_candidate():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/candidate'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# Create a new candidate
@app.route("/candidate",methods=['POST'])
def create_candidate():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/candidate'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

# list a candidate by id
@app.route("/candidate/<string:id>",methods=['GET'])
def get_candidate_by_id(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/candidate/'+id
    response = requests.get(url, headers=headers)
    if response.content == b'':
        return jsonify({"msg":"Candidate not found"})
    else:
        json = response.json()
        return jsonify(json)

# Update a candidate's info by id
@app.route("/candidate/<string:id>",methods=['PUT'])
def update_candidate(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/candidate/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 500:
        return jsonify([{"msg":"Candidate not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Delete a candidate by id
@app.route("/candidate/<string:id>",methods=['DELETE'])
def delete_candidate(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-security"] + '/candidate/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    if json['deleted_count'] == 0:
        return jsonify({"msg":"Candidate not found"})
    elif json['deleted_count'] == 1:
        return jsonify({"msg":"Candidate has been succesfully deleted"})

# Assign a candidate to a political party
@app.route("/candidate/<string:candidate_id>/party/<string:party_id>",methods=['PUT'])
def assign_candidate_party(candidate_id,party_id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/candidate/'+candidate_id+'/party/'+party_id
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 500:
        return jsonify([{"msg":"Candidate not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

########## TABLE URLS ##########
# List all tables
@app.route("/table",methods=['GET'])
def get_table():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/table'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# Create a new table
@app.route("/table",methods=['POST'])
def create_table():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/table'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

# list a table by id
@app.route("/table/<string:id>",methods=['GET'])
def get_table_by_id(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/table/'+id
    response = requests.get(url, headers=headers)
    if response.status_code == 500:
        return jsonify([{"msg":"Table not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Update a table's info by id
@app.route("/table/<string:id>",methods=['PUT'])
def update_table(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/table/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 500:
        return jsonify([{"msg":"Table not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Delete a table by id
@app.route("/table/<string:id>",methods=['DELETE'])
def delete_table(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/table/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    if json['deleted_count'] == 0:
        return jsonify({"msg":"Table not found"})
    elif json['deleted_count'] == 1:
        return jsonify({"msg":"Table has been succesfully deleted"})

############ Political Party ############
# List all political parties
@app.route("/party",methods=['GET'])
def get_parties():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/party'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# Create a new party
@app.route("/party",methods=['POST'])
def create_party():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/party'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

# list a party by id
@app.route("/party/<string:id>",methods=['GET'])
def get_party_by_id(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/party/'+id
    response = requests.get(url, headers=headers)
    if response.status_code == 500:
        return jsonify([{"msg":"Party not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Update a party's info by id
@app.route("/party/<string:id>",methods=['PUT'])
def update_party(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/party/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 500:
        return jsonify([{"msg":"Party not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Delete a party by id
@app.route("/party/<string:id>",methods=['DELETE'])
def delete_party(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/party/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    if json['deleted_count'] == 0:
        return jsonify({"msg":"Party not found"})
    elif json['deleted_count'] == 1:
        return jsonify({"msg":"Party has been succesfully deleted"})

############ Results (Reports) ############
# List all results
@app.route("/result",methods=['GET'])
def get_results():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# Create a new result
@app.route("/result/candidate/<string:candidate_id>/table/<string:table_id>",methods=['POST'])
def create_result(candidate_id, table_id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/candidate/'+candidate_id+'/table/'+table_id
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

# list a result by id
@app.route("/result/<string:id>",methods=['GET'])
def get_result_by_id(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/'+id
    response = requests.get(url, headers=headers)
    if response.status_code == 500:
        return jsonify([{"msg":"Result not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Update a result's info by id
@app.route("/result/<string:id>",methods=['PUT'])
def update_result(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/'+id
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 500:
        return jsonify([{"msg":"Result not found"},{"status_code":response.status_code}])
    else:
        json = response.json()
        return jsonify(json)

# Delete a result by id
@app.route("/result/<string:id>",methods=['DELETE'])
def delete_result(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    if json['deleted_count'] == 0:
        return jsonify({"msg":"Result not found"})
    elif json['deleted_count'] == 1:
        return jsonify({"msg":"Result has been succesfully deleted"})

# List votes per table
@app.route("/result/table/<string:table_id>",methods=['GET'])
def show_votes_per_table(table_id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/table/'+table_id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# List most voted candidate per table
@app.route("/result/table/most_voted",methods=['GET'])
def show_most_voted_per_table():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/table/most_voted'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

# List average votes per table
@app.route("/result/table/avg_voted/<string:table_id>",methods=['GET'])
def show_average_votes_per_table(table_id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = config_data["url-backend-administration"] + '/result/table/avg_voted/'+table_id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


######################## END GATEWAY URLS ########################


# Main function
if __name__ == '__main__':
    config_data = load_config_file()
    print("Server running: "+"http://"+config_data["url-backend"]+":" +
    str(config_data["port"]))
    serve(app,host=config_data["url-backend"],port=config_data["port"])