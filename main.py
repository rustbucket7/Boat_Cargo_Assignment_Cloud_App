from flask import Flask, request, render_template, make_response, abort
from google.cloud import datastore
from google.auth.transport import requests
import jwt
import requests
import secrets

app = Flask(__name__)
client = datastore.Client()


# Content-Type constants
app_json = "application/json"
text_html = "text/html"

# OAuth constants
client_id = "97558860735-i3fqtu4madf06tf1a46sfc4k7ni3k9qh.apps.googleusercontent.com"
redirect_uri = "https://finalproject1-cs493-hoangmic.wl.r.appspot.com/oauth"
client_secret = "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"

# ============================================================================
# helper functions for OAuth and Token validation and creating responses
# ============================================================================


def make_oauth_url():
    """ Make OAuth redirect URL for /getoauth to return to index.html """
    state_str = secrets.token_urlsafe(32)  # randomly generate a new 32 byte string each time an OAuth request is made

    # store state_str in Datastore
    new_state = datastore.entity.Entity(key=client.key("oauth_state"))
    new_state.update({"state": state_str})
    client.put(new_state)

    # parameters needed to make redirect URL
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "profile",  # need to use profile instead of email from example
        "state": state_str,
        # "access_type": "offline"
    }

    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    param_str = ""

    # make the redirect URL
    for key in params:
        param_str += "&" + key + "=" + params[key]

    # when making final redirect_url, skip the first '&' char of param_str and replace it with '?' char
    redirect_url = base_url + '?' + param_str[1:]

    return redirect_url


def get_access_token():
    """ Get Access Token for /oauth to use to get People data """
    token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_body = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": request.args["code"]}

    token_url = "https://oauth2.googleapis.com/token"

    # get an access_token
    token_response = requests.post(token_url, headers=token_headers, data=token_body)

    return token_response


def verify_state(redirect_state):
    """ Verify if redirect state matches what is in Datastore Kind """
    # query all states to output what should be only 1 state in the Datastore Kind
    query = client.query(kind="oauth_state")
    all_states = list(query.fetch())  # get all states

    # if saved_state from OAuth redirect is the same as the one in Datastore Kind,
    # state value authentication complete
    for state in all_states:
        if state["state"] == redirect_state:
            verified_state = redirect_state  # save verified_state
            client.delete(state)  # delete the state in Datastore Kind

    if verified_state:
        return verified_state

    else:
        return False


def verify_token(id_token):
    """ Verify JWT token's integrity using Google's OAuth endpoint (not safe for production) """
    tokeninfo_url = "https://oauth2.googleapis.com/tokeninfo?id_token=" + id_token
    tokeninfo_response = requests.post(tokeninfo_url)

    # if token is good, return True
    if tokeninfo_response.status_code == 200:
        return True

    else:
        return False


def decode_token(token):
    """ Decode the payload of a JWT token """
    return jwt.decode(token, options={"verify_signature": False})  # decode payload of token


def check_for_jwt(request):
    """ Check for Authorization in request header """
    # adapted from auth0 code example from exploration
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]

        # if token is good, return decoded payload
        if verify_token(token):
            return decode_token(token)
        else:
            return False

    else:
        return False


def create_response(response_json, content_type, status_code, allow_methods=None, location_link=None):
    """ Create response object to return to API caller """
    # if content_type is 'application/json', make response using JSON
    if content_type == app_json:
        response = make_response(response_json)

    # if allow_methods are specified, set the header appropriately
    if allow_methods is not None:
        response.headers["access_control_allow_methods"] = allow_methods

    # if a URL link is specified, set the header appropriately
    if location_link is not None:
        response.headers["Location"] = location_link

    # set the response Content-Type to appropriate type
    # and set appropriate status code
    response.headers.set("Content-Type", content_type)
    response.status_code = status_code

    # return completed response
    return response

# ============================================================================
# ============================================================================


# ============================================================================
# API Routes
# ============================================================================


# allow code 405 errors to return as JSON instead of HTML
@app.errorhandler(405)
def invalid_method_405(description):
    response_json = {"Error": "Invalid HTTP method for endpoint"}
    allow_methods = "POST, GET"
    return create_response(response_json, app_json, 405, allow_methods)


@app.route('/')
def root():
    return render_template("index.html")


@app.route('/users', methods=['GET'])
def get_users():
    if request.method == 'GET':
        # get all users in Datastore

        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # get all users in Datastore
        query = client.query(kind="User")
        all_users = list(query.fetch())  # get all entities in kind "users"

        # add a temp key:value (ex. "id": 123456) to return to the user API call
        for user in all_users:
            user["id"] = user.key.id

        response_json = {"users": all_users}
        return create_response(response_json, app_json, 200)


@app.route('/boats', methods=['POST', 'GET'])
def get_post_boats():
    # create a new boat
    if request.method == 'POST':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # if request body is not JSON, return code 415
        if request.content_type != "application/json" or request.get_json() is None:
            response_json = {"Error": "Unsupported data format"}
            return create_response(response_json, app_json, 415)

        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        content = request.get_json()

        # if all required keys are found, create new boat and
        # return new boat's id, name, type, and length with code 201
        if all(key in content for key in ('name', 'type', 'length')):
            new_boat = datastore.entity.Entity(key=client.key("boats"))
            new_boat.update(
                {"name": content["name"],
                 "type": content["type"],
                 "length": content["length"],
                 "loads": [],
                 "owner": decoded_jwt['sub']
                 })
            client.put(new_boat)

            response_json = new_boat
            response_json["id"] = new_boat.key.id
            response_json["self"] = request.host_url + 'boats/' + str(response_json["id"])

            # return response_json, 201
            return create_response(response_json, app_json, 201)

        # if a key is missing, return code 400
        else:
            response_json = {"Error": "The request object is missing at least one of the required attributes"}
            return create_response(response_json, app_json, 400)

    # get all boats of owner
    elif request.method == 'GET':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        # pagination code based on one from exploration
        # grab offset and limit values from user request's header
        req_offset = int(request.args.get('offset', '0'))
        req_limit = int(request.args.get('limit', '5'))

        # if the limit value is larger than 5, reset it to 5
        if req_limit > 5:
            req_limit = 5

        # query Datastore, convert the returned iterator into a list of objects
        query = client.query(kind="boats")
        query.add_filter("owner", "=", decoded_jwt['sub'])  # filter only for those owned by owner
        all_boats_iterator = query.fetch(limit=req_limit, offset=req_offset)  # get all entities in kind "boats"
        all_boats_pages = all_boats_iterator.pages
        all_boats = list(next(all_boats_pages))

        # construct next_url for pagination
        if all_boats_iterator.next_page_token:
            next_offset = req_offset + req_limit
            next_url = request.base_url + "?limit=" + str(req_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        # add a temp key:value for "id" and "self" to return to the user API call
        owner_boats = []
        for boat in all_boats:
            if boat['owner'] == decoded_jwt['sub']:
                boat["id"] = boat.key.id
                boat["self"] = request.host_url + 'boats/' + str(boat["id"])
                owner_boats.append(boat)

        # construct response JSON for list of owner's boats, # of boats in this list,  and the next_url
        response_json = {"boats": owner_boats, "total_items": len(owner_boats)}

        if next_url:
            response_json["next_url"] = next_url

        # return response_json, 200
        return create_response(response_json, app_json, 200)

    # if PUT or DELETE methods are used, return code 405
    elif request.method in ["PUT", "PATCH", "DELETE"]:
        # abort(405, description="Invalid HTTP method for endpoint")
        abort(405)


@app.route('/boats/<boat_id>', methods=['GET', 'DELETE', 'PATCH', 'PUT'])
def get_delete_boats(boat_id):
    # get an existing boat
    if request.method == 'GET':
        # check Accept header
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        # try to retrieve the boat
        boat_key = client.key("boats", int(boat_id))
        boat = client.get(key=boat_key)

        # if no entity was found with desired boat_id, return an Error message with code 404
        if boat is None:
            response_json = {"Error": "No boat with this boat_id exists"}
            return create_response(response_json, app_json, 404)

        # if boat owner is not the same one in JWT's sub, return 403
        elif boat['owner'] != decoded_jwt['sub']:
            response_json = {"Error": "Boat does not belong to this owner"}
            return create_response(response_json, app_json, 403)

        # add a self link to the boat object before returning it to the API caller
        boat["id"] = boat.key.id
        boat["self"] = request.host_url + 'boats/' + str(boat["id"])

        # add a self link to each load before returning it to the API caller
        for load in boat["loads"]:
            load["self"] = request.host_url + 'loads/' + str(load["id"])

        # return data on desired boat_id
        response_json = boat
        return create_response(response_json, app_json, 200)

    # delete a boat... no response body
    elif request.method == 'DELETE':
        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        boat_key = client.key("boats", int(boat_id))
        boat = client.get(key=boat_key)

        # if no entity was found with desired boat_id, return an Error message with code 404
        if boat is None:
            response_json = {"Error": "No boat with this boat_id exists"}
            return create_response(response_json, app_json, 404)

        # if boat owner is not the same one in JWT's sub, return 403
        elif boat['owner'] != decoded_jwt['sub']:
            response_json = {"Error": "Boat does not belong to this owner"}
            return create_response(response_json, app_json, 403)

        # otherwise, delete Entity with boat_key from Kind
        client.delete(boat_key)

        # also, free the load assigned to the boat for other carriers
        query = client.query(kind="loads")
        all_loads = list(query.fetch())  # get all loads

        # iterate through all loads to see if any of them have the deleted boat
        # if yes, set that load's "carrier" to None and update the loads Kind
        for load in all_loads:
            if load["carrier"] is not None:
                if load["carrier"]["id"] == int(boat_id):
                    load["carrier"] = None
                    client.put(load)

        # return '', 204
        return create_response('', app_json, 204)

    # edit a boat (only 1 attribute)... no response body
    elif request.method == 'PATCH':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # if request JSON is not JSON, return code 415
        if request.content_type != "application/json" or request.get_json() is None:
            response_json = {"Error": "Unsupported data format"}
            return create_response(response_json, app_json, 415)
        
        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        content = request.get_json()

        # if incoming request JSON is not exactly 1 attribute, return code 400
        if len(content) != 1:
            response_json = {"Error": "Too many/few attributes to edit"}
            return create_response(response_json, app_json, 400)

        # if an appropriate attribute is found in "content",
        # try to edit that attribute
        elif list(content.keys())[0] in ['name', 'type', 'length']:
            boat_key = client.key("boats", int(boat_id))
            boat = client.get(key=boat_key)

            # if no entity was found with desired boat_id, return an Error message with code 404
            if boat is None:
                response_json = {"Error": "No boat with this boat_id exists"}
                return create_response(response_json, app_json, 404)

            # if boat owner is not the same one in JWT's sub, return 403
            elif boat['owner'] != decoded_jwt['sub']:
                response_json = {"Error": "Boat does not belong to this owner"}
                return create_response(response_json, app_json, 403)

            # change boat's attribute based on JSON sent by API caller
            if 'name' in content:
                boat['name'] = content['name']

            elif 'type' in content:
                boat['type'] = content['type']

            elif 'length' in content:
                boat['length'] = content['length']

            client.put(boat)

            # make response JSON with self link for API caller
            response_json = boat
            response_json['id'] = boat.key.id
            response_json["self"] = request.host_url + 'boats/' + str(response_json["id"])

            # create response
            # return '', 204
            return create_response('', app_json, 204)

        # if a key is missing, return code 400
        else:
            response_json = {"Error": "The request object is missing at least one of the required attributes"}
            return create_response(response_json, app_json, 400)

    # edit a boat (all attributes)... response body is JSON
    elif request.method == 'PUT':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # if request JSON is not JSON, return code 415
        if request.content_type != "application/json" or request.get_json() is None:
            response_json = {"Error": "Unsupported data format"}
            return create_response(response_json, app_json, 415)

        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        content = request.get_json()

        # if incoming request JSON is not exactly 3 attribute, return code 400
        if len(content) != 3:
            response_json = {"Error": "Too many/few attributes to edit"}
            return create_response(response_json, app_json, 400)

        if all(key in content for key in ('name', 'type', 'length')):
            # if not, get the boat entity
            boat_key = client.key("boats", int(boat_id))
            boat = client.get(key=boat_key)

            # if no entity was found with desired boat_id, return an Error message with code 404
            if boat is None:
                response_json = {"Error": "No boat with this boat_id exists"}
                return create_response(response_json, app_json, 404)

            # if boat owner is not the same one in JWT's sub, return 403
            elif boat['owner'] != decoded_jwt['sub']:
                response_json = {"Error": "Boat does not belong to this owner"}
                return create_response(response_json, app_json, 403)

            # change boat's attributes based on JSON from API caller
            boat.update(
                {"name": content["name"],
                 "type": content["type"],
                 "length": content["length"]
                 })

            client.put(boat)

            # make response JSON with self link for API caller
            response_json = boat
            response_json["id"] = boat.key.id
            response_json["self"] = request.host_url + 'boats/' + str(response_json["id"])

            # response must be JSON and return code 303
            return create_response(response_json, app_json, 303)

        # if a key is missing, return code 400
        else:
            # response must be JSON
            response_json = {"Error": "The request object is missing at least one of the required attributes"}
            return create_response(response_json, app_json, 400)


@app.route('/loads', methods=['POST', 'GET'])
def get_post_loads():
    # create a new load
    if request.method == 'POST':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # if request JSON is not JSON, return code 415
        if request.content_type != "application/json" or request.get_json() is None:
            response_json = {"Error": "Unsupported data format"}
            return create_response(response_json, app_json, 415)

        content = request.get_json()

        # if all required keys are found, create new load and
        # return new load's id, volume, carrier, item, and type with code 201
        if all(key in content for key in ('volume', 'item', 'creation_date')):
            new_load = datastore.entity.Entity(key=client.key("loads"))

            new_load.update(
                {"volume": content["volume"],
                 "carrier": None,
                 "item": content["item"],
                 "creation_date": content["creation_date"]
                 })

            # upload newly created load to loads Kind
            client.put(new_load)

            # make response JSON with self link for API caller
            response_json = new_load
            response_json["id"] = new_load.key.id
            response_json["self"] = request.host_url + 'loads/' + str(response_json["id"])

            # return response_json, 201
            return create_response(response_json, app_json, 201)

        # if a key is missing, return code 400
        else:
            response_json = {"Error": "The request object is missing at least one of the required attributes"}
            return create_response(response_json, app_json, 400)

    # get all loads
    elif request.method == 'GET':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # pagination code based on one from exploration
        # grab offset and limit values from user request's header
        req_offset = int(request.args.get('offset', '0'))
        req_limit = int(request.args.get('limit', '5'))

        # if the limit value is larger than 5, reset it to 5
        if req_limit > 5:
            req_limit = 5

        # query Datastore, convert the returned iterator into a list of objects
        query = client.query(kind="loads")
        all_loads_iterator = query.fetch(limit=req_limit, offset=req_offset)  # get all entities in kind "loads"
        all_loads_pages = all_loads_iterator.pages
        all_loads = list(next(all_loads_pages))

        # construct next_url for pagination
        if all_loads_iterator.next_page_token:
            next_offset = req_offset + req_limit
            next_url = request.base_url + "?limit=" + str(req_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        # add a temp key:value for "id", "carrier", and "self" to return to the user API call
        for load in all_loads:
            load["id"] = load.key.id
            load["self"] = request.host_url + 'loads/' + str(load["id"])
            if load["carrier"] is not None:
                load["carrier"]["self"] = request.host_url + 'boats/' + str(load["carrier"]["id"])

        # construct response JSON for list of boats and the next_url
        response_json = {"loads": all_loads, "total_items": len(all_loads)}

        if next_url:
            response_json["next_url"] = next_url

        # return response_json, 200
        return create_response(response_json, app_json, 200)


@app.route('/loads/<load_id>', methods=['GET', 'DELETE', 'PATCH', 'PUT'])
def get_delete_loads(load_id):
    # get an existing load
    if request.method == 'GET':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # try to retrieve load
        load_key = client.key("loads", int(load_id))
        load = client.get(key=load_key)

        # if no entity was found with desired load_id, return an Error message with code 404
        if load is None:
            response_json = {"Error": "No load with this load_id exists"}
            return create_response(response_json, app_json, 404)

        # add a self link to the load object and the carrier object before returning it to the API caller
        load["id"] = load.key.id
        load["self"] = request.host_url + 'loads/' + str(load["id"])
        if load["carrier"] is not None:
            load["carrier"]["self"] = request.host_url + 'boats/' + str(load["carrier"]["id"])

        # otherwise, return data on desired load_id
        response_json = load
        return create_response(response_json, app_json, 200)

    # delete a load... no response body
    elif request.method == 'DELETE':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # try to retrieve load
        load_key = client.key("loads", int(load_id))
        load = client.get(key=load_key)

        # if load does not exist, return an Error with code 404
        if load is None:
            response_json = {"Error": "No load with this load_id exists"}
            return create_response(response_json, app_json, 404)

        # if load has an assign boat carrier, delete this load from that carrier's "loads" field
        if load["carrier"] is not None:
            boat_key = client.key("boats", int(load["carrier"]["id"]))
            boat = client.get(key=boat_key)

            for i in range(len(boat["loads"])):
                if boat["loads"][i]["id"] == int(load_id):
                    del boat["loads"][i]
                    break

            # update the boat to Kind
            client.put(boat)

        # delete Entity with load_key from Kind
        client.delete(load_key)

        # return '', 204
        return create_response('', app_json, 204)

    # edit load (1 attribute only)... no response body
    elif request.method == 'PATCH':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # if request JSON is not JSON, return code 415
        if request.content_type != "application/json" or request.get_json() is None:
            response_json = {"Error": "Unsupported data format"}
            return create_response(response_json, app_json, 415)

        content = request.get_json()

        # if incoming request JSON is not exactly 1 attribute, return code 400
        if len(content) != 1:
            response_json = {"Error": "Too many/few attributes to edit"}
            return create_response(response_json, app_json, 400)

        # if an appropriate attribute is found in "content",
        # try to edit that attribute
        elif list(content.keys())[0] in ['volume', 'item', 'creation_date']:
            load_key = client.key("loads", int(load_id))
            load = client.get(key=load_key)

            # if no entity was found with desired load_id, return an Error message with code 404
            if load is None:
                response_json = {"Error": "No load with this load_id exists"}
                return create_response(response_json, app_json, 404)

            # change load's attribute based on JSON sent by API caller
            if 'volume' in content:
                load['volume'] = content['volume']

            elif 'item' in content:
                load['item'] = content['item']

            elif 'creation_date' in content:
                load['creation_date'] = content['creation_date']

            client.put(load)

            # create response_json
            response_json = load
            response_json["id"] = load.key.id
            response_json["self"] = request.host_url + 'loads/' + str(
                response_json["id"])

            # return '', 204
            return create_response('', app_json, 204)

        # if a key is missing, return code 400
        else:
            response_json = {
                "Error": "The request object is missing at least one of the required attributes"}
            return create_response(response_json, app_json, 400)

    # edit load (all attributes required)... response body is JSON
    elif request.method == 'PUT':
        # if returning data format is not JSON, return code 406
        if "application/json" not in request.accept_mimetypes:
            response_json = {"Error": "Improper mimetype in Accept header"}
            return create_response(response_json, app_json, 406)

        # if request JSON is not JSON, return code 415
        if request.content_type != "application/json" or request.get_json() is None:
            response_json = {"Error": "Unsupported data format"}
            return create_response(response_json, app_json, 415)

        content = request.get_json()

        # if incoming request JSON is not exactly 3 attribute, return code 400
        if len(content) != 3:
            response_json = {"Error": "Too many/few attributes to edit"}
            return create_response(response_json, app_json, 400)

        if all(key in content for key in ('volume', 'item', 'creation_date')):
            # if not, get the load entity
            load_key = client.key("loads", int(load_id))
            load = client.get(key=load_key)

            # if no entity was found with desired load_id, return an Error message with code 404
            if load is None:
                response_json = {"Error": "No load with this load_id exists"}
                return create_response(response_json, app_json, 404)

            # change boat's attributes based on JSON from API caller
            load.update(
                {"volume": content["volume"],
                 "item": content["item"],
                 "creation_date": content["creation_date"]
                 })
            client.put(load)

            response_json = load
            response_json["id"] = load.key.id
            response_json["self"] = request.host_url + 'loads/' + str(
                response_json["id"])

            # response must be JSON and return code 303
            return create_response(response_json, app_json, 303)

        # if a key is missing, return code 400
        else:
            # response must be JSON
            response_json = {
                "Error": "The request object is missing at least one of the required attributes"}
            return create_response(response_json, app_json, 400)


@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def get_delete_boats_loads(boat_id, load_id):
    # assign a load to a boat... no response body
    if request.method == 'PUT':
        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        load_key = client.key("loads", int(load_id))
        load = client.get(key=load_key)
        boat_key = client.key("boats", int(boat_id))
        boat = client.get(key=boat_key)

        # if no entity was found with desired load_id or boat_id, return an Error message with code 404
        if load is None or boat is None:
            response_json = {"Error": "The specified boat and/or load does not exist"}
            return create_response(response_json, app_json, 404)

        # if boat owner is not the same one in JWT's sub, return 403
        elif boat['owner'] != decoded_jwt['sub']:
            response_json = {"Error": "Boat does not belong to this owner"}
            return create_response(response_json, app_json, 403)

        # check if load is already assigned,
        # if yes, return Error with code 403
        elif load["carrier"] is not None:
            response_json = {"Error": "The load is already loaded on another boat"}
            return create_response(response_json, app_json, 403)

        # otherwise,
        # assign boat to load's "carrier"
        load["carrier"] = {
            "id": int(boat_id),
            "name": boat["name"],
        }

        # update load to Datastore Kind
        client.put(load)

        # in preparation to save this info to boat's "load" key (a list of objects)
        # add load's ID to the object
        load["id"] = load.key.id
        del load["carrier"]  # remove load's carrier data, if just to reduce bulk

        # add load to boat's "loads"
        boat["loads"].append(load)

        # update boat Datastore Kind
        client.put(boat)

        # return '', 204
        return create_response('', app_json, 204)

    # delete a load from a boat... no response body
    elif request.method == 'DELETE':
        # check for valid JWT
        check_jwt = check_for_jwt(request)
        if not check_jwt:
            response_json = {
                "Error": "No Authorization in request header and/or JWT is invalid"}
            return create_response(response_json, app_json, 401)

        else:
            decoded_jwt = check_jwt

        # try to retrieve boat and load
        load_key = client.key("loads", int(load_id))
        load = client.get(key=load_key)
        boat_key = client.key("boats", int(boat_id))
        boat = client.get(key=boat_key)

        # check if boat and load even exist
        # check if load has a carrier and if it is assigned to the desired boat
        # if none of the above, return Error with code 404
        if boat is None or load is None or load["carrier"] is None or load["carrier"]["id"] != int(boat_id):
            response_json = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
            return create_response(response_json, app_json, 404)

        # if boat owner is not the same one in JWT's sub, return 403
        elif boat['owner'] != decoded_jwt['sub']:
            response_json = {"Error": "Boat does not belong to this owner"}
            return create_response(response_json, app_json, 403)

        # otherwise,
        # remove boat info from load's "carrier"
        load["carrier"] = None

        # remove load object from boat's "loads" field
        for i in range(len(boat["loads"])):
            if boat["loads"][i]["id"] == int(load_id):
                del boat["loads"][i]
                break

        # update load and boat entities
        client.put(load)
        client.put(boat)

        # return '', 204
        return create_response('', app_json, 204)

# ============================================================================
# ============================================================================


# ============================================================================
# OAuth Routes
# ============================================================================


@app.route('/oauth')
def oauth():
    """
    oauth() will get an Access Token, create a User into Datastore,
    and output JWT token and its decoded payload to user_info.html
    """
    if request.args["code"]:
        redirect_state = request.args["state"]  # save this state to compare with Datastore Kind's state

        # verify if redirect's state is the same as the one in Datastore Kind
        if not verify_state(redirect_state):
            return "State could not be verified"

        # get access token data
        token_response = get_access_token()
        token_response_json = token_response.json()

        # output JWT token to user_info.html
        if token_response_json["id_token"]:
            token = token_response_json["id_token"]

            idinfo = verify_token(token)
            if idinfo is False:
                idinfo = "Bad token"
                user_name = "Bad token"
                user_id = "Bad token"
            else:
                idinfo = decode_token(token)  # decode payload of token

                user_name = idinfo['name']
                user_id = idinfo['sub']

                # get all users in Datastore to see if their unique ID is the same as the JWT's sub
                query = client.query(kind="User")
                query.add_filter("user_id", "=", user_id)
                user_exists = list(query.fetch())

                # if no user_id was found, make a new entry in Datastore's User kind
                # otherwise, do nothing
                if len(user_exists) == 0:
                    # add new user to Datastore
                    new_user = datastore.entity.Entity(key=client.key("User"))
                    new_user.update({
                        "user_id": user_id,  # use str, don't use int, number value is too large
                        "user_name": user_name
                    })
                    client.put(new_user)

            # output encoded JWT token and decoded JWT payload to user_info.html
            return render_template("user_info.html",
                                   jwt=token,
                                   jwt_decoded=str(idinfo),
                                   user_name=user_name,
                                   user_id=user_id)

        # id token was not returned
        else:
            return render_template("bad_oauth.html", bad_oauth_msg="JWT ID Token was not found")

    # redirect OAuth code was not found
    else:
        return render_template("bad_oauth.html", bad_oauth_msg="Improper OAuth redirect - No 'code' found")


@app.route('/getoauth', methods=['GET'])
def get_oauth():
    """ get_oauth() is purely for giving index.html the redirect to the Google consent form """
    response = make_response()
    response.headers.set("Content-Type", "text/html")
    response.status_code = 303
    response.headers["Location"] = make_oauth_url()
    return response


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
