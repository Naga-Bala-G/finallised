import psycopg2
from psycopg2 import sql
from flask import Flask, request, jsonify, abort, render_template
import requests
import logging
import sys
from datetime import datetime, timedelta
from config import KEYCLOAK_SERVER_URL, REALM_NAME, CLIENTS
from functions import get_db_connection, get_admin_token

app = Flask(__name__)

# Keycloak configuration
TOKEN_URL = f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token'
USERS_URL = f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/users'
CLIENTS_URL = f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/clients'

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s', handlers=[logging.StreamHandler(sys.stdout)])


@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard/executive')
def executive_dashboard():
    return render_template('dashboard_executive.html')

@app.route('/dashboard/manager')
def manager_dashboard():
    return render_template('dashboard_manager.html')

@app.route('/dashboard/manager/personal_info')
def Personal_info():
    return render_template('personal-info.html')

@app.route('/dashboard/manager/reports')
def Reports():
    return render_template('reports.html')

@app.route('/dashboard/manager/manager_tools')
def Manager_tools():
    return render_template('manager-tools.html')

@app.route('/dashboard/employee')
def employee_dashboard():
    return render_template('dashboard_employee.html')

def get_client_credentials(client_name):
    """Retrieve client_id and client_secret based on the client_name."""
    client = CLIENTS.get(client_name)
    if not client:
        logging.error(f"Client {client_name} not found in configuration")
        abort(400, description='Invalid client')
    return client['client_id'], client['client_secret']

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate a user and return an access token along with user roles and client name."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        client_name = data.get('client')

        if not all([username, password, client_name]):
            logging.warning("Missing login parameters")
            abort(400, description='Missing parameters')

        if client_name not in CLIENTS:
            logging.error(f"Client {client_name} not found in configuration")
            abort(400, description='Invalid client')

        client_id = CLIENTS[client_name]['client_id']
        client_secret = CLIENTS[client_name]['client_secret']

        logging.info(f"Authenticating user {username} for client {client_name}")
        token_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token', data={
            'grant_type': 'password',
            'client_id': client_id,
            'client_secret': client_secret,
            'username': username,
            'password': password,
        })

        if token_response.status_code != 200:
            logging.error(f"Authentication failed for user {username}")
            abort(token_response.status_code, description='Authentication failed')

        token_data = token_response.json()

        # Introspect the access token to get user roles
        introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
            'token': token_data['access_token'],
            'client_id': client_id,
            'client_secret': client_secret,
        })

        if introspect_response.status_code != 200:
            logging.error("Token introspection failed")
            abort(introspect_response.status_code, description='Token introspection failed')

        introspect_data = introspect_response.json()
        roles = introspect_data.get('realm_access', {}).get('roles', [])

        logging.info(f"User {username} roles: {roles}")

        return jsonify({
            'access_token': token_data['access_token'],
            'refresh_token': token_data['refresh_token'],
            'roles': roles,
            'client': client_name  # Include the client name in the response
        })

    except Exception as e:
        logging.error(f"Error during login process: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/user-details', methods=['POST'])
def user_details():
    """Fetch details of the user based on the provided access token and client name."""
    try:
        data = request.json
        auth_header = request.headers.get('Authorization')
        client_name = data.get('client')

        if not auth_header:
            logging.warning("Authorization header is missing")
            abort(400, description='Authorization header is missing')
        
        if not client_name:
            logging.warning("Client name is missing")
            abort(400, description='Client name is missing')

        token_prefix = 'Bearer '
        if not auth_header.startswith(token_prefix):
            logging.warning("Invalid authorization header format")
            abort(400, description='Invalid authorization header format')

        access_token = auth_header[len(token_prefix):]
        if not access_token:
            logging.warning("Access token is missing")
            abort(400, description='Missing access token')

        # Get client credentials
        client_id, client_secret = get_client_credentials(client_name)

        logging.info("Introspecting access token")
        introspect_response = requests.post(f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token/introspect', data={
            'token': access_token,
            'client_id': client_id,
            'client_secret': client_secret,
        })

        if introspect_response.status_code != 200:
            logging.error("Token introspection failed")
            abort(introspect_response.status_code, description='Token introspection failed')

        introspect_data = introspect_response.json()

        if not introspect_data.get('active'):
            logging.warning("Token is not active or invalid")
            abort(401, description='Token is not active or invalid')

        logging.info("Returning user details")
        return jsonify(introspect_data)
    except Exception as e:
        logging.error(f"Error fetching user details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh the access token using the provided refresh token."""
    try:
        data = request.json
        refresh_token = data.get('refresh_token')
        client_name = data.get('client')  # Get client name from the request

        if not refresh_token:
            logging.warning("Missing refresh token")
            abort(400, description='Missing refresh token')

        if not client_name or client_name not in CLIENTS:
            logging.error(f"Invalid client: {client_name}")
            abort(400, description='Invalid client')

        # Get client credentials
        client_id, client_secret = get_client_credentials(client_name)

        logging.info("Requesting new access token using refresh token")
        token_response = requests.post(TOKEN_URL, data={
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
        })

        if token_response.status_code != 200:
            logging.error("Token refresh failed")
            abort(token_response.status_code, description='Token refresh failed')

        token_data = token_response.json()
        logging.info("Token refreshed successfully")
        return jsonify(token_data)
    except Exception as e:
        logging.error(f"Error refreshing token: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Fetch the list of users from Keycloak and their roles."""
    try:
        logging.info("Fetching list of users and their roles")

        # Get client name from the request JSON body
        client_name = request.json.get('client')
        if not client_name:
            logging.error("Client name not provided in request")
            return jsonify({'error': 'Client name is required'}), 400

        access_token = get_admin_token(client_name)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Fetch all users from Keycloak
        users_response = requests.get(USERS_URL, headers=headers)
        users_response.raise_for_status()
        users = users_response.json()

        # Fetch all clients to find client IDs
        clients_response = requests.get(CLIENTS_URL, headers=headers)
        clients_response.raise_for_status()
        clients = clients_response.json()

        client_id_mapping = {client['clientId']: client['id'] for client in clients}

        user_details = []

        for user in users:
            user_id = user.get('id')
            first_name = user.get('firstName', 'N/A')
            last_name = user.get('lastName', 'N/A')
            name = user.get('username', 'N/A')
            email = user.get('email', 'N/A')

            if not user_id:
                logging.warning("User ID missing in response, skipping user")
                continue

            # Fetch realm roles for the user
            realm_roles_response = requests.get(f'{USERS_URL}/{user_id}/role-mappings/realm', headers=headers)
            realm_roles_response.raise_for_status()
            realm_roles_data = realm_roles_response.json()
            realm_roles = [role['name'] for role in realm_roles_data]

            # Fetch client roles for the user
            client_roles = {}
            for client_name, client_id in client_id_mapping.items():
                client_roles_response = requests.get(f'{USERS_URL}/{user_id}/role-mappings/clients/{client_id}', headers=headers)
                if client_roles_response.status_code == 200:
                    client_roles_data = client_roles_response.json()
                    client_roles[client_name] = [role['name'] for role in client_roles_data]
                else:
                    client_roles[client_name] = []

            # Append user information and their roles to the response list
            user_details.append({
                'first_name': first_name,
                'last_name': last_name,
                'name': name,
                'email': email,
                'roles': {
                    'realm_roles': realm_roles,
                    'client_roles': client_roles
                }
            })

        logging.info("Successfully fetched user details and their roles")
        return jsonify(user_details), 200

    except Exception as e:
        logging.error(f"Error fetching users: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/roles', methods=['GET'])
def get_roles():
    """Fetch each user's details including their given name and role."""
    try:
        logging.info("Fetching list of users and their roles")

        # Get client name from the request JSON body
        client_name = request.json.get('client')
        if not client_name:
            logging.error("Client name not provided in request")
            return jsonify({'error': 'Client name is required'}), 400

        # Get the admin token to authenticate with Keycloak
        access_token = get_admin_token(client_name)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Fetch all users from Keycloak
        response = requests.get(USERS_URL, headers=headers)
        response.raise_for_status()
        users = response.json()

        user_roles = []

        # Loop through each user to get their given name and roles
        for user in users:
            user_id = user.get('id')
            given_name = user.get('firstName', 'N/A')

            if not user_id:
                logging.warning("User ID missing in response, skipping user")
                continue

            # Fetch roles for each user by introspecting their details or realm access
            logging.info(f"Fetching roles for user {user_id} ({given_name})")

            user_roles_url = f'{USERS_URL}/{user_id}/role-mappings/realm'
            roles_response = requests.get(user_roles_url, headers=headers)
            roles_response.raise_for_status()

            roles_data = roles_response.json()
            realm_roles = [role['name'] for role in roles_data]

            user_roles.append({
                'given name': given_name,
                'role': realm_roles if realm_roles else []  # Return an empty list if no roles
            })

        logging.info("Successfully fetched users and their roles")
        return jsonify(user_roles), 200

    except Exception as e:
        logging.error(f"Error fetching user roles: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/roles/change_role', methods=['POST'])
def change_role():
    """Change a user's role by removing the current role and assigning a new one if the requester is an admin."""
    try:
        data = request.json
        username = data.get('username')
        old_role = data.get('old_role')
        new_role = data.get('new_role')

        if not all([username, old_role, new_role]):
            logging.warning("Missing parameters for role change")
            abort(400, description='Missing parameters')

        # Get client name from the request JSON body
        client_name = request.json.get('client')
        access_token = get_admin_token(client_name)

        # Get user ID
        user_id = get_user_id(username, access_token)
        
        # Change roles
        remove_role_from_user(user_id, old_role, access_token)
        assign_role_to_user(user_id, new_role, access_token)

        return jsonify({'message': f'Role changed from {old_role} to {new_role} for user {username}'}), 200
    except Exception as e:
        logging.error(f"Error changing role: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/roles/remove', methods=['POST'])
def remove_role():
    """Remove a role from a user if the requester is an admin."""
    try:
        data = request.json
        username = data.get('username')
        role_name = data.get('role')

        if not all([username, role_name]):
            logging.warning("Missing parameters for role removal")
            abort(400, description='Missing parameters')

        # Get client name from the request JSON body
        client_name = request.json.get('client')
        access_token = get_admin_token(client_name)

        # Get user ID
        user_id = get_user_id(username, access_token)

        # Remove role
        remove_role_from_user(user_id, role_name, access_token)

        return jsonify({'message': f'Role {role_name} removed from user {username}'}), 200
    except Exception as e:
        logging.error(f"Error removing role: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/roles/assign', methods=['POST'])
def assign_role():
    """Assign a role to a user if the requester is an admin."""
    try:
        data = request.json
        username = data.get('username')
        role_name = data.get('role')

        if not all([username, role_name]):
            logging.warning("Missing parameters for role assignment")
            abort(400, description='Missing parameters')

        # Get client name from the request JSON body
        client_name = request.json.get('client')
        access_token = get_admin_token(client_name)

        # Get user ID
        user_id = get_user_id(username, access_token)

        # Assign role
        assign_role_to_user(user_id, role_name, access_token)

        return jsonify({'message': f'Role {role_name} assigned to user {username}'}), 200
    except Exception as e:
        logging.error(f"Error assigning role: {str(e)}")
        return jsonify({'error': str(e)}), 500


def get_user_id(username, access_token):
    """Fetch the user ID for the specified username."""
    user_response = requests.get(
        f'{USERS_URL}?username={username}',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    )

    if user_response.status_code != 200:
        logging.error(f"Failed to fetch user ID for {username}: {user_response.text}")
        abort(user_response.status_code, description='Failed to fetch user ID')

    users = user_response.json()
    if not users:
        logging.warning(f"User {username} not found")
        abort(404, description='User not found')

    return users[0]['id']

def remove_role_from_user(user_id, role_name, access_token):
    """Remove a role from the user."""
    logging.info(f"Fetching role ID for {role_name}")
    role_response = requests.get(
        f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/roles/{role_name}',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    )

    if role_response.status_code != 200:
        logging.error(f"Failed to fetch role ID for {role_name}: {role_response.text}")
        abort(role_response.status_code, description='Failed to fetch role ID')

    role_data = role_response.json()
    role_id = role_data['id']

    logging.info(f"Removing role {role_name} from user {user_id}")
    remove_role_response = requests.delete(
        f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/users/{user_id}/role-mappings/realm',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        },
        json=[{
            'id': role_id,
            'name': role_name
        }]
    )

    if remove_role_response.status_code != 204:
        logging.error(f"Failed to remove role {role_name} from user {user_id}: {remove_role_response.text}")
        abort(remove_role_response.status_code, description='Failed to remove role')

def assign_role_to_user(user_id, role_name, access_token):
    """Assign a role to the user."""
    logging.info(f"Fetching role ID for {role_name}")
    role_response = requests.get(
        f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/roles/{role_name}',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    )

    if role_response.status_code != 200:
        logging.error(f"Failed to fetch role ID for {role_name}: {role_response.text}")
        abort(role_response.status_code, description='Failed to fetch role ID')

    role_data = role_response.json()
    role_id = role_data['id']

    logging.info(f"Assigning role {role_name} to user {user_id}")
    assign_role_response = requests.post(
        f'{KEYCLOAK_SERVER_URL}/admin/realms/{REALM_NAME}/users/{user_id}/role-mappings/realm',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        },
        json=[{
            'id': role_id,
            'name': role_name
        }]
    )

    if assign_role_response.status_code != 204:
        logging.error(f"Failed to assign role {role_name} to user {user_id}: {assign_role_response.text}")
        abort(assign_role_response.status_code, description='Failed to assign role')


if __name__ == '__main__':
    app.run(debug=True)