import logging
import psycopg2
import requests
from config import KEYCLOAK_SERVER_URL, REALM_NAME, CLIENTS
TOKEN_URL = f'{KEYCLOAK_SERVER_URL}/realms/{REALM_NAME}/protocol/openid-connect/token'

def get_db_connection():
    """Connect to the PostgreSQL database."""
    conn = psycopg2.connect(
        dbname='sso_db',
        user='postgreshackuser01',  # Replace with your DB user
        password='hackathonsrv01@',  # Replace with your DB password
        host='hackathon-postgres-01.postgres.database.azure.com',
        port='5432'
    )
    return conn


def get_admin_token(client_name):
    """Obtain an admin access token from Keycloak for a specific client."""
    try:
        # Check if the client exists in the CLIENTS configuration
        if client_name not in CLIENTS:
            logging.error(f"Client {client_name} not found in configuration")
            raise ValueError('Invalid client name')

        client_id = CLIENTS[client_name]['client_id']
        client_secret = CLIENTS[client_name]['client_secret']

        logging.info(f"Getting admin access token from Keycloak for client {client_name}")
        response = requests.post(TOKEN_URL, data={
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        })
        response.raise_for_status()
        logging.info("Successfully obtained admin token")
        return response.json()['access_token']
    except requests.RequestException as e:
        logging.error(f"Failed to obtain admin token: {str(e)}")
        raise
    except ValueError as ve:
        logging.error(str(ve))
        raise

