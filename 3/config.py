# Keycloak configuration
# client_config.py

# Keycloak configuration
KEYCLOAK_SERVER_URL = 'http://localhost:8080'
REALM_NAME = 'myrealm'

# Client configurations
CLIENTS = {
    'myclient': {
        'client_id': 'myclient',
        'client_secret': '074SRvot2YnhTpO5X1xTrBP92tWqqbNn'
    },
    'microsoft': {
        'client_id': 'microsoft',
        'client_secret': 'xGjq5YJdIm2wo3iBZRvsFuUYpL00BrhI'
    },
    'google': {
        'client_id': 'google',
        'client_secret': 'nOtNw2wZrNTAdt9t9fPnMCmUl7nrnUUu'
    },
    'aws': {
        'client_id': 'aws',
        'client_secret': 'NxSD3cFUuah2QsysoRtp0BwW0psuipQS'
    }
}

