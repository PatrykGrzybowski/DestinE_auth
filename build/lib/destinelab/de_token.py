import requests
import jwt
from lxml import html
from urllib.parse import parse_qs, urlparse

IAM_URL = "https://auth.destine.eu/"
CLIENT_ID = "dedl-hda"
REALM = "desp"
SERVICE_URL = "https://hda.data.destination-earth.eu/stac"

# Import DESPAuth and DEDLAuth here to ensure they are available
from .desp_auth import DESPAuth
from .dedl_auth import DEDLAuth

class AuthHandler:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.desp_access_token = None
        self.dedl_access_token = None
    
    def get_token(self):
        # Get DESP auth token
        desp_auth = DESPAuth(self.username, self.password)
        self.desp_access_token = desp_auth.get_token_otp()
        
        # Get DEDL auth token
        dedl_auth = DEDLAuth(self.desp_access_token)
        self.dedl_access_token = dedl_auth.get_token()
        
        return self.dedl_access_token

    def get_roles(self,token):
        decoded_token = jwt.decode(token, options={"verify_signature": False})
         
        roles = None
        if decoded_token['realm_access']['roles']:
            roles = decoded_token['realm_access']['roles']
        
        return roles
        
    def is_DTaccess_allowed(self,token):
        roles=self.get_roles(token)

        is_allowed = False
        if 'DPAD_Direct_Access' in roles:
            is_allowed = True
            print("DT Output access allowed")
        else:
            print("DT Output access denied")
            
        return is_allowed
