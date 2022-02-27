session_config = {
    'secret_key': b'my secret session key',
    'debug': True,
    'SESSION_FILE_DIR': './.cache',
    'SESSION_TYPE': 'filesystem',
    'PERMANENT_SESSION_LIFETIME' : 300,
    'SESSION_COOKIE_NAME' :'demo',
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': True,

}

sample_saml_config = {
# These are required: no defaults:
      "saml_endpoint": 'required',  # URL of Idp's authentication endpoint
      "issuer": 'required',         # The Idp's 'issuer' URN imprimatur
      "spid": 'required',           # Your applications URN identifier registered with the Idp
      "certificate" : '-----BEGIN CERTIFICATE----- .... required .... -----END CERTIFICATE-----',   
                                    # The Idp's X509 signing certificate, PEM
# These are optional: defaults listed:
      "user_attr": "name_id",       # The claim used to set the username in the session 
      "auth_duration": 3600,        # number of seconds authentication considered valid
      "idp_ok": False,              # if True, IDP initiated logins are supported
      "assertions": [],             # claims to add to session attributes ["uid", "givenname", ...]
      "force_reauth" : False,       # True forces a full, non-SSO login
}