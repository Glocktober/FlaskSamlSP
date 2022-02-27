 ## FlaskSP - SAML Service Provider for Flask

The **FlaskSaml** [module](../README.md) implements a SAML Service Provider class (**FlaskSP**)for the [Flask web framework.](https://palletsprojects.com/p/flask/) 

This module Implements a SAML v2 [*Service Provider* (SP)](https://en.wikipedia.org/wiki/Service_provider_(SAML)) 
* Creates SAMLRequests, validates SAMLResponses, and adds SAML assertions into to session data.
  
* Establishes an Assertion Control Service (ACS) endpoint '/saml/acs'

* Makes available SAML **assertions** are to other middleware and views as a Python `dict` maintained in the user session data.

* Uses @HENNGE's excellent [minisaml implementation](https://github.com/HENNGE/minisaml).


## Quickstart
> pypi installation:
```bash
# python3 -m pip install FlaskSamlSP
```
This will load required python modules, including Flask, Flask-Session and minisaml, and all their dependencies.
### Initializing FlaskSP
> Adding FlaskSP to a flask app:
```python
# Imports
from flask import Flask
from Flask-Session import Sessions   
from FlaskSaml import FlaskSP  

app = Flask(__name__)
app.config.from_mapping(session_config)
Session(app)

# Install and register the FlaskSaml blueprint
saml = FlaskSP(saml_config=saml_config)
app.register_blueprint(auth)                        

```

The **`saml_config`** is a Python `dict` containing the necessary information to use the [SAML IdP](https://en.wikipedia.org/wiki/Identity_provider_(SAML)) (and a few configuration parameters). The parameters needed for configuring `saml_config` are discussed later. The [FlaskSP class is discussed here](SAMLSPCLASS.md), cover some other features, [such as login hooks.](LOGINHOOKS.md)
### Using the SAML data
```python
# require_login decorator initiates SAML IdP login
@app.route('/login')
@saml.require_login         
def hello_user():
    return f"Hello {session['username']}"

# is_authenticated indicates login status
@app.route('/')
def index():
    if saml.is_authenticated:
        return "You are authenticated"
    else:
        return "You need to login first"

# simple way to logout (withou a SAML Logout)
@app.route('/logout')
def logout_view():
    session.clear()
    return 'OK'

```

## Accessing SAML Attributes from Views and Middleware
The saved attributes and values are accessible to views and other middleware in the users session. For instance, you can pre-populate a form with the authenticated user's name, department, email, and other data you acquire from the IdP.
> Using SAML provided user data
```python
@app.route('/whoami')
@saml.login_required
def whoami():
    return session['username']

@app.routes('/allattributes')
@saml.login_required
def allattrs():
    return session['attributes']

@app.route('/admins')
@saml.login_required
def admins_only():
    if 'sysadmin' in session['attributes']['groups]:
        return 'Welcome to admins only'
    else:
        return 'Restricted access - admins only'

```
### Available Session Attributes  
The attributes you have available and saved in your session from the SAML authorizaiton process depend on:
* The SAML ***assertions*** provided by the IdP. This is set by the IdP configuration. We can't save something we never received. This is all on the IdP end.
* The attributes listed in the ***`assertions`*** key in the **saml_config** options. This `list` is set by you, and filters the assertions you care about from the IdP's `SAMLResponse`. 
* If an **assertion** *name* matches an attribute *name* in the config, the value is added to the users `session['attributes']` dict with the *name* as the key.
* If no ***`assertions`*** list is provided in **saml_config**, the only attribute added to your session will be `username`, set from the `name_id` in the `SAMLResponse`. 
* Multi-value assertions (such as you might find in a `group` or `member_of` parameter) are stored as a Python `list` of values.

#### SAML Attribute Session Layout
This is the structure used by SamlSP to save attributes is presented here: avoid namespace collisions with view or middleware session data.
> FlaskSP session data layout:
```
{'username': <username>}
{'attributes':{
                'attr1': value1,    # attribute/value pairs 
                'attr2': value2.    # created from SAML
                ...                 # assertions
                'attrN': valueN,
                '_SAML' : {         # SamlSP's metadata
                    'issuer' : <IdP entity id>
                    'requestid' : <saml 'on behalf of'> 
                    'audience' : <saml response audience>
                    'expires' : <unix time until reauth required>
                }
}
{'request_id': <request-id>}  # temporary during login
... 
```

## SAML Configuation Parameters

Configuration information required to set-up the SAML authentication, and parameters to tune FlaskSP is formed into a `dict` passed as the **`saml_config=`** argument to **`SamlSP()`**.  Typically this is imported from a `config.py` as in the example above.

Collect the necessary information from the IdP (much available from it's metadata) and to select the behavior appropriate for your application.  

This isn't difficult, but it can confusing if you are unfamiliar with SAML.
>SamlSP config file paramters: 

| **parameter**  |**type** | **default** | **description**
|------------------|-----|--------|----------------------|
|**saml_endpoint** |URL|*required*|IdP's SAML auth endpoint|
|**spid** |URI|*required*|Our apps's entity id|
|**issuer** |URI|*required*|IdP's `issuer` identity|
|**force_reauth**|Bool|False| True will request IdP full login|
|**user_attr**|string|name_id|SAML assertion providing `username` attribute|
|**assertions**|[string]|[]|A list of SAMLRespons assertions to collect|
|**idp_ok**|Bool|True|Permit IdP initiated logon|
|**auth_duration**|int|3600|Seconds between SAML credentials renewal |
|**certificate**|string|*required*|The IdP's public certificate for signing verification|

* In most cases the "URI's" will be "URL's".
* The SPID must be configured with the IdP. This is how the IdP knows who we are.
* If `assertions` is missing or an empty list, only the `username` will be placed in the session.

