"""
FlaskSP - SAML2 Service Provider for Flask 

- Not strictly middlware, FlaskSP creates SAMLRequests, validates SAMLResponses,
  and adds SAML assertions to session data.
  
- Requires Flask-Session

- Assertion Control Service endpoint '/saml/acs' by default

"""
import time
from urllib.parse import urlencode, parse_qs

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from minisaml.response import validate_response
from minisaml.request import get_request_redirect_url

from flask import (
        Blueprint,
        redirect, 
        url_for, 
        session, 
        request,
        current_app,
        abort,
    )

from .reqID import ReqID
from FlaskSaml.flask_utils import (
    AppError,
    BadRequestError, 
    ConflictError,
    ForbiddenError,
    UnauthorizedError,
) 


class FlaskSP(Blueprint):
    """
SAML Service Provider module for Bottle

saml = FlaskSP(saml_config, app=None)

- Creates an instance of the saml service provider authenticator blueprint

saml_config - Dict of SAML configuration parameters: (Required)

    'saml_endpoint'     URL of iDP endpoint
    'spid'              Our Service Provider entity id
    'issuer'            IdP's issuer identifier (generally a url)
    'force_reauth'      Force username/password on all iDP visits (def: False)
    'user_attr'         SAML assertion to use for username (def: name_id)
    'auth_duration'     Number of seconds authentication considered valid (def: 3600)
    'assertions'        A list of assertions to collect for attributes (def: None)
    'certificate'        The IdP's public certificate for signing verification
"""

    def __init__(self, saml_config={}, app=None, **kwargs):

        config = saml_config
        
        # no defaults for these:
        self.saml_endpoint = config['saml_endpoint']
        self.saml_audience = config['spid']
        self.saml_issuer = config['issuer']

        # Optional 'ForceAuth' to IdP: 
        # default False
        self.force_reauth = config.get('force_reauth', False)

        # This is SAML claim we use to set 'username': 
        # defalut 'name_id'
        self.attr_uid = config.get('user_attr', 'name_id')
        
        # A list of the SAML claims we will add to the session attribute: 
        # default: [] (none)
        temp_attrs = config.get('assertions', [])
        # Convert these all to lower case...
        self.saml_attrs = [attr.lower() for attr in temp_attrs ]

        # Load IdP (public) certificate - use to validate assertions
        # default: none
        self.saml_certificate = load_pem_x509_certificate(
            config['certificate'].encode('utf-8'), default_backend())

        # how long till we expire the auth? In seconds
        # default: 1 hour
        self.auth_duration = config.get('auth_duration',3600)

        # login hooks - build_attrs_list() must be first
        self.login_hooks = [self.__build_attrs_list]

        # after auth hooks - runs at completion of authentication
        # based on RelayState key
        self.after_auth_hooks = {}

        # Accept responses from IDP initiated requests:
        # default: True
        idp_ok = config.get('idp_ok', True)
        
        # Request ID generator/validator
        self.reqid = ReqID(idpok=idp_ok, ttl=config.get('reqid_life',60))

        # make this a blueprint
        Blueprint.__init__(self, name='samlsp', import_name=__name__)

        # add route for the Assertion Control Service (ACS) endpoint
        self.add_url_rule(
            '/saml/acs',
            methods=['POST'],
            endpoint='authorized',
            view_func=self.finish_saml_login
        )

        if app:
            # app was specified - install ourself as a blueprint
            app.register_blueprint(self,)


    @property
    def is_authenticated(self):
        """
        is_authenticated() (Property)
        - True iff:
            - session has a username
            - && the session has not expired
        """
        try:
            if session['username'] and session['attributes']['_saml']['expires'] >= int(time.time()):
                return True
        except:
            pass   

        return False
    

    @property
    def my_attrs(self):
        """ Return collected assertions for the current session. """

        return session['attributes'] if self.is_authenticated else {'status': 'unauthenticated'}


    def initiate_login(self, force_reauth=False, userhint=None, **kwargs):
        """
        saml.initiate_login(next, force_reauth, userhint, **kwargs) => Response
        
        - Builds and returns a SAMLRequest redirect to iDP to initiate login

        - parameters:
            force_reauth - When true, the IdP is requested to demand a full login
                        (i.e. not an SSO session) (optional)

            userhint - provides the IdP with username hint (optional)

            **kwargs - arguments added to relay state
        """

        # Create a request id
        request_id = self.reqid.new_requestID()

        # encode relay state
        relay_state = urlencode(kwargs, doseq=True) if kwargs else None
        
        # Build the URL with SAMLRequest
        url = get_request_redirect_url(
                saml_endpoint=self.saml_endpoint,
                expected_audience = self.saml_audience,
                acs_url = url_for('samlsp.authorized', _external=True),
                force_reauthentication = self.force_reauth or force_reauth,
                request_id= request_id,
                relay_state= relay_state
            )

        if userhint:
            sep = '&' if '?' in url else '?'
            url = url + sep + 'login_hint=' + userhint
        
        current_app.logger.info(f'SAML: SP created authentication request {request_id}')

        # Redirect user to IdP
        return redirect(url)


    # /saml/acs
    def finish_saml_login(self):
        """             
        Assertion Control Service endpoint (/saml/acs):

            Post to saml._finish_saml_login()

        - invoked as POST by browser on response from IdP
        - SAML response signing verified with IdP cert
        - Issuer verified
        - Claims gathered as attributes and optionally massaged with login_hooks
        - first login hook moves attributes from saml_response to a dict
        - attributes and username set into session object
        - redirect user to 'next' in RelayState or '/' if missing

        """ 
        
        if self.is_authenticated:
            return AppError('ACS invoked for authenticated user')

        relay_state = parse_qs(request.form.get('RelayState',b''))

        try:
            raw_saml_resp = request.form["SAMLResponse"]

            saml_resp = validate_response(
                    data=raw_saml_resp, 
                    certificate = self.saml_certificate, 
                    expected_audience = self.saml_audience
                )
            
        except Exception as e:
            msg = f'SAML: response_validation failed: {str(e)}'
            current_app.logger.info(msg)
            #session.clear()
            return BadRequestError(msg)
            
        current_app.logger.info(f'SAML: ACS received SAMLResponse to {saml_resp.in_response_to}')

        if self.reqid.validate_requestID(saml_resp.in_response_to) is False:
            msg = f'SAML: Invalid Request: "{saml_resp.in_response_to}"'
            current_app.logger.info(msg)

            # If we're not allowing IdP initiated login,issue BadRequest
            return BadRequestError(msg)

        # Validate this was from where we requested it
        if saml_resp.issuer != self.saml_issuer:
            msg = f'SAML: Issuer mismatch: rcvd "{saml_resp.issuer}" expected "{self.saml_issuer}"'
            current_app.logger.info(msg)
            return ConflictError(msg)

        # First login hook will convert saml_resp to dict
        username = saml_resp.name_id
        attrs = saml_resp

        try: 
            # Run all the login hooks.
            for login_hook in self.login_hooks:
                username, attrs = login_hook(username, attrs)

            # set the actual session values
            session['attributes'] = attrs
            session['username'] = username

            current_app.logger.info(f'SAML: User "{saml_resp.name_id}" authenticated')
            
        except Exception as e:
            # failed hooks also fail the login
            msg = f'SAML: login_hooks failed: {str(e)}'
            current_app.logger.info(msg)
            session.clear()
            return ForbiddenError(msg)

        # Quo vidas?
        if 'after' in relay_state:
            key = relay_state['after'][0]
            if key in self.after_auth_hooks:
                return self.after_auth_hooks[key](relayState=relay_state)

        if 'next' in relay_state:
            url = relay_state['next'][0]
        else:
            url = '/'

        current_app.logger.info(f'SAML: Authenticated user {username} redirected to {url}')

        # Redirect back to the url that initiated the login           
        return redirect(url)


    def add_login_hook(self, f):
        """ Add login hook Decorator """
        
        self.login_hooks.append(f)           
        return f


    def require_login(self, f):
        """ Decorator: Require (force) Login if unauthenticated """

        def wrapper(*args, **kwargs):
            if self.is_authenticated:
                return f(*args, **kwargs)
            else:
                return self.initiate_login(next=request.url)
    
        wrapper.__name__ = f.__name__
        return wrapper


    def assert_login(self, f):
        """ Decoratir: return UnauthorizedError if user is not logged in """

        def wrapper(*args, **kwargs):
            if self.is_authenticated:
                return f(*args, **kwargs)
            else:
                return UnauthorizedError()
    
        wrapper.__name__ = f.__name__
        return wrapper


    def __build_attrs_list(self, username, saml_resp):
        """
        Build attribute list from SAML response.
        
        - This needs to be the first login hook
        - creates dict to replace minisaml.SamlResponse
        - items in self.attributes list are saved in the dict
        - sets username to attribute self.attr_uid, or response 'nameid' 
        - adds [_SAML] dict with authentication information
        - returns updated username and atttribute dict
        """

        attrs = {}
        for attr in saml_resp.attributes:
            # we can deliver singles and lists 
            # from what minisaml parsed

            if attr.name in self.saml_attrs:
                
                if len(attr.values)==1:
                    # single value
                    attrs[attr.name] = attr.values[0]

                elif len(attr.values)>1:
                    # list of values 
                    attrs[attr.name] = attr.values

                else:
                    # no values found
                    attrs[attr.name] = None

        # prefered username or use the name_id
        if self.attr_uid in attrs:
            username = attrs[self.attr_uid]
        
        if not 'username' in attrs:
            attrs['username'] = username

        attrs['_saml'] = {
            'name_id': saml_resp.name_id,
            'request_id': saml_resp.in_response_to,
            'issuer': saml_resp.issuer,
            'audience': saml_resp.audience,
            'expires': int(time.time()) + self.auth_duration
        }
            
        return username, attrs

