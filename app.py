from flask import Flask, session
from flask_session import Session
from FlaskSaml.flask_utils import now

from FlaskSaml import FlaskSP

from config import session_config, saml_config

app = Flask(__name__)
app.config.from_mapping(session_config)
Session(app)

auth = FlaskSP(saml_config=saml_config)
app.register_blueprint(auth)

@app.route('/hello')
def hi():
    user = session['username'] if auth.is_authenticated else 'World'
    return f'Hello {user}!'

@app.route('/inc')
def inc():
    n = session.get('num',0)
    n+=1
    session['num'] = n 
    return f'number is {n}'

@app.route('/login')
@auth.require_login
def forcelogin():
    return f'Hello {session["username"]}!'

@app.route('/sess')
@auth.assert_login
def sess():
    print(f'asdfsdfsd {now()}')
    return session['attributes']

@app.route('/mustbeloggedin')
@auth.assert_login
def must():
    return 'ok - so you are logged in.'

@app.route('/logoff')
def logoff():
    session.clear()
    return 'logged off'
