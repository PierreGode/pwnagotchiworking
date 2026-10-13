#import _thread
import threading
import secrets
import logging
import os

# https://stackoverflow.com/questions/14888799/disable-console-messages-in-flask-server
logging.getLogger('werkzeug').setLevel(logging.ERROR)
os.environ['WERKZEUG_RUN_MAIN'] = 'false'

from flask import Flask
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

from pwnagotchi.ui.web.handler import Handler

# Path where the Flask secret key is persisted across web-server restarts.
_SECRET_KEY_PATH = '/etc/pwnagotchi/.flask_secret'


def _persistent_secret_key():
    """Return a Flask secret key that is stable across web-server restarts.

    Generating a fresh random key on every start invalidates all existing
    sessions, so the CSRF token baked into any already-open page (browser tab
    or a kiosk display) no longer validates after a restart or a mode swap,
    producing "Bad Request: The CSRF session token is missing". Persisting the
    key removes that whole class of intermittent failure. Falls back to an
    ephemeral key only if the file can neither be read nor written.
    """
    try:
        with open(_SECRET_KEY_PATH, 'r') as fp:
            key = fp.read().strip()
        if key:
            return key
    except OSError:
        pass

    key = secrets.token_urlsafe(256)
    try:
        os.makedirs(os.path.dirname(_SECRET_KEY_PATH), exist_ok=True)
        with open(_SECRET_KEY_PATH, 'w') as fp:
            fp.write(key)
        os.chmod(_SECRET_KEY_PATH, 0o600)
    except OSError:
        logging.warning("Could not persist Flask secret key; sessions will reset on restart")
    return key


class Server:
    def __init__(self, agent, config):
        self._config = config['web']
        self._enabled = self._config['enabled']
        self._port = self._config['port']
        self._address = self._config['address']
        self._origin = None
        self._agent = agent
        if 'origin' in self._config:
            self._origin = self._config['origin']

        if self._enabled:
            #_thread.start_new_thread(self._http_serve, ())
            logging.info("Starting WebServer thread")
            self._thread = threading.Thread(target=self._http_serve, name="WebServer", daemon = True).start()

    def _http_serve(self):
        if self._address is not None:
            web_path = os.path.dirname(os.path.realpath(__file__))

            app = Flask(__name__,
                        static_url_path='',
                        static_folder=os.path.join(web_path, 'static'),
                        template_folder=os.path.join(web_path, 'templates'))

            app.secret_key = _persistent_secret_key()

            if self._origin:
                CORS(app, resources={r"*": {"origins": self._origin}})

            CSRFProtect(app)
            Handler(self._config, self._agent, app)

            formatServerIpAddress = '[::]' if self._address == '::' else self._address
            logging.info("web ui available at http://%s:%d/" % (formatServerIpAddress, self._port))

            app.run(host=self._address, port=self._port)
        else:
            logging.info("could not get ip of usb0, video server not starting")
