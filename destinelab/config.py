import logging

IAM_URL = "https://auth.destine.eu"
CLIENT_ID = "dedl-hda"
REALM = "desp"
SERVICE_URL = "https://hda.data.destination-earth.eu/stac"

DEDL_TOKEN_URL = "https://identity.data.destination-earth.eu/auth/realms/dedl/protocol/openid-connect/token"
DEDL_CLIENT_ID = "hda-public"
DEDL_AUDIENCE = "hda-public"
DEDL_KEYCLOAK_SERVER_URL = "https://identity.data.destination-earth.eu/auth/"
DEDL_KEYCLOAK_REALM = "dedl"

DEFAULT_TIMEOUT_SECONDS = 15


PACKAGE_LOGGER_NAME = "destinelab"


def configure_logging(level=logging.WARNING, handler=None):
	"""Configure package logging level and handler for DestinE auth helpers.

	By default, a ``StreamHandler`` is used if no handler is provided.
	"""

	logger = logging.getLogger(PACKAGE_LOGGER_NAME)
	logger.setLevel(level)

	if handler is None:
		handler = logging.StreamHandler()

	if not logger.handlers:
		logger.addHandler(handler)

	return logger