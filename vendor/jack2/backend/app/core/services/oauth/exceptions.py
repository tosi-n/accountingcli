from app.core.exceptions import JackBaseException


class OAuthIntegrationBaseException(JackBaseException):
    http_status_code = 400
    message = "Integration failed"


class OAuthIntegrationLoginFailedException(OAuthIntegrationBaseException):
    message = "Integration login failed"


class OAuthIntegrationLoginRequiredException(OAuthIntegrationBaseException):
    message = "Integration login required"


class OAuthIntegrationRevokeTokenException(OAuthIntegrationBaseException):
    http_status_code = 400
    message = "Integration token revoke failed"


class OAuthIntegrationValidationFailed(OAuthIntegrationBaseException):
    pass


class OAuthIntegrationAPICallFailed(OAuthIntegrationBaseException):
    pass


class OAuthIntegrationTooManyRequestsException(OAuthIntegrationBaseException):
    message = "Too many requests"
    http_status_code = 429

    def __init__(self, response):
        super().__init__()
        self.response = response
