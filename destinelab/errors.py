class AuthError(Exception):
    pass


class InvalidCredentialsError(AuthError):
    pass


class OTPRequiredError(AuthError):
    pass


class AuthNetworkError(AuthError):
    pass


class TokenExchangeError(AuthError):
    pass