class APIError(Exception):
    """Class that encapsulates errors returned by an API."""

    def __init__(self, message: str, code: str = None):
        self.value = message
        self.message = message
        self.code = code
        super().__init__(message)

    def __str__(self):
        return self.message


class APITimeout(APIError):
    pass
