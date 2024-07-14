"""Defines a class to handle errors returned by an API."""

import typing


class APIError(Exception):
    """Class that encapsules errors returned by an API."""

    @classmethod
    def from_dict(cls, dict_error: typing.Dict):
        return cls(dict_error["code"], str(dict_error.get("message")))

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(code, message)
