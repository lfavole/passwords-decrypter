import datetime as dt
from dataclasses import dataclass


@dataclass
class Password:
    """
    A password with username and additional data.
    """

    username: str
    password: str
    username_field: str = ""
    password_field: str = ""
    origin: str = ""
    action: str = ""
    created: dt.datetime | None = None
    edited: dt.datetime | None = None
    used: dt.datetime | None = None
    used_times: int | None = None
    enctype: int | None = None
