import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .password import Password
from .utils import Exit, NotFoundError

logger = logging.getLogger(__name__)


@dataclass
class Credentials:
    """
    Base credentials backend manager.
    """

    db: Path

    def __post_init__(self):
        logger.debug("Database location: %s", self.db)
        if not os.path.isfile(self.db):
            raise NotFoundError(f"ERROR - {self.db} database not found\n")

        logger.info("Using %s for credentials.", self.db)

    def __iter__(self) -> Iterator[Password]:
        """
        Iterate over the credentials.
        """
        raise NotImplementedError

    def done(self):
        """
        Override this method if the credentials subclass needs to do any
        action after interaction.
        """


class SqliteCredentials(Credentials):
    """
    SQLite credentials backend manager.
    """

    def __init__(self, profile: Path):
        super().__init__(profile / "signons.sqlite")

        self.conn = sqlite3.connect(self.db)
        self.cursor = self.conn.cursor()

    def __iter__(self) -> Iterator[Password]:
        logger.debug("Reading password database in SQLite format")
        self.cursor.execute(
            "SELECT encryptedUsername, encryptedPassword, usernameField, passwordField, hostname, "
            "formSubmitURL, timeCreated, timePasswordChanged, timeLastUsed, timesUsed, encType FROM moz_logins"
        )
        for i in self.cursor:
            yield Password(*i)

    def done(self):
        """
        Close the sqlite cursor and database connection.
        """
        super().done()

        self.cursor.close()
        self.conn.close()


class JsonCredentials(Credentials):
    """
    JSON credentials backend manager.
    """

    def __init__(self, profile: Path):
        super().__init__(profile / "logins.json")

    def __iter__(self) -> Iterator[Password]:
        with open(self.db) as f:
            logger.debug("Reading password database in JSON format")
            data = json.load(f)

            try:
                logins = data["logins"]
            except Exception as exc:
                logger.error("Unrecognized format in %s", self.db)
                raise Exit(Exit.BAD_SECRETS) from exc

            for i in logins:
                yield Password(
                    i["encryptedUsername"],
                    i["encryptedPassword"],
                    i["usernameField"],
                    i["passwordField"],
                    i["hostname"],
                    i["formSubmitURL"],
                    i["timeCreated"],
                    i["timePasswordChanged"],
                    i["timeLastUsed"],
                    i["timesUsed"],
                    i["encType"],
                )
