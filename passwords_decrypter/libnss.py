import ctypes as ct
import logging
import os
import shutil
import sys
from base64 import b64decode
from getpass import getpass
from pathlib import Path

from .credentials import Credentials, JsonCredentials, SqliteCredentials
from .password import Password
from .utils import DEFAULT_ENCODING, SYSTEM, Exit, NotFoundError

logger = logging.getLogger(__name__)


def ask_password(profile: str, interactive: bool) -> str:
    """
    Prompt for profile password.
    """
    passmsg = f"\nMaster Password for profile {profile}: "

    if sys.stdin.isatty() and interactive:
        return getpass(passmsg)

    sys.stderr.write("Reading Master password from standard input:\n")
    sys.stderr.flush()
    # Ability to read the password from stdin (echo "pass" | ./firefox_...)
    return sys.stdin.readline().rstrip("\n")


def find_nss(locations: list[Path], nssname: str) -> ct.CDLL:
    """
    Locate nss is one of the many possible locations.
    """
    fail_errors = []
    workdir = ""

    chdir_os = ("Windows", "Darwin")

    for loc in locations:
        nsslib = loc / nssname
        if not nsslib.exists():
            logger.debug("NSS library %s doesn't exist", nsslib)
            continue
        logger.debug("Loading NSS library from %s", nsslib)

        if SYSTEM in chdir_os:
            # On windows in order to find DLLs referenced by nss3.dll
            # we need to have those locations on PATH
            os.environ["PATH"] = f"{loc};{os.environ['PATH']}"
            logger.debug("PATH is now %s", os.environ["PATH"])
            # However this doesn't seem to work on all setups and needs to be
            # set before starting python so as a workaround we chdir to
            # Firefox's nss3.dll/libnss3.dylib location
            if not loc.is_dir():
                # No point in trying to load from paths that don't exist
                continue

            workdir = os.getcwd()
            os.chdir(loc)

        try:
            nss = ct.CDLL(str(nsslib))
        except OSError as err:
            fail_errors.append((nsslib, err))
        else:
            logger.debug("Loaded NSS library from %s", nsslib)
            return nss
        finally:
            if SYSTEM in chdir_os:
                # Restore workdir changed above
                os.chdir(workdir)

    logger.error(
        "Couldn't load '%s'. This library is essential to interact with your Mozilla profile.",
        nssname,
    )
    logger.error(
        "If you are seeing this error please perform a system-wide search "
        "for '%s' and file a bug report indicating any location found. Thanks!",
        nssname,
    )
    logger.error(
        "Alternatively you can try launching firefox_decrypt from the location where you found '%s'. "
        "That is 'cd' or 'chdir' to that location and run firefox_decrypt from there.",
        nssname,
    )

    logger.error("Please also include the following on any bug report. Errors seen while searching/loading NSS:")

    for target, error in fail_errors:
        logger.error("Error when loading %s was %s", target, error)

    raise Exit(Exit.FAIL_LOCATE_NSS)


def load_libnss():
    """
    Load libnss into python using the CDLL interface.
    """
    locations: list[str | Path]
    if SYSTEM == "Windows":
        nssname = "nss3.dll"
        locations = [
            "",  # Current directory or system lib finder
            Path.home() / "AppData/Local/Mozilla Firefox",
            Path.home() / "AppData/Local/Firefox Developer Edition",
            Path.home() / "AppData/Local/Mozilla Thunderbird",
            Path.home() / "AppData/Local/Nightly",
            Path.home() / "AppData/Local/SeaMonkey",
            Path.home() / "AppData/Local/Waterfox",
            "C:/Program Files/Mozilla Firefox",
            "C:/Program Files/Firefox Developer Edition",
            "C:/Program Files/Mozilla Thunderbird",
            "C:/Program Files/Nightly",
            "C:/Program Files/SeaMonkey",
            "C:/Program Files/Waterfox",
            "C:/Program Files (x86)/Mozilla Firefox",
            "C:/Program Files (x86)/Firefox Developer Edition",
            "C:/Program Files (x86)/Mozilla Thunderbird",
            "C:/Program Files (x86)/Nightly",
            "C:/Program Files (x86)/SeaMonkey",
            "C:/Program Files (x86)/Waterfox",
        ]

        # If either of the supported software is in PATH try to use it
        software = ["firefox", "thunderbird", "waterfox", "seamonkey"]
        for binary in software:
            location = shutil.which(binary)
            if location is not None:
                locations.append(Path(location).parent / nssname)

    elif SYSTEM == "Darwin":
        nssname = "libnss3.dylib"
        locations = [
            "",  # Current directory or system lib finder
            "/usr/local/lib/nss",
            "/usr/local/lib",
            "/opt/local/lib/nss",
            "/sw/lib/firefox",
            "/sw/lib/mozilla",
            "/usr/local/opt/nss/lib",  # nss installed with Brew on Darwin
            "/opt/pkg/lib/nss",  # installed via pkgsrc
            "/Applications/Firefox.app/Contents/MacOS",  # default manual install location
            "/Applications/Thunderbird.app/Contents/MacOS",
            "/Applications/SeaMonkey.app/Contents/MacOS",
            "/Applications/Waterfox.app/Contents/MacOS",
        ]

    else:
        nssname = "libnss3.so"
        locations = [
            "",  # Current directory or system lib finder
            "/usr/lib",
            "/usr/lib/firefox",
            "/usr/lib/nss",
            "/usr/lib/thunderbird",
            "/usr/lib32",
            "/usr/lib32/firefox",
            "/usr/lib32/nss",
            "/usr/lib32/thunderbird",
            "/usr/lib64",
            "/usr/lib64/firefox",
            "/usr/lib64/nss",
            "/usr/lib64/thunderbird",
            "/usr/local/lib",
            "/usr/local/lib/firefox",
            "/usr/local/lib/nss",
            "/usr/local/lib/thunderbird",
            "/opt/local/lib",
            "/opt/local/lib/firefox",
            "/opt/local/lib/nss",
            "/opt/local/lib/thunderbird",
            Path.home() / ".nix-profile/lib",
        ]

    # If this succeeds libnss was loaded
    return find_nss([Path(loc) for loc in locations], nssname)


class c_char_p_fromstr(ct.c_char_p):  # pylint: disable=C0103
    """
    ctypes char_p override that handles encoding str to bytes.
    """

    def from_param(self):
        """
        Transparently handles the encoding of data.
        """
        return self.encode(DEFAULT_ENCODING)  # type: ignore


class NSSProxy:
    """
    Class that interacts with libnss.
    """

    class SECItem(ct.Structure):
        """
        struct needed to interact with libnss.
        """

        _fields_ = [
            ("type", ct.c_uint),
            ("data", ct.c_char_p),  # actually: unsigned char *
            ("len", ct.c_uint),
        ]

        def decode_data(self):
            """
            Transparently handles the decoding of data.
            """
            _bytes = ct.string_at(self.data, self.len)
            return _bytes.decode(DEFAULT_ENCODING)

    class PK11SlotInfo(ct.Structure):
        """
        Opaque structure representing a logical PKCS slot.
        """

    def __init__(self):
        # pylint: disable=C0103

        # Locate libnss and try loading it
        self.libnss = load_libnss()

        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self.NSS_Init = self._get_ctypes(ct.c_int, "NSS_Init", c_char_p_fromstr)
        self.NSS_Shutdown = self._get_ctypes(ct.c_int, "NSS_Shutdown")
        self.PK11_GetInternalKeySlot = self._get_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self.PK11_FreeSlot = self._get_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self.PK11_NeedLogin = self._get_ctypes(ct.c_int, "PK11_NeedLogin", SlotInfoPtr)
        self.PK11_CheckUserPassword = self._get_ctypes(
            ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, c_char_p_fromstr
        )
        self.PK11SDR_Decrypt = self._get_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self.SECITEM_ZfreeItem = self._get_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)

        # for error handling
        self.PORT_GetError = self._get_ctypes(ct.c_int, "PORT_GetError")
        self.PR_ErrorToName = self._get_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self.PR_ErrorToString = self._get_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _get_ctypes(self, restype, name, *argtypes):
        """
        Get input/output types on libnss C functions for automatic type casting.
        """
        res = getattr(self.libnss, name)
        res.argtypes = argtypes
        res.restype = restype

        # Transparently handle decoding to string when returning a c_char_p
        if restype == ct.c_char_p:

            def _decode(result, _func, *_args):
                return result.decode(DEFAULT_ENCODING)

            res.errcheck = _decode

        return res

    def initialize(self, profile: Path):
        """
        Initialize NSS with the given profile.
        """
        # The sql: prefix ensures compatibility with both
        # Berkley DB (cert8) and Sqlite (cert9) dbs
        profile_path = f"sql:{profile}"
        logger.debug("Initializing NSS with profile '%s'", profile_path)
        err_status: int = self.NSS_Init(profile_path)
        logger.debug("Initializing NSS returned %s", err_status)

        if err_status:
            self.handle_error(
                Exit.FAIL_INIT_NSS,
                "Couldn't initialize NSS, maybe '%s' is not a valid profile?",
                profile,
            )

    def shutdown(self):
        """
        Shutdown NSS when finished.
        """
        err_status: int = self.NSS_Shutdown()

        if err_status:
            self.handle_error(
                Exit.FAIL_SHUTDOWN_NSS,
                "Couldn't shutdown current NSS profile",
            )

    def authenticate(self, profile, interactive):
        """
        Unlocks the profile if necessary, in which case a password
        will prompted to the user.
        """
        logger.debug("Retrieving internal key slot")
        keyslot = self.PK11_GetInternalKeySlot()

        logger.debug("Internal key slot %s", keyslot)
        if not keyslot:
            self.handle_error(
                Exit.FAIL_NSS_KEYSLOT,
                "Failed to retrieve internal KeySlot",
            )

        try:
            if self.PK11_NeedLogin(keyslot):
                password = ask_password(profile, interactive)

                logger.debug("Authenticating with password '%s'", password)
                err_status: int = self.PK11_CheckUserPassword(keyslot, password)

                logger.debug("Checking user password returned %s", err_status)

                if err_status:
                    self.handle_error(Exit.BAD_MASTER_PASSWORD, "Master password is not correct")

            else:
                logger.info("No Master Password found - no authentication needed")
        finally:
            # Avoid leaking PK11KeySlot
            self.PK11_FreeSlot(keyslot)

    def handle_error(self, exitcode: int, *logerror):
        """
        If an error happens in libnss, handle it and print some debug information.
        """
        if logerror:
            logger.error(*logerror)
        else:
            logger.debug("Error during a call to NSS library, trying to obtain error info")

        code = self.PORT_GetError()
        name = self.PR_ErrorToName(code)
        name = "NULL" if name is None else name
        # 0 is the default language (localization related)
        text = self.PR_ErrorToString(code, 0)

        logger.debug("%s: %s", name, text)

        raise Exit(exitcode)

    def decrypt(self, data64: str):
        """
        Decrypt a password.
        """
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)

        err_status: int = self.PK11SDR_Decrypt(inp, out, None)
        logger.debug("Decryption of data returned %s", err_status)
        try:
            if err_status:  # -1 means password failed, other status are unknown
                self.handle_error(
                    Exit.NEED_MASTER_PASSWORD,
                    "Password decryption failed. Passwords protected by a Master Password!",
                )

            res = out.decode_data()
        finally:
            # Avoid leaking SECItem
            self.SECITEM_ZfreeItem(out, 0)

        return res


class MozillaInteraction:
    """
    Abstraction interface to Mozilla profile and lib NSS.
    """

    def __init__(self):
        self.profile: Path | None = None
        self.proxy = NSSProxy()

    def load_profile(self, profile: Path):
        """
        Initialize the NSS library and profile.
        """
        self.profile = profile
        self.proxy.initialize(self.profile)

    def authenticate(self, interactive):
        """
        Authenticate the the current profile is protected by a master password,
        prompt the user and unlock the profile.
        """
        self.proxy.authenticate(self.profile, interactive)

    def unload_profile(self):
        """
        Shutdown NSS and deactivate current profile.
        """
        self.proxy.shutdown()

    def decrypt_passwords(self):
        """
        Decrypt requested profile using the provided password.
        Returns all passwords in a list of dicts.
        """
        credentials: Credentials = self.obtain_credentials()

        logger.info("Decrypting credentials")
        outputs: list[Password] = []

        for password in credentials:
            # enctype informs if passwords need to be decrypted
            if password.enctype:
                try:
                    logger.debug("Decrypting username data '%s'", password.username)
                    password.username = self.proxy.decrypt(password.username)
                    logger.debug("Decrypting password data '%s'", password.password)
                    password.password = self.proxy.decrypt(password.password)
                except (TypeError, ValueError) as err:
                    logger.warning(
                        "Failed to decode username or password for entry from URL %s",
                        password.origin,
                    )
                    logger.exception(err)
                    continue

            logger.debug(
                "Decoded username '%s' and password '%s' for website '%s'",
                password.username,
                password.password,
                password.origin,
            )

            outputs.append(password)

        if not outputs:
            logger.warning("No passwords found in selected profile")

        # Close credential handles (SQL)
        credentials.done()

        return outputs

    def obtain_credentials(self) -> Credentials:
        """
        Figure out which of the 2 possible backend credential engines is available.
        """
        if self.profile is None:
            raise RuntimeError("No profile loaded!")

        try:
            credentials = JsonCredentials(self.profile)
        except NotFoundError:
            try:
                credentials = SqliteCredentials(self.profile)
            except NotFoundError as err:
                logger.error("Couldn't find credentials file (logins.json or signons.sqlite).")
                raise Exit(Exit.MISSING_SECRETS) from err

        return credentials
