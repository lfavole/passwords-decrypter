# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Based on original work from: www.dumpzilla.org

import argparse
import datetime as dt
import locale
import logging
import os
import shlex
import sys
from pathlib import Path

from .chrome import ChromePasswordsExtractor
from .libnss import MozillaInteraction
from .output import (
    CSVOutputFormat,
    HumanOutputFormat,
    JSONOutputFormat,
    OutputFormat,
    PassOutputFormat,
    TabularOutputFormat,
)
from .profiles import get_profile
from .utils import Exit

logger = logging.getLogger(__name__)
DEFAULT_ENCODING = "utf-8"

__version__ = "1.0.0+git"


# From https://bugs.python.org/msg323681
class ConvertChoices(argparse.Action):
    """
    Argparse action that interprets the `choices` argument as a dict
    mapping the user-specified choices values to the resulting option
    values.
    """

    def __init__(self, *args, choices, **kwargs):
        super().__init__(*args, choices=choices.keys(), **kwargs)
        self.mapping = choices

    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, self.mapping[value])


CHROMIUM_BROWSERS = ["brave", "chrome", "chromium", "edge", "opera", "vivaldi"]
MOZILLA_BROWSERS = ["firefox", "thunderbird"]
BROWSERS = CHROMIUM_BROWSERS + MOZILLA_BROWSERS

_OUTPUT_DEFAULT = object()


def parse_sys_args(sys_args: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description="Access Firefox/Thunderbird profiles and decrypt existing passwords")
    parser.add_argument("browser_or_profile", nargs="*", help="Browser to access or profile path")

    format_choices = {
        "human": HumanOutputFormat,
        "json": JSONOutputFormat,
        "csv": CSVOutputFormat,
        "tabular": TabularOutputFormat,
        "pass": PassOutputFormat,
    }

    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        default=_OUTPUT_DEFAULT,
        help="Output file.",
    )
    parser.add_argument(
        "-f",
        "--format",
        action=ConvertChoices,
        choices=format_choices,
        default=HumanOutputFormat,
        help="Format for the output.",
    )
    parser.add_argument(
        "-d",
        "--csv-delimiter",
        action="store",
        default=";",
        help="The delimiter for CSV output.",
    )
    parser.add_argument(
        "-q",
        "--csv-quotechar",
        action="store",
        default='"',
        help="The quote char for CSV output.",
    )
    parser.add_argument(
        "--no-csv-header",
        action="store_false",
        dest="csv_header",
        default=True,
        help="Do not include a header in CSV output.",
    )
    parser.add_argument(
        "--pass-username-prefix",
        action="store",
        default="",
        help=(
            "Export username as is (default), or with the provided format prefix. "
            "For instance 'login: ' for browserpass."
        ),
    )
    parser.add_argument(
        "-p",
        "--pass-prefix",
        action="store",
        default="web",
        help="Folder prefix for export to pass from passwordstore.org (default: %(default)s).",
    )
    parser.add_argument(
        "-m",
        "--pass-cmd",
        action="store",
        default="pass",
        help="Command/path to use when exporting to pass (default: %(default)s).",
    )
    parser.add_argument(
        "--pass-always-with-login",
        action="store_true",
        help="Always save as /<login> (default: only when multiple accounts per domain).",
    )
    parser.add_argument(
        "-n",
        "--no-interactive",
        action="store_false",
        dest="interactive",
        default=True,
        help="Disable interactivity.",
    )
    parser.add_argument(
        "-c",
        "--choice",
        help="The profile to use (starts with 1). If only one profile, defaults to that.",
    )
    parser.add_argument("-l", "--list", action="store_true", help="List profiles and exit.")
    parser.add_argument(
        "-e",
        "--encoding",
        action="store",
        default=DEFAULT_ENCODING,
        help="Override default encoding (%(default)s).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbosity level. Warning on -vv (highest level) user input will be printed on screen.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Display version of passwords-decrypter and exit.",
    )

    args = parser.parse_args(sys_args)

    # understand `\t` as tab character if specified as delimiter.
    if args.csv_delimiter == "\\t":
        args.csv_delimiter = "\t"

    return args


def setup_logging(args) -> None:
    """
    Setup the logging level.
    """
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(format="[%(name)s] %(levelname)s: %(message)s", level=level)


def identify_system_locale() -> str:
    """
    Return the system locale.
    """
    encoding: str | None = locale.getpreferredencoding()

    if encoding is None:
        logger.error(
            "Could not determine which encoding/locale to use for NSS interaction. "
            "This configuration is unsupported.\n"
            "If you are in Linux or MacOS, please search online "
            "how to configure a UTF-8 compatible locale and try again."
        )
        raise Exit(Exit.BAD_LOCALE)

    return encoding


def get_profile_path(path: str | Path):
    if path in BROWSERS:
        # Firefox
        if path == "firefox":
            if sys.platform in ("cygwin", "win32"):
                return Path.home() / "AppData/Roaming/Mozilla/Firefox"
            if sys.platform == "darwin":
                return Path.home() / "Library/Application Support/Firefox"

            ret = Path.home() / ".mozilla/firefox"
            if not ret.exists():
                return Path.home() / "snap/firefox/common/.mozilla/firefox"
            return ret

        # Thunderbird
        if path == "thunderbird":
            if sys.platform in ("cygwin", "win32"):
                return Path.home() / "AppData/Roaming/Thunderbird"
            if sys.platform == "darwin":
                return Path.home() / "Library/Thunderbird"

            ret = Path.home() / ".thunderbird"
            if not ret.exists():
                return Path.home() / "snap/firefox/common/.mozilla/thunderbird"
            return ret

        # Chromium-based
        if sys.platform in ("cygwin", "win32"):
            appdata_local = Path.home() / "AppData/Local"
            appdata_roaming = Path.home() / "AppData/Roaming"
            return {
                "brave": appdata_local / "BraveSoftware/Brave-Browser/User Data",
                "chrome": appdata_local / "Google/Chrome/User Data",
                "chromium": appdata_local / "Chromium/User Data",
                "edge": appdata_local / "Microsoft/Edge/User Data",
                "opera": appdata_roaming / "Opera Software/Opera Stable",
                "vivaldi": appdata_local / "Vivaldi/User Data",
            }[path]

        if sys.platform == "darwin":
            appdata = Path.home() / "Library/Application Support"
            return {
                "brave": appdata / "BraveSoftware/Brave-Browser",
                "chrome": appdata / "Google/Chrome",
                "chromium": appdata / "Chromium",
                "edge": appdata / "Microsoft Edge",
                "opera": appdata / "com.operasoftware.Opera",
                "vivaldi": appdata / "Vivaldi",
            }[path]

        config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        return {
            "brave": config / "BraveSoftware/Brave-Browser",
            "chrome": config / "google-chrome",
            "chromium": config / "chromium",
            "edge": config / "microsoft-edge",
            "opera": config / "opera",
            "vivaldi": config / "vivaldi",
        }[path]

    path = Path(path)
    if not path.exists():
        raise ValueError(f"Incorrect profile name: {path}")

    return path


def _real_main(sys_args: list[str] | None = None) -> None:
    """
    Main entry point.
    """
    sys_args = sys_args or sys.argv[1:]
    if hasattr(sys, "frozen") and not sys_args:
        sys_args = shlex.split(input("Arguments: "))
    args = parse_sys_args(sys_args)

    setup_logging(args)

    global DEFAULT_ENCODING

    if args.encoding != DEFAULT_ENCODING:
        logger.info(
            "Overriding default encoding from '%s' to '%s'",
            DEFAULT_ENCODING,
            args.encoding,
        )

        # Override default encoding if specified by user
        DEFAULT_ENCODING = args.encoding

    logger.info("Running passwords-decrypter version: %s", __version__)
    logger.debug("Parsed commandline arguments: %s", args)
    encodings: list[tuple[str, str]] = [
        ("stdin", sys.stdin.encoding),
        ("stdout", sys.stdout.encoding),
        ("stderr", sys.stderr.encoding),
        ("locale", identify_system_locale()),
    ]

    logger.debug("Running with encodings: %s", (", ".join(": ".join(encoding) for encoding in encodings)))

    for stream, encoding in encodings:
        if encoding.lower() != DEFAULT_ENCODING:
            logger.warning(
                "Running with unsupported encoding '%s': %s - Things are likely to fail from here onwards",
                stream,
                encoding,
            )

    outputs = []

    all_passwords = False
    all_profiles: list[str | Path] = args.browser_or_profile
    if not all_profiles:
        all_profiles = BROWSERS  # type: ignore
        all_passwords = True

    for profile_path in all_profiles:
        profile_path = get_profile_path(profile_path)

        try:
            if any(browser in [part.lower() for part in profile_path.parts] for browser in MOZILLA_BROWSERS):
                # Load Mozilla profile and initialize NSS before asking the user for input
                moz = MozillaInteraction()

                basepath = Path(profile_path).expanduser()

                # Read profiles from profiles.ini in profile folder
                profile = get_profile(basepath, args.interactive, args.choice, args.list)

                # Start NSS for selected profile
                moz.load_profile(profile)
                # Check if profile is password protected and prompt for a password
                moz.authenticate(args.interactive)
                # Decode all passwords
                outputs.extend(moz.decrypt_passwords())

                # Finally shutdown NSS
                moz.unload_profile()
            else:
                chrome = ChromePasswordsExtractor(profile_path)
                outputs.extend(chrome.get_all_passwords())
        except Exit:
            if not all_passwords:
                raise

    # Export passwords into one of many formats
    formatter: OutputFormat = args.format(outputs, args)
    output = formatter.output()
    if args.output is not _OUTPUT_DEFAULT:
        output_file = args.output
        if output_file is None:
            output_file = "passwords_%(date)s.txt"
        logger.debug("Writing to file %s", output_file)
        with open(
            (
                output_file
                % {
                    "date": dt.datetime.now(),
                }
            ).replace(":", "_"),
            "w",
        ) as f:
            f.write(output)

    print(output)


def main():
    """
    Run the main entry point when the file is called.
    """
    try:
        _real_main()
        if hasattr(sys, "frozen"):
            input()
    except KeyboardInterrupt:
        print("Quit.")
        sys.exit(Exit.KEYBOARD_INTERRUPT)
    except Exit as err:
        if hasattr(sys, "frozen"):
            print(f"The program will exit with the status code {err.exitcode}.", file=sys.stderr)
            input()
        sys.exit(err.exitcode)


if __name__ == "__main__":
    main()
