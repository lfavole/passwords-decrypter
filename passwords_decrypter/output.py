import argparse
import csv
import io
import json
import logging
import platform
from dataclasses import dataclass
from subprocess import run
from urllib.parse import urlparse

from .password import Password
from .utils import Exit

logger = logging.getLogger(__name__)
SYSTEM = platform.system()
SYS64 = platform.architecture()[0] == "64bit"
DEFAULT_ENCODING = "utf-8"


@dataclass
class OutputFormat:
    """
    Base class for output formats.
    """

    pwstore: list[Password]
    cmdargs: argparse.Namespace

    def output(self) -> str:
        """
        Return the output of the passwords with the given format.
        """
        raise NotImplementedError


class HumanOutputFormat(OutputFormat):
    """
    Human readable output.
    """

    def output(self):
        ret = ""
        for output in self.pwstore:
            ret += f"""\
Website:   {output.origin}
Username: '{output.username}'
Password: '{output.password}'

"""
        return ret


class JSONEncoder(json.JSONEncoder):
    """
    JSON encoder that supports `Password` objects.
    """

    def default(self, o):
        return o.__dict__


class JSONOutputFormat(OutputFormat):
    """
    JSON output.
    """

    def output(self):
        return json.dumps(self.pwstore, cls=JSONEncoder, indent=2)


class CSVOutputFormat(OutputFormat):
    """
    CSV output.
    """

    def __post_init__(self):
        self.delimiter = self.cmdargs.csv_delimiter
        self.quotechar = self.cmdargs.csv_quotechar
        self.header = self.cmdargs.csv_header

    def output(self):
        f = io.StringIO()
        csv_writer = csv.DictWriter(
            f,
            fieldnames=["url", "user", "password"],
            lineterminator="\n",
            delimiter=self.delimiter,
            quotechar=self.quotechar,
            quoting=csv.QUOTE_ALL,
        )
        if self.header:
            csv_writer.writeheader()

        for output in self.pwstore:
            csv_writer.writerow({"url": output.origin, "user": output.username, "password": output.password})

        f.seek(0)
        return f.read()


class TabularOutputFormat(CSVOutputFormat):
    """
    CSV output delimited with tabs.
    """

    def __post_init__(self):
        self.delimiter = "\t"
        self.quotechar = "'"


class PassOutputFormat(OutputFormat):
    """
    Call a command for each password.
    """

    def __post_init__(self):
        self.prefix = self.cmdargs.pass_prefix
        self.cmd = self.cmdargs.pass_cmd
        self.username_prefix = self.cmdargs.pass_username_prefix
        self.always_with_login = self.cmdargs.pass_always_with_login

    def output(self):
        self.test_pass_cmd()
        to_export = self.preprocess_outputs()
        self.export(to_export)

    def test_pass_cmd(self) -> None:
        """
        Check if pass from passwordstore.org is installed.
        If it is installed but not initialized, initialize it.
        """
        logger.debug("Testing if password store is installed and configured")

        try:
            proc = run([self.cmd, "ls"], capture_output=True, check=True, text=True)
        except FileNotFoundError as err:
            if err.errno == 2:
                logger.error("Password store is not installed and exporting was requested")
                raise Exit(Exit.PASSSTORE_MISSING) from err

            logger.error("Unknown error happened.")
            logger.error("Error was '%s'", err)
            raise Exit(Exit.UNKNOWN_ERROR) from err

        logger.debug("pass returned:\nStdout: %s\nStderr: %s", proc.stdout, proc.stderr)

        if proc.returncode != 0:
            if 'Try "pass init"' in proc.stderr:
                logger.error("Password store was not initialized.")
                logger.error("Initialize the password store manually by using 'pass init'")
                raise Exit(Exit.PASSSTORE_NOT_INIT)

            logger.error("Unknown error happened when running 'pass'.")
            logger.error("Stdout: %s\nStderr: %s", proc.stdout, proc.stderr)
            raise Exit(Exit.UNKNOWN_ERROR)

    def preprocess_outputs(self):
        """
        Prepare the data to be passed to the command.
        """
        # Format of "self.to_export" should be:
        #     {"address": {"login": "password", ...}, ...}
        to_export: dict[str, dict[str, str]] = {}
        for record in self.pwstore:
            url = record.origin
            user = record.username
            passw = record.password

            # Keep track of web-address, username and passwords
            # If more than one username exists for the same web-address
            # the username will be used as name of the file
            address = urlparse(url)

            if address.netloc not in to_export:
                to_export[address.netloc] = {user: passw}
            else:
                to_export[address.netloc][user] = passw

        return to_export

    def export(self, to_export):
        """
        Export given passwords to password store

        Format of "to_export" should be:
            {"address": {"login": "password", ...}, ...}
        """
        logger.info("Exporting credentials to password store")
        if self.prefix:
            prefix = f"{self.prefix}/"
        else:
            prefix = self.prefix

        logger.debug("Using pass prefix '%s'", prefix)

        for address, data in to_export.items():
            for user, passw in data.items():
                # When more than one account exist for the same address, add
                # the login to the password identifier
                if self.always_with_login or len(data) > 1:
                    passname = f"{prefix}{address}/{user}"
                else:
                    passname = f"{prefix}{address}"

                logger.info("Exporting credentials for '%s'", passname)

                data = f"{passw}\n{self.username_prefix}{user}\n"

                logger.debug("Inserting pass '%s' '%s'", passname, data)

                # NOTE --force is used. Existing passwords will be overwritten
                cmd: list[str] = [
                    self.cmd,
                    "insert",
                    "--force",
                    "--multiline",
                    passname,
                ]

                logger.debug("Running command '%s' with stdin '%s'", cmd, data)

                proc = run(cmd, input=data, capture_output=True, check=True, text=True)

                if proc.returncode != 0:
                    logger.error("ERROR: passwordstore exited with non-zero: %s", proc.returncode)
                    logger.error("Stdout: %s\nStderr: %s", proc.stdout, proc.stderr)
                    raise Exit(Exit.PASSSTORE_ERROR)

                logger.debug("Successfully exported '%s'", passname)
