import logging
import sys
from configparser import ConfigParser
from pathlib import Path
from typing import Optional

from .utils import DEFAULT_ENCODING, Exit

logger = logging.getLogger(__name__)


def get_sections(profiles: ConfigParser):
    """
    Returns hash of profile numbers and profile names.
    """
    sections: dict[str, str] = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
            i += 1
        else:
            continue
    return sections


def print_sections(sections, text_io_wrapper=sys.stderr):
    """
    Prints all available sections to a TextIOWrapper (defaults to sys.stderr).
    """
    for i in sorted(sections):
        text_io_wrapper.write(f"{i} -> {sections[i]}\n")
    text_io_wrapper.flush()


def ask_section(sections: dict[str, str]):
    """
    Prompt the user which profile should be used for decryption.
    """
    # Do not ask for choice if user already gave one
    choice = "ASK"
    while choice not in sections:
        sys.stderr.write("Select the Mozilla profile you wish to decrypt\n")
        print_sections(sections)
        try:
            choice = input()
        except EOFError as err:
            logger.error("Could not read Choice, got EOF")
            raise Exit(Exit.READ_GOT_EOF) from err

    try:
        final_choice = sections[choice]
    except KeyError as err:
        logger.error("Profile No. %s does not exist!", choice)
        raise Exit(Exit.NO_SUCH_PROFILE) from err

    logger.debug("Profile selection matched %s", final_choice)

    return final_choice


def read_profiles(basepath: Path):
    """
    Parse Firefox profiles in provided location.
    If list_profiles is true, will exit after listing available profiles.
    """
    profileini = basepath / "profiles.ini"

    logger.debug("Reading profiles from %s", profileini)

    if not profileini.is_file():
        logger.warning("profile.ini not found in %s", basepath)
        raise Exit(Exit.MISSING_PROFILEINI)

    # Read profiles from Firefox profile folder
    profiles = ConfigParser()
    profiles.read(profileini, encoding=DEFAULT_ENCODING)

    logger.debug("Read profiles %s", profiles.sections())

    return profiles


def get_profile(basepath: Path, interactive: bool, choice: Optional[str], list_profiles: bool):
    """
    Select profile to use by either reading profiles.ini or assuming given
    path is already a profile.
    If interactive is false, will not try to ask which profile to decrypt.
    choice contains the choice the user gave us as an CLI arg.
    If list_profiles is true will exits after listing all available profiles.
    """
    try:
        profiles: ConfigParser = read_profiles(basepath)
    except Exit as err:
        if err.exitcode == Exit.MISSING_PROFILEINI:
            logger.warning("Continuing and assuming '%s' is a profile location", basepath)
            profile = basepath

            if list_profiles:
                logger.error("Listing single profiles not permitted.")
                raise

            if not profile.is_dir():
                logger.error("Profile location '%s' is not a directory", profile)
                raise
        else:
            raise
    else:
        sections = get_sections(profiles)

        if list_profiles:
            logger.debug("Listing available profiles...")
            print_sections(sections, sys.stdout)
            raise Exit(Exit.CLEAN)

        if len(sections) == 1:
            section = sections["1"]

        elif choice is not None:
            try:
                section = sections[choice]
            except KeyError as err:
                logger.error("Profile No. %s does not exist!", choice)
                raise Exit(Exit.NO_SUCH_PROFILE) from err

        elif not interactive:
            logger.error(
                "Don't know which profile to decrypt. "
                "We are in non-interactive mode and -c/--choice wasn't specified."
            )
            raise Exit(Exit.MISSING_CHOICE)

        else:
            # Ask user which profile to open
            section = ask_section(sections)

        profile = basepath / section

        if not profile.is_dir():
            logger.error(
                "Profile location '%s' is not a directory. Has profiles.ini been tampered with?",
                profile,
            )
            raise Exit(Exit.BAD_PROFILEINI)

    return profile
