from pathlib import Path

from PyInstaller.__main__ import run

BASE_PATH = Path(__file__).parent


exclusions = [
    "cffi",
    "distutils",
    "email",
    "heapq",
    "multiprocessing",
    "numpy",
    "pygments",
    "PIL",
    "setuptools",
    "statistics",
    "unittest",
    "urllib.request",
    "xml",
    "xmlrpc",
]
exclusions_args = []
for excl in exclusions:
    exclusions_args.append("--exclude-module")
    exclusions_args.append(excl)

run(
    [
        "--onefile",
        "--name",
        "passwords-decrypter",
        *exclusions_args,
        str(BASE_PATH / "passwords_decrypter/__main__.py"),
    ]
)
