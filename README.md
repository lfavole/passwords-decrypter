# passwords-decrypter

Extract passwords from Firefox, Thunderbird and Chromium-based browsers.

## Examples

    # extract all passwords
	passwords-decrypter

    # extract passwords of some browsers
	passwords-decrypter firefox
	passwords-decrypter brave

    # you can use the profile location
	passwords-decrypter C:\Users\Laurent\AppData\Local\Mozilla\Firefox\Profiles\abcdefgh.default-release

## Building

	python -m install -e .[build]
	python -m build
	twine check dist/*
	twine upload dist/* [--repository testpypi]

## Bumping the version

	python -m install -e .[dev]
    bumpver update
