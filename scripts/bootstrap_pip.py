"""Bootstrap pip from the PSF advisory's hash-pinned wheel before index access.

Run with each build, development, or smoke-test environment's own interpreter.
The hash authenticates the first download even when the old pip CA bundle is stale.
"""
import ssl
import subprocess
import sys


# Keep the URL and digest together: this is the initial download's trust anchor.
PIP_WHEEL = (
    "https://files.pythonhosted.org/packages/3f/06/"
    "3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    "pip-26.2.2-py3-none-any.whl"
    "#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
)


def main():
    """Replace bundled pip without index/dependency access, then audit its bundle."""
    subprocess.run([
        sys.executable, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
        "install", "--no-index", "--no-deps", "--no-cache-dir", "--upgrade", PIP_WHEEL,
    ], check=True)
    import pip
    from pip._vendor import certifi

    if pip.__version__ != "26.2.2":
        raise SystemExit("Expected the hash-pinned pip 26.2.2")
    print(f"Python {sys.version}; pip {pip.__version__}; vendored certifi {certifi.__version__}")
    print(f"OS trust paths: {ssl.get_default_verify_paths()}")
    context = ssl.create_default_context(cafile=certifi.where())
    if any(value == "emSign ECC Root CA - G3" for cert in context.get_ca_certs()
           for rdn in cert["subject"] for key, value in rdn if key == "commonName"):
        raise SystemExit("pip's vendored CA bundle still trusts emSign ECC G3")
    print("pip bundle: emSign ECC G3 absent")


if __name__ == "__main__":
    main()
