"""Check release identity and the complete wheel/sdist before publication."""

import argparse
import configparser
from email.parser import BytesParser
from pathlib import Path
import re
import tarfile
import tomllib
import zipfile


def normalized(name):
    """Compare distribution identities using Python's package-name rules."""
    return re.sub(r"[-_.]+", "-", name).lower()


def check_metadata(raw, project, root):
    """Require the built identity, dependencies, license, and long description."""
    metadata = BytesParser().parsebytes(raw)
    assert normalized(metadata["Name"]) == normalized(project["name"])
    assert metadata["Version"] == project["version"]
    assert metadata["Requires-Python"] == project["requires-python"]
    assert set(metadata.get_all("Requires-Dist", [])) == set(project["dependencies"])
    assert metadata["License-Expression"] == project["license"]
    assert metadata.get_all("License-File") == ["LICENSE"]
    assert metadata["Description-Content-Type"] == "text/markdown"
    assert metadata.get_payload().strip() == (root / "README.md").read_text().strip()


def check_wheel(path, project, modules, root):
    """Allow only declared runtime modules and standard distribution metadata."""
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1, "Expected one distribution"
        prefix = metadata_names[0].removesuffix("METADATA")
        allowed = modules | {prefix + name for name in (
            "METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt", "licenses/LICENSE",
        )}
        assert names == allowed, f"Unexpected/missing wheel files: {names ^ allowed}"
        check_metadata(wheel.read(prefix + "METADATA"), project, root)
        assert wheel.read(prefix + "licenses/LICENSE") == (root / "LICENSE").read_bytes()
        entrypoints = configparser.ConfigParser()
        entrypoints.read_string(wheel.read(prefix + "entry_points.txt").decode())
        assert dict(entrypoints["console_scripts"]) == project["scripts"]


def check_sdist(path, project, modules, root):
    """Reject unrelated source payloads while retaining the offline test suite."""
    with tarfile.open(path) as archive:
        files = {member.name.partition("/")[2]: member for member in archive.getmembers()
                 if not member.isdir()}
        required = modules | {"LICENSE", "README.md", "pyproject.toml", "PKG-INFO"}
        assert required <= files.keys(), f"Missing source files: {required - files.keys()}"
        metadata = normalized(project["name"]).replace("-", "_") + ".egg-info/"
        allowed = required | {"setup.cfg"} | {metadata + name for name in (
            "PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt",
            "requires.txt", "top_level.txt",
        )} | {str(path.relative_to(root)) for path in (root / "tests").glob("test_*.py")}
        assert files.keys() <= allowed, f"Unexpected source files: {files.keys() - allowed}"
        assert all(member.isfile() for member in files.values()), "Non-regular source file"
        check_metadata(archive.extractfile(files["PKG-INFO"]).read(), project, root)
        for name in modules | {"LICENSE", "README.md", "pyproject.toml"}:
            assert archive.extractfile(files[name]).read() == (root / name).read_bytes(), name


def main():
    """Fail closed on wrong tags, incomplete module lists, or contaminated artifacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Release tag; must exactly equal v<project.version>")
    parser.add_argument("--tag-only", action="store_true", help="Check identity before building")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text())
    project = config["project"]
    if args.tag is not None:
        assert args.tag == "v" + project["version"], "Release tag/version mismatch"
    if args.tag_only:
        assert args.tag is not None, "--tag-only requires --tag"
        return
    modules = {name + ".py" for name in config["tool"]["setuptools"]["py-modules"]}
    assert modules == {path.name for path in root.glob("offenders*.py")}
    wheels = list((root / "dist").glob("*.whl"))
    sources = list((root / "dist").glob("*.tar.gz"))
    assert len(wheels) == len(sources) == 1, "Expected exactly one wheel and one sdist"
    assert set((root / "dist").iterdir()) == set(wheels + sources), "Unexpected dist payload"
    check_wheel(wheels[0], project, modules, root)
    check_sdist(sources[0], project, modules, root)
    print(f"Validated {project['name']} {project['version']}: wheel and sdist")


if __name__ == "__main__":
    main()
