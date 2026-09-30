"""Top-level discovery stays local and preserves subcommand ownership."""
from contextlib import redirect_stderr, redirect_stdout
from importlib import metadata
from io import StringIO
import unittest
from unittest.mock import patch

import offenders
from offenders_help_content import project_information


class CLITests(unittest.TestCase):
    """Prove dispatcher behavior without starting product work."""

    def invoke(self, args):
        """Capture the public entrypoint's status and both output streams."""
        output, error = StringIO(), StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = offenders.main(args)
        return status, output.getvalue(), error.getvalue()

    def test_help_aliases_are_concise_cli_discovery(self):
        """Static help lists invocation surfaces without a second product manual."""
        with patch("offenders_help_content.metadata.version", side_effect=AssertionError("metadata")), \
                patch("offenders_help_content.metadata.metadata", side_effect=AssertionError("metadata")):
            long_form = self.invoke(["--help"])
            self.assertEqual(long_form, self.invoke(["-h"]))
        status, output, error = long_form
        self.assertEqual((status, error), (0, ""))
        self.assertLess(len(output), 1024)
        for fragment in ("offenders", "Open the TUI", "export [OPTIONS]", "geoip COMMAND",
                         "--help", "-h", "--version", "-V", "export --help", "geoip --help"):
            self.assertIn(fragment, output)
        for fragment in ("Enforcement", "Coverage", "RDNS", "Registration", "key bindings",
                         "--period", "--output-dir", "auto on|off"):
            self.assertNotIn(fragment, output)

    def test_version_aliases_share_tui_metadata_authority(self):
        """CLI and TUI use installed metadata rather than a source version constant."""
        with patch("offenders_help_content.metadata.version", return_value="9.8.7+test") as version:
            self.assertEqual(self.invoke(["--version"]), (0, "offenders 9.8.7+test\n", ""))
            self.assertEqual(self.invoke(["-V"]), (0, "offenders 9.8.7+test\n", ""))
            self.assertIn("Version: 9.8.7+test", project_information())
        self.assertEqual(version.call_count, 3)
        version.assert_called_with("offenders")

    def test_source_fallback_and_version_output_are_bounded(self):
        """Missing metadata is factual; malformed local values cannot add lines."""
        with patch("offenders_help_content.metadata.version", side_effect=metadata.PackageNotFoundError), \
                patch("pathlib.Path.read_text", side_effect=AssertionError("source parsing")):
            for flag in ("--version", "-V"):
                self.assertEqual(self.invoke([flag]), (0, "offenders (source development)\n", ""))
        with patch("offenders_help_content.metadata.version", return_value="test\n" * 200):
            status, output, error = self.invoke(["--version"])
        self.assertEqual((status, error), (0, ""))
        self.assertEqual(len(output.splitlines()), 1)
        self.assertLess(len(output), 150)

    def test_discovery_never_enters_product_dispatch(self):
        """App construction and headless dispatch are the product-work boundaries."""
        with patch("offenders.OffendersApp", side_effect=AssertionError("TUI")), \
                patch("offenders_export_cli.main", side_effect=AssertionError("Export")), \
                patch("offenders_geoip_cli.main", side_effect=AssertionError("GeoIP")):
            for flag in ("--help", "-h", "--version", "-V"):
                self.assertEqual(self.invoke([flag])[0], 0)

    def test_subcommands_receive_the_remainder_unchanged(self):
        """Global-looking options after a command belong to that command."""
        for command in ("export", "geoip"):
            for remainder in (["--version"], ["--help"], ["status"], ["--period", "30d"]):
                with self.subTest(command=command, args=remainder), \
                        patch(f"offenders_{command}_cli.main", return_value=7) as dispatch, \
                        patch("offenders.OffendersApp", side_effect=AssertionError("TUI")):
                    self.assertEqual(self.invoke([command, *remainder]), (7, "", ""))
                    dispatch.assert_called_once_with(remainder)

    def test_subcommand_help_retains_argparse_ownership(self):
        """Each existing parser handles its own help before acquisition."""
        for command, option in (("export", "--output-dir"), ("geoip", "{status,update,auto}")):
            output, error = StringIO(), StringIO()
            with self.subTest(command=command), redirect_stdout(output), redirect_stderr(error), \
                    patch("offenders.OffendersApp", side_effect=AssertionError("TUI")), \
                    self.assertRaises(SystemExit) as exit_status:
                offenders.main([command, "--help"])
            self.assertEqual(exit_status.exception.code, 0)
            self.assertIn(f"usage: offenders {command}", output.getvalue())
            self.assertIn(option, output.getvalue())
            self.assertEqual(error.getvalue(), "")

    def test_unsupported_and_non_singleton_flags_remain_errors(self):
        """No trailing argument is ignored and lowercase -v remains reserved."""
        cases = (["-v"], ["--unknown"], ["status"],
                 *([flag, "extra"] for flag in ("--help", "-h", "--version", "-V")))
        with patch("offenders.OffendersApp", side_effect=AssertionError("TUI")), \
                patch("offenders_export_cli.main", side_effect=AssertionError("Export")), \
                patch("offenders_geoip_cli.main", side_effect=AssertionError("GeoIP")):
            for args in cases:
                with self.subTest(args=args):
                    status, output, error = self.invoke(args)
                    self.assertEqual((status, output), (2, ""))
                    self.assertTrue(error.startswith("Usage: offenders"))
                    self.assertLess(len(error), 256)
