"""Offline inspector navigation, asynchronous snapshots, and bounded tools."""
import asyncio
import threading
import unittest
from dataclasses import replace
from unittest.mock import patch

from textual.widgets import DataTable, Static
from ipwhois.exceptions import HTTPLookupError

from offenders import OffendersApp
from offenders_fail2ban import JailStatus
from offenders_geoip import Enrichment, LookupResult
from offenders_ip import project_ip
from offenders_ip_ui import CommandOutputModal, IPInspectorScreen, ip_details
from offenders_jail_ui import JailDetailScreen
from offenders_report import Offender
from test_ip import NOW, UNMAPPED, report
from offenders_events import BanEvent

IP = "2001:db8::1"


def snapshot():
    """Include historical-only, shared, and current-only jail identities."""
    events = [BanEvent(NOW, jail, IP, "") for jail in ["old", "old", "shared"]]
    statuses = [JailStatus(jail, 0, 0, 1, 1, (IP,)) for jail in ("shared", "live")]
    return replace(report(events, statuses, [Offender(IP, 3, "", "", "", UNMAPPED)]), period="7d")


class DetailTests(unittest.TestCase):
    """Snapshot details preserve literal enrichment states."""

    def test_complete_details_and_enrichment_states(self):
        """Mapped, healthy-unmapped, and unavailable stay distinct in literal text."""
        p = project_ip(snapshot(), IP)
        text = ip_details(p).plain
        for value in (IP, "7d", str(NOW), "Historical bans: 3", "Distinct historical jails: 2",
                      "Currently banned: Yes", "Current jails: shared, live", "Country: unmapped"):
            self.assertIn(value, text)
        enriched = replace(p, enrichment=Enrichment(LookupResult("mapped", "GR"),
                           LookupResult("mapped", "123", "[red]Org")))
        self.assertIn("Organization: [red]Org", ip_details(enriched).plain)
        self.assertIn("Country: mapped — GR", ip_details(enriched).plain)
        empty = project_ip(report(), IP, lookup=lambda ip: Enrichment(
            LookupResult("unavailable", detail="missing"), LookupResult("unmapped")))
        for value in ("First seen: Unavailable", "Last seen: Unavailable", "Country: unavailable",
                      "ASN: unmapped", "Historical bans: 0", "Currently banned: No"):
            self.assertIn(value, ip_details(empty).plain)


class InspectorTests(unittest.IsolatedAsyncioTestCase):
    """Use actual Textual screens with only report/host seams replaced."""

    async def test_navigation_refresh_period_copy_and_tools(self):
        """Round trips retain screen instances and failed refresh keeps the snapshot."""
        source = snapshot()
        ui_thread = threading.get_ident()
        calls = []
        def runner(ip, tool):
            """Record actual worker execution without performing network I/O."""
            calls.append((ip, tool, threading.get_ident()))
            return "[red]literal answer"
        with patch("offenders.build_report", return_value=source) as build, \
             patch("offenders_geoip_ui.read_state", return_value={}), \
             patch("offenders_ip_ui.lookup_output", side_effect=runner), \
             patch("offenders_ip_ui.project_ip", side_effect=lambda r, ip: project_ip(
                 r, ip, lookup=lambda address: UNMAPPED)):
            app = OffendersApp()
            async with app.run_test(size=(110, 45)) as pilot:
                await app.workers.wait_for_complete()
                top = app.query_one("#offenders", DataTable)
                top.focus()
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                inspector = app.screen
                self.assertIsInstance(inspector, IPInspectorScreen)
                self.assertEqual(inspector.ip, IP)
                jails = inspector.query_one("#ip-jails", DataTable)
                self.assertEqual([jails.get_row_at(i) for i in range(3)],
                                 [["old", "2", "No"], ["shared", "1", "Yes"], ["live", "0", "Yes"]])
                jails.focus()
                with patch.object(app, "_copy_text") as copy:
                    await pilot.press("c", "x")
                    self.assertEqual(copy.call_count, 2)
                    copy.assert_called_with("old\t2\tNo")
                await pilot.press("enter")
                jail = app.screen
                self.assertIsInstance(jail, JailDetailScreen)
                self.assertEqual(jail.jail, "old")
                history = jail.query_one("#jail-history", DataTable)
                history.focus()
                await pilot.press("e", "down", "enter")
                await app.workers.wait_for_complete()
                self.assertEqual(app.screen.ip, IP)
                await pilot.press("escape")
                self.assertIs(app.screen, jail)
                self.assertEqual(jail.history_level, 1)
                self.assertIs(app.focused, history)
                self.assertEqual(history.cursor_row, 1)
                await pilot.press("q")
                self.assertIs(app.screen, inspector)
                self.assertIs(app.focused, jails)
                jails.move_cursor(row=2)
                await pilot.press("enter")
                self.assertEqual(app.screen.jail, "live")
                # An inspector covered by another screen still receives successful reports.
                build.return_value = replace(source, events=[], jail_statuses=[], top_offenders=[])
                await pilot.press("r")
                await app.workers.wait_for_complete()
                await pilot.press("escape")
                self.assertIs(app.screen, inspector)
                self.assertEqual(inspector.projection.total_bans, 0)
                self.assertFalse(inspector.projection.currently_banned)
                build.return_value = replace(source, period="30d", top_offenders=[
                    Offender("192.0.2.8", 9, "", "", "", UNMAPPED), *source.top_offenders])
                await pilot.press("p")
                await app.workers.wait_for_complete()
                self.assertEqual(inspector.projection.period, "30d")
                before = inspector.projection
                build.side_effect = RuntimeError("offline failure")
                await pilot.press("r")
                await app.workers.wait_for_complete()
                self.assertIs(inspector.projection, before)
                for key, tool in (("w", "registration"), ("d", "rdns")):
                    await pilot.press(key)
                    await app.workers.wait_for_complete()
                    modal = app.screen
                    self.assertIsInstance(modal, CommandOutputModal)
                    self.assertEqual(modal.tool, tool)
                    self.assertEqual(modal._output_text, "[red]literal answer")
                    self.assertEqual("".join(line.text for line in modal.query_one("#cmd-out").lines), modal._output_text)
                    with patch.object(app, "copy_to_clipboard") as copy:
                        await pilot.press("c")
                        copy.assert_called_once_with(modal._output_text)
                    with patch.object(app, "copy_to_clipboard", side_effect=RuntimeError), patch("builtins.print") as output:
                        await pilot.press("c")
                        output.assert_called_once_with(modal._output_text)
                    self.assertEqual(calls[-1][:2], (IP, tool))
                    self.assertNotEqual(calls[-1][2], ui_thread)
                    await pilot.press("q")
                await pilot.press("escape")
                self.assertIs(app.focused, top)
                self.assertEqual(top.get_row_at(top.cursor_row)[1], IP)
                self.assertEqual(top.cursor_row, 1)
                for table, key in ((top, "w"), (app.query_one("#last-bans", DataTable), "d")):
                    table.focus()
                    await pilot.press(key)
                    await app.workers.wait_for_complete()
                    self.assertIsInstance(app.screen, CommandOutputModal)
                    self.assertEqual(app.screen.tool, "registration" if key == "w" else "rdns")
                    await pilot.press("escape")
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertEqual(app.screen.ip, IP)
                await pilot.press("escape")
                self.assertEqual(build.call_count, 4)

    async def test_provider_failure_is_literal_copyable_result(self):
        """A real backend failure completes normally and retains action wording."""
        with patch("offenders.build_report", return_value=snapshot()), \
             patch("offenders_geoip_ui.read_state", return_value={}), \
             patch("offenders_lookup.IPWhois") as provider:
            provider.return_value.lookup_rdap.side_effect = HTTPLookupError("offline")
            app = OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                for screen_type in (OffendersApp, IPInspectorScreen):
                    self.assertIn(("w", "registration", "Registration"), screen_type.BINDINGS)
                    self.assertIn(("d", "rdns", "RDNS"), screen_type.BINDINGS)
                modal = CommandOutputModal("8.8.8.8", "registration")
                await app.push_screen(modal)
                await app.workers.wait_for_complete()
                self.assertIn("Outcome: rdap-unavailable", modal._output_text)
                self.assertEqual("".join(line.text for line in modal.query_one("#cmd-out").lines),
                                 modal._output_text.replace("\n", ""))
                with patch.object(app, "copy_to_clipboard") as copy:
                    await pilot.press("c")
                    copy.assert_called_once_with(modal._output_text)
                await pilot.press("q")

    async def test_off_loop_overlapping_results_and_dismissal(self):
        """A non-top projection may block without freezing UI or winning a race."""
        source = replace(snapshot(), top_offenders=[])
        started, release = threading.Event(), threading.Event()
        completed = asyncio.Event()
        ui_thread = threading.get_ident()
        loop = asyncio.get_running_loop()
        def project(r, ip):
            """Hold the initial result until the newer snapshot has rendered."""
            self.assertNotEqual(threading.get_ident(), ui_thread)
            result = project_ip(r, ip, lookup=lambda address: UNMAPPED)
            if r is source:
                started.set()
                if not release.wait(5):
                    raise AssertionError("Projection gate was not released")
                loop.call_soon_threadsafe(completed.set)
            return result
        with patch("offenders.build_report", return_value=source), \
             patch("offenders_geoip_ui.read_state", return_value={}), \
             patch("offenders_ip_ui.project_ip", side_effect=project):
            app = OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                top = app.query_one("#offenders", DataTable)
                top.focus()
                await pilot.press("enter")
                self.assertIs(app.screen, app.default_screen)
                app._push_ip("2001:0db8:0:0:0:0:0:1")
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait, 3))
                    inspector = app.screen
                    self.assertIn("Loading", str(inspector.query_one("#ip-details", Static).content))
                    newer = replace(source, period="30d", events=[])
                    app._apply_report(newer)
                    # Wait only for the newer worker; the first remains causally gated.
                    workers = list(app.workers)
                    await workers[-1].wait()
                    self.assertEqual(inspector.projection.period, "30d")
                    release.set()
                    await app.workers.wait_for_complete()
                    self.assertEqual(inspector.projection.period, "30d")
                    self.assertEqual(inspector.projection.total_bans, 0)
                    started.clear()
                    release.clear()
                    completed.clear()
                    inspector.update_report(source)
                    self.assertTrue(await asyncio.to_thread(started.wait, 3))
                    before = inspector.projection
                    await pilot.press("escape")
                    release.set()
                    await asyncio.wait_for(completed.wait(), 3)
                    await pilot.pause()
                    self.assertIs(app.screen, app.default_screen)
                    self.assertIs(inspector.projection, before)
                finally:
                    release.set()
