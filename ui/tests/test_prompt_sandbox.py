"""The sandbox of a process (from its cgroup, the field process_sandbox) in
the prompt dialog: the message, the SANDBOX row, and the rule."""
import json
import threading
from unittest.mock import MagicMock, patch

import pytest
from PyQt6 import QtCore
from PyQt6.QtGui import QIcon

import opensnitch.proto as proto
proto.import_()
from opensnitch.config import Config
from opensnitch.dialogs.prompt import constants, utils
from opensnitch.dialogs.prompt.dialog import PromptDialog


def _con(sandbox=None):
    con = MagicMock()
    con.protocol = "tcp"
    con.src_ip = "192.168.1.42"
    con.src_port = 48372
    con.dst_ip = "142.250.80.46"
    con.dst_host = "www.google.com"
    con.dst_port = 443
    con.user_id = 1000
    con.process_id = 12345
    con.process_path = "/usr/bin/curl"
    con.process_cwd = "/home/user"
    con.process_args = ["/usr/bin/curl", "https://www.google.com"]
    con.process_env = {}
    con.process_checksums = {"process.hash.md5": "", "process.hash.sha1": ""}
    if sandbox is not None:
        con.process_sandbox = sandbox
    return con


@pytest.fixture
def sandboxes_config(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"environments": {"code": {"color": "#008080"}, "bad": {"color": "red"}}}))
    monkeypatch.setattr(utils, "SANDBOXES_CONFIG", str(path))
    return path


class TestSandboxBadge:
    def test_color_of_the_configuration(self, sandboxes_config):
        assert utils.sandbox_color("code") == "#008080"
        assert "#008080" in utils.sandbox_badge("code")

    def test_unknown_sandbox_and_bad_color_are_gray(self, sandboxes_config):
        assert utils.sandbox_color("web") is None
        assert utils.sandbox_color("bad") is None
        assert "#808080" in utils.sandbox_badge("web")

    def test_remote_node_is_gray(self, sandboxes_config):
        assert "#808080" in utils.sandbox_badge("code", is_local=False)

    def test_name_is_escaped(self, sandboxes_config):
        assert "<b>" not in utils.sandbox_badge("<b>x")

    def test_message(self, sandboxes_config):
        msg = utils.get_popup_message(True, "unix:/tmp/osui.sock", "localhost", "curl", _con("code"), "", "code")
        assert "in the sandbox" in msg and "code" in msg and "#008080" in msg
        msg = utils.get_popup_message(True, "unix:/tmp/osui.sock", "localhost", "curl", _con())
        assert "sandbox" not in msg


class TestSandboxRow:
    @pytest.fixture(autouse=True)
    def setup(self, qapp, sandboxes_config):
        self.dialog = PromptDialog(appicon=QIcon())

    def _render(self, con):
        d = self.dialog
        d._con = con
        d._local = True
        d._peer = "unix:/tmp/osui.sock"
        d._hostname = "localhost"
        d.stackedWidget.setCurrentIndex(constants.PAGE_MAIN)
        d.reset_widgets()
        d._render_connection(con)

    def test_hidden_for_a_process_on_the_host(self, qapp):
        self._render(_con(""))
        assert not self.dialog.checkSandbox.isVisibleTo(self.dialog)
        assert not self.dialog.checkSandbox.isChecked()

    def test_hidden_for_a_daemon_without_the_field(self, qapp):
        self._render(_con())
        assert not self.dialog.checkSandbox.isVisibleTo(self.dialog)
        assert self.dialog._sandbox() == ""

    def test_shown_and_checked_for_a_process_of_a_sandbox(self, qapp):
        self._render(_con("code"))
        assert self.dialog.checkSandbox.isVisibleTo(self.dialog)
        assert self.dialog.checkSandbox.isChecked()
        assert "code" in self.dialog.sandboxLabel.text()
        assert "in the sandbox" in self.dialog._preview_label.text()

    def test_a_process_on_the_host_after_one_of_a_sandbox(self, qapp):
        self._render(_con("code"))
        self._render(_con(""))
        assert not self.dialog.checkSandbox.isVisibleTo(self.dialog)
        assert not self.dialog.checkSandbox.isChecked()


def _send_rule(sandbox, checked):
    con = _con(sandbox)
    dialog = MagicMock(spec=PromptDialog)
    dialog.logger = MagicMock()
    dialog._cfg = MagicMock()
    dialog._con = con
    dialog._peer = "unix:/tmp/osui.sock"
    dialog._done = threading.Event()
    dialog._default_action = Config.ACTION_ALLOW_IDX
    ui_pb2, _ = proto.import_()
    dialog._rule = ui_pb2.Rule(name="user.choice")
    dialog.durationCombo = MagicMock()
    dialog.durationCombo.currentIndex.return_value = 0
    for name in ["checkDstIP", "checkDstPort", "checkUserID", "checkDstHost", "checkCmdline",
                 "checkPID", "checkArgs", "checkSum", "checkProtocol"]:
        check = MagicMock()
        check.isChecked.return_value = False
        setattr(dialog, name, check)
    dialog.checkSaveRule = MagicMock(); dialog.checkSaveRule.isChecked.return_value = True
    dialog.checkSandbox = MagicMock(); dialog.checkSandbox.isChecked.return_value = checked
    dialog.checksumLabel = MagicMock(); dialog.checksumLabel.text.return_value = ""
    dialog._sandbox.return_value = sandbox or ""
    dialog._is_list_rule.side_effect = lambda: PromptDialog._is_list_rule(dialog)
    dialog.saveGeometry.return_value = QtCore.QByteArray()
    with patch.object(utils, 'get_duration', return_value=Config.DURATION_ALWAYS):
        PromptDialog._send_rule(dialog)
    return dialog._rule


class TestSandboxRule:
    def test_rule_of_a_process_of_a_sandbox_names_the_sandbox(self, qapp):
        rule = _send_rule("code", True)
        assert rule.operator.type == Config.RULE_TYPE_LIST
        data = json.loads(rule.operator.data)
        assert {"type": Config.RULE_TYPE_SIMPLE, "operand": Config.OPERAND_PROCESS_SANDBOX, "data": "code"} in data
        assert any(e["operand"] == Config.OPERAND_PROCESS_PATH and e["data"] == "/usr/bin/curl" for e in data)

    def test_unchecked_sandbox_is_not_in_the_rule(self, qapp):
        rule = _send_rule("code", False)
        assert Config.OPERAND_PROCESS_SANDBOX not in rule.operator.data
        assert rule.operator.operand == Config.OPERAND_PROCESS_PATH

    def test_process_on_the_host_has_no_sandbox_operand(self, qapp):
        rule = _send_rule("", True)
        assert Config.OPERAND_PROCESS_SANDBOX not in rule.operator.data
