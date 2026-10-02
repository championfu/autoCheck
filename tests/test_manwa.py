"""漫蛙的离线协议测试和独立本地真实测试入口。"""

import base64
import hashlib
import json
import tempfile
import unittest
from http.client import HTTPMessage
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

import main
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from checkin import manwa
from tests.live_helpers import run_configured_service
from tests import manwa_manual
from utils import config


def encrypted_response(request, data: dict, status: int = 200, cookie: bool = False):
    """模拟服务器加密响应和 Set-Cookie，不访问外网或读取真实配置。"""
    timestamp = request.headers["Devid"]
    key = hashlib.md5(f"{timestamp},noiusdfy73osadjap012njdsfn".encode()).hexdigest().encode()
    response = requests.Response()
    response.status_code = status
    response.request = request
    response._content = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(
        pad(json.dumps(data).encode(), 16),
    ))
    response._content = json.dumps(response._content.decode()).encode()
    headers = HTTPMessage()
    if cookie:
        headers.add_header("Set-Cookie", "test_session=test-cookie; Path=/")
    response.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=headers))
    return response


class ManwaUnitTests(unittest.TestCase):
    """验证真实 Session 的 Cookie 复用与加密响应处理。"""

    def test_known_ciphertext(self):
        self.assertEqual(manwa._decode_response(
            b"VYlpxw+tIazfDknzcGGDsOHDYLKXdvYfSTigXvhAzKI=", "1700000000000",
        ), {"code": 1, "data": {}, "msg": "ok"})
        expected = hashlib.md5(b"1700000000000,jsdaghuiaonfyudsfnkgjdfkdd").hexdigest()
        self.assertEqual(manwa._headers("1700000000000")["X-Token"], expected)

    def test_json_wrapped_ciphertext(self):
        ciphertext = "VYlpxw+tIazfDknzcGGDsOHDYLKXdvYfSTigXvhAzKI="
        self.assertEqual(manwa._decode_response(
            json.dumps(ciphertext).encode(), "1700000000000",
        )["code"], 1)

    @patch("checkin.manwa.sys.platform", "darwin")
    @patch("checkin.manwa.socket.if_nametoindex", return_value=7)
    @patch("checkin.manwa.create_connection")
    def test_direct_connection_preserves_host_and_binds_only_its_socket(self, connect, _index):
        from urllib3.poolmanager import pool_classes_by_scheme

        original = pool_classes_by_scheme.copy()
        adapter = manwa._direct_adapter("192.0.2.1", "en0")
        pool = adapter.poolmanager.connection_from_url("https://manwa.example")
        connection = pool.ConnectionCls("manwa.example", port=443, timeout=3)
        self.assertIs(connection._new_conn(), connect.return_value)
        self.assertEqual(connection.host, "manwa.example")
        args, kwargs = connect.call_args
        self.assertEqual(args[0], ("192.0.2.1", 443))
        self.assertIn((manwa.socket.IPPROTO_IP, 25, 7), kwargs["socket_options"])
        self.assertEqual(pool_classes_by_scheme, original)

    @patch("checkin.manwa._request")
    def test_incomplete_direct_configuration_makes_no_request(self, request):
        result = manwa.checkin("https://manwa.example", "u", "p", server_ip="192.0.2.1")
        self.assertFalse(result["success"])
        request.assert_not_called()

    @patch("checkin.manwa.sys.platform", "linux")
    def test_unsupported_direct_platform_reports_safe_failure(self):
        result = manwa.checkin("https://manwa.example", "u", "p", "192.0.2.1", "en0")
        self.assertFalse(result["success"])
        self.assertIn("macOS", result["message"])

    @patch("checkin.manwa.checkin", return_value={"success": True})
    @patch("utils.service_runner.log")
    def test_optional_direct_fields_are_forwarded_but_not_required(self, _log, checkin):
        accounts = [
            {"base_url": "https://manwa.example", "username": "a", "password": "p",
             "server_ip": "192.0.2.1", "network_interface": "en0"},
            {"base_url": "https://manwa.example", "username": "b", "password": "p"},
        ]
        result = manwa.run(accounts)
        self.assertEqual(result["success"], 2)
        self.assertEqual(checkin.call_args_list[0].kwargs["server_ip"], "192.0.2.1")
        self.assertEqual(checkin.call_args_list[1].kwargs["network_interface"], "")

    @patch("requests.adapters.HTTPAdapter.send")
    def test_login_cookie_is_reused_for_automatic_checkin(self, send):
        calls = []

        def respond(request, **kwargs):
            calls.append(request)
            if request.url.endswith("/api/account/login"):
                self.assertEqual(request.method, "POST")
                self.assertEqual(json.loads(request.body), {"username": "test-user", "password": "test-password"})
                self.assertNotIn("test-password", request.url)
                return encrypted_response(request, {"code": 1, "data": {"uid": "test-id"}}, cookie=True)
            self.assertIn("test_session=test-cookie", request.headers["Cookie"])
            if request.url.endswith("/api/users/welfare"):
                self.assertEqual(request.method, "GET")
                self.assertIsNone(request.body)
                return encrypted_response(request, {"code": 1, "data": {
                    "consecutive_sign": 1, "sign_list": [{"status": "signedtoday", "date": manwa.datetime.now(manwa.BEIJING).date().isoformat()}],
                }})
            return encrypted_response(request, {"code": 1, "data": {"point": 10}})

        send.side_effect = respond
        result = manwa.checkin("https://manwa.example", "test-user", "test-password")
        self.assertTrue(result["success"])
        self.assertIn("当前积分 10", result["message"])
        self.assertEqual(len(calls), 3)

    @patch("checkin.manwa._request")
    def test_login_failure_does_not_trigger_checkin_or_leak_response(self, request):
        request.return_value = {"code": 0, "msg": "test-password secret-ssid"}
        result = manwa.checkin("https://manwa.example", "test-user", "test-password")
        self.assertFalse(result["success"])
        self.assertNotIn("test-password", result["message"])
        self.assertNotIn("secret-ssid", result["message"])
        request.assert_called_once()

    @patch("checkin.manwa._request", return_value={"code": 0, "msg": "验证码错误"})
    def test_captcha_requirement_is_reported(self, _request):
        self.assertIn("验证码", manwa.checkin("https://manwa.example", "u", "p")["message"])

    @patch("requests.adapters.HTTPAdapter.send")
    def test_redirect_is_not_followed(self, send):
        def respond(request, **kwargs):
            response = encrypted_response(request, {}, status=302)
            response.headers["Location"] = "https://other.example/"
            return response

        send.side_effect = respond
        result = manwa.checkin("https://manwa.example", "test-user", "test-password")
        self.assertFalse(result["success"])
        self.assertIn("重定向", result["message"])
        send.assert_called_once()

    def test_malformed_response_does_not_expose_contents(self):
        with self.assertRaises(manwa.ManwaError) as caught:
            manwa._decode_response(b"secret-cookie <html>", "1700000000000")
        self.assertNotIn("secret-cookie", str(caught.exception))

    @patch("checkin.manwa._request")
    def test_missing_today_marker_is_not_success(self, request):
        request.side_effect = [
            {"code": 1}, {"code": 1, "data": {"sign_list": [{"status": "signedin"}]}},
        ]
        self.assertFalse(manwa.checkin("https://manwa.example", "u", "p")["success"])

    @patch("checkin.manwa._request")
    def test_stale_calendar_is_not_reported_as_today_success(self, request):
        request.side_effect = [
            {"code": 1, "msg": "登录成功，已签到成功"},
            {"code": 1, "data": {"sign_list": [{"status": "signedtoday", "date": "2000-01-01"}]}},
        ]
        result = manwa.checkin("https://manwa.example", "u", "p")
        self.assertFalse(result["success"])
        self.assertEqual(request.call_count, 2)

    def test_production_login_checkin_and_wxpusher_order(self):
        self._verify_production_notification(login_success=True)

    def test_login_failure_is_included_in_wxpusher_without_checkin(self):
        self._verify_production_notification(login_success=False)

    def _verify_production_notification(self, login_success: bool) -> None:
        """在 HTTP 边界模拟服务和推送，执行真实生产汇总链路。"""
        calls = []
        service = main.Service("Manwa", "checkin.manwa", "manwa.json", "MANWA_ACCOUNTS")
        account = {"base_url": "https://manwa.example", "username": "private-user", "password": "private-password"}

        def respond(request, **kwargs):
            path = manwa.urlsplit(request.url).path
            calls.append((request.method, path))
            if path == "/api/account/login":
                return encrypted_response(request, {
                    "code": 1 if login_success else 0,
                    "msg": "登录成功，已签到成功" if login_success else "private-password private-cookie",
                }, cookie=login_success)
            if path == "/api/users/welfare":
                self.assertIn("test_session=test-cookie", request.headers["Cookie"])
                return encrypted_response(request, {"code": 1, "data": {
                    "consecutive_sign": 1, "sign_list": [{
                        "status": "signedtoday", "date": manwa.datetime.now(manwa.BEIJING).date().isoformat(),
                    }],
                }})
            if path == "/api/users/info":
                return encrypted_response(request, {"code": 1, "data": {"point": 10}})
            self.assertEqual(request.url, "https://wxpusher.zjiecode.com/api/send/message")
            payload = json.loads(request.body)
            self.assertEqual(payload["topicIds"], [123])
            self.assertIn(f"Manwa：成功 {int(login_success)}/1", payload["content"])
            if login_success:
                self.assertIn("签到接口确认", payload["content"])
                self.assertIn("当前积分 10", payload["content"])
            else:
                self.assertIn("自动登录失败", payload["content"])
            for secret in ("private-user", "private-password", "private-cookie", "test-cookie"):
                self.assertNotIn(secret, payload["content"])
            response = requests.Response()
            response.status_code = 200
            response._content = b'{"code":1000}'
            response.raw = SimpleNamespace(_original_response=SimpleNamespace(msg=HTTPMessage()))
            return response

        with patch("requests.adapters.HTTPAdapter.send", side_effect=respond), \
             patch.object(main, "discover_services", return_value=[service]), \
             patch.object(config, "load_all_configs"), \
             patch.object(config, "ACCOUNT", {"Manwa": [account]}), \
             patch.object(config, "PUSH", {"WXPUSHER_APPTOKEN": "AT_test", "WXPUSHER_TOPICID": "123"}), \
             patch.object(main, "SUMMARY", {}), patch("main.signal.signal"):
            self.assertEqual(main.main(), 0 if login_success else 1)
        expected = [("POST", "/api/account/login")]
        if login_success:
            expected += [("GET", "/api/users/welfare"), ("GET", "/api/users/info")]
        expected.append(("POST", "/api/send/message"))
        self.assertEqual(calls, expected)

    @patch("checkin.manwa._request")
    def test_points_failure_preserves_confirmed_checkin(self, request):
        request.side_effect = [
            {"code": 1}, {"code": 1, "data": {"sign_list": [{"status": "signedtoday", "date": manwa.datetime.now(manwa.BEIJING).date().isoformat()}]}},
            requests.Timeout("test-password"),
        ]
        result = manwa.checkin("https://manwa.example", "u", "p")
        self.assertTrue(result["success"])
        self.assertIn("积分暂未获取", result["message"])

    @patch("checkin.manwa._request", side_effect=requests.Timeout("secret-cookie"))
    def test_network_error_is_sanitized(self, _request):
        result = manwa.checkin("https://manwa.example", "u", "p")
        self.assertFalse(result["success"])
        self.assertNotIn("secret-cookie", result["message"])

    @patch("checkin.manwa._request")
    def test_url_credentials_are_rejected(self, request):
        self.assertFalse(manwa.checkin("https://u:p@manwa.example", "u", "p")["success"])
        request.assert_not_called()

    @patch("checkin.manwa.checkin")
    @patch("utils.service_runner.log")
    def test_multiple_accounts_are_isolated(self, _log, checkin):
        checkin.side_effect = [{"success": False}, {"success": True}]
        result = manwa.run([
            {"base_url": "https://manwa.example", "username": "a", "password": "p"},
            {"base_url": "https://manwa.example", "username": "b", "password": "p"},
        ])
        self.assertEqual((result["total"], result["success"], result["failed"]), (2, 1, 1))

    def test_shared_base_url_and_username_deduplication(self):
        accounts = config._accounts_from_value({
            "base_url": "https://manwa.example",
            "accounts": [{"username": "a", "password": "high"}],
        }, "offline", "Manwa")
        merged = config._merge_accounts("Manwa", [
            ("high", accounts),
            ("low", [{"base_url": "https://manwa.example", "username": "a", "password": "low"}]),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["password"], "high")

    def test_manual_script_records_safe_log_and_exit_status(self):
        account = {"base_url": "https://manwa.example", "username": "private-user", "password": "private-password"}
        cases = [
            ([{"code": 0, "msg": "private-user private-password private-cookie"}], 1),
            ([{"code": 1}, {"code": 1, "data": {"sign_list": [{"status": "signedtoday", "date": manwa.datetime.now(manwa.BEIJING).date().isoformat()}]}},
              {"code": 1, "data": {"point": 10}}], 0),
        ]
        for responses, expected in cases:
            with self.subTest(exit_status=expected), tempfile.TemporaryDirectory() as directory:
                with patch.object(manwa_manual, "ROOT_PATH", Path(directory)), \
                     patch.object(manwa_manual, "configured_accounts", return_value=[account]), \
                     patch("checkin.manwa._request", side_effect=responses):
                    self.assertEqual(manwa_manual.main([]), expected)
                files = list(Path(directory).glob("manwa-manual-*.log"))
                self.assertEqual(len(files), 1)
                content = files[0].read_text(encoding="utf-8")
                self.assertIn("测试结束", content)
                self.assertIn("+0800", content)
                for secret in ("private-user", "private-password", "private-cookie"):
                    self.assertNotIn(secret, content)


if __name__ == "__main__":
    raise SystemExit(run_configured_service(manwa))
