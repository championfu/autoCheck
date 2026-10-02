"""漫蛙3：复用 App 1.1.27 的自动登录、签名和福利接口。"""

import base64
import hashlib
import json
import time
from typing import Any
from urllib.parse import urlsplit

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from utils.service_runner import run_accounts

SERVICE_NAME = "Manwa"
CONFIG_FILENAME = "manwa.json"
ENV_KEY = "MANWA_ACCOUNTS"
ACCOUNT_FIELDS = ("base_url", "username", "password")

# 来自 App 的公开协议常量，不是用户密码或登录凭据。
SIGN_SALT = "jsdaghuiaonfyudsfnkgjdfkdd"
RESPONSE_SALT = "noiusdfy73osadjap012njdsfn"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 16; V2307A) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 "
    "mwa-1.1.27+1 (Android/16 vivo/V2307A)"
)


class ManwaError(ValueError):
    """仅携带可安全写入日志的本站错误。"""


def _headers(timestamp: str) -> dict[str, str]:
    """每次请求重新生成签名；Devid 为毫秒时间戳。"""
    signature = hashlib.md5(f"{timestamp},{SIGN_SALT}".encode()).hexdigest()
    return {
        "Devid": timestamp,
        "X-Token": signature,
        "User-Agent": USER_AGENT,
        "Referer": "http://mseeowpm1.xyz",
        "Origin": "http://mseeowpm1.xyz",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "Content-Type": "application/json; charset=utf-8",
    }


def _decode_response(content: bytes, timestamp: str) -> dict[str, Any]:
    """按 App 协议解密 Base64/AES-256-ECB/PKCS7 响应。"""
    key = hashlib.md5(f"{timestamp},{RESPONSE_SALT}".encode()).hexdigest().encode()
    try:
        encrypted = base64.b64decode(content.strip(), validate=True)
        plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted), AES.block_size)
        data = json.loads(plaintext)
    except (ValueError, UnicodeError):
        # 解析异常可能包含响应原文，禁止传播原始异常或认证响应。
        raise ManwaError("漫蛙响应解密失败，可能返回了网页或接口协议已变化") from None
    if not isinstance(data, dict):
        raise ManwaError("漫蛙接口响应格式错误")
    return data


def _request(
    session: requests.Session, method: str, url: str, payload: dict[str, str] | None = None,
) -> dict[str, Any]:
    """复用服务器 Cookie；禁止跟随重定向向其他站点发送登录请求。"""
    timestamp = str(time.time_ns() // 1_000_000)
    response = session.request(
        method, url, headers=_headers(timestamp), json=payload,
        timeout=30, allow_redirects=False,
    )
    if 300 <= response.status_code < 400:
        raise ManwaError("漫蛙接口返回重定向，当前网络或接口线路不可用")
    if response.status_code != 200:
        raise ManwaError(f"漫蛙接口 HTTP 状态异常 ({response.status_code})")
    return _decode_response(response.content, timestamp)


def checkin(base_url: str, username: str, password: str) -> dict[str, Any]:
    """自动登录后访问福利页触发签到，并检查今日成功标记。"""
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"} or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        return {"success": False, "message": "漫蛙 base_url 必须为不含凭据的接口站点根地址"}
    base_url = base_url.rstrip("/")
    try:
        with requests.Session() as session:
            # App 的 loginWithoutCaptcha 使用相同 JSON；Cookie 由响应自动保存。
            login = _request(session, "POST", f"{base_url}/api/account/login", {
                "username": username, "password": password,
            })
            if login.get("code") != 1:
                message = str(login.get("msg", ""))
                reason = "漫蛙自动登录失败，请核对账号密码"
                if "验证码" in message or "驗證碼" in message or "captcha" in message.lower():
                    reason = "漫蛙自动登录需要验证码，当前账号无法无人值守登录"
                return {"success": False, "message": reason}

            welfare = _request(session, "GET", f"{base_url}/api/users/welfare")
            data = welfare.get("data")
            if welfare.get("code") != 1 or not isinstance(data, dict):
                return {"success": False, "message": "漫蛙福利接口未返回有效签到数据"}
            records = data.get("sign_list")
            if not isinstance(records, list) or not any(
                isinstance(item, dict) and item.get("status") == "signedtoday"
                for item in records
            ):
                return {"success": False, "message": "漫蛙福利接口未确认今日已签到"}

            message = "今日签到已确认（含重复运行时已签到）"
            days = data.get("consecutive_sign")
            if isinstance(days, int) and not isinstance(days, bool) and days >= 0:
                message += f"，连续签到 {days} 天"
            # 积分查询可能有缓存或单独失败，不覆盖已经确认的签到状态。
            try:
                info = _request(session, "GET", f"{base_url}/api/users/info")
                user = info.get("data")
                points = user.get("point") if isinstance(user, dict) else None
                if info.get("code") == 1 and isinstance(points, (int, float)) and not isinstance(points, bool):
                    message += f"，当前积分 {points}（可能有缓存）"
            except (ManwaError, requests.RequestException):
                message += "，积分暂未获取"
            return {"success": True, "message": message}
    except ManwaError as exc:
        return {"success": False, "message": str(exc)}
    except requests.RequestException:
        return {"success": False, "message": "漫蛙网络请求失败，请检查当前网络和接口线路"}


def run(accounts: list[dict[str, Any]]) -> dict[str, Any]:
    """复用公共执行器，使用账号序号避免输出登录信息。"""
    return run_accounts(SERVICE_NAME, accounts, ACCOUNT_FIELDS, checkin)
