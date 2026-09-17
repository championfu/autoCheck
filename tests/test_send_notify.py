"""通知渠道的离线测试。"""

import unittest
from unittest.mock import Mock, patch

from utils import config
from utils import sendNotify


class WxPusherTests(unittest.TestCase):
    """验证 WxPusher 请求契约和配置校验。"""

    @patch("utils.sendNotify.requests.post")
    def test_sends_autosign_compatible_payload(self, post):
        response = Mock()
        response.json.return_value = {"code": 1000, "msg": "处理成功"}
        post.return_value = response

        with patch.object(
            config,
            "PUSH",
            {"WXPUSHER_APPTOKEN": "AT_test_token", "WXPUSHER_TOPICID": "40802"},
        ):
            sendNotify.wxpusher("AutoCheck 签到结果", "签到汇总：成功 1，失败 0")

        post.assert_called_once_with(
            "https://wxpusher.zjiecode.com/api/send/message",
            json={
                "appToken": "AT_test_token",
                "content": "签到汇总：成功 1，失败 0",
                "summary": "AutoCheck 签到结果",
                "contentType": 1,
                "topicIds": [40802],
            },
            timeout=15,
        )

    @patch("utils.sendNotify.requests.post")
    @patch("utils.sendNotify.log")
    def test_invalid_topic_id_skips_request(self, log, post):
        with patch.object(
            config,
            "PUSH",
            {"WXPUSHER_APPTOKEN": "AT_test_token", "WXPUSHER_TOPICID": "not-a-number"},
        ):
            sendNotify.wxpusher("标题", "正文")

        post.assert_not_called()
        log.warning.assert_called_once_with("WxPusher 推送失败: WXPUSHER_TOPICID 必须是整数")

    @patch("utils.sendNotify.requests.post")
    @patch("utils.sendNotify.log")
    def test_non_success_response_is_logged(self, log, post):
        response = Mock()
        response.json.return_value = {"code": 1001, "msg": "参数错误"}
        post.return_value = response

        with patch.object(
            config,
            "PUSH",
            {"WXPUSHER_APPTOKEN": "AT_test_token", "WXPUSHER_TOPICID": "40802"},
        ):
            sendNotify.wxpusher("标题", "正文")

        log.warning.assert_called_once_with("%s 推送失败: %s", "WxPusher", {"code": 1001, "msg": "参数错误"})


if __name__ == "__main__":
    unittest.main()
