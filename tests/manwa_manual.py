"""漫蛙手动真实测试：立即执行一次并记录脱敏日志。"""

import argparse
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from checkin import manwa
from tests.live_helpers import configured_accounts
from utils.config import ROOT_PATH
from utils.logger import log

BEIJING = timezone(timedelta(hours=8))


class BeijingFormatter(logging.Formatter):
    """日志时间统一使用北京时间，避免终端时区差异。"""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return datetime.fromtimestamp(record.created, BEIJING).strftime(
            datefmt or "%Y-%m-%d %H:%M:%S +0800"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    now = datetime.now(BEIJING)
    # 文件放在已有项目根目录，*.log 已被 Git 忽略；每次运行独立保存。
    logfile: Path = ROOT_PATH / f"manwa-manual-{now:%Y%m%d-%H%M%S-%f}.log"
    try:
        handler = logging.FileHandler(logfile, encoding="utf-8")
        logfile.chmod(0o600)
    except OSError:
        print("无法创建测试日志，请检查项目目录写入权限")
        return 1
    handler.setFormatter(BeijingFormatter("%(asctime)s - %(levelname)s - %(message)s"))
    log.addHandler(handler)
    try:
        log.info("漫蛙手动测试日志: %s", logfile)
        log.info("仅读取 config/manwa.json；不发送通知；只执行一次签到")
        try:
            accounts = configured_accounts(manwa)
        except (ValueError, OSError):
            log.error("本地漫蛙配置读取失败，请检查文件格式和权限")
            return 1
        if not accounts:
            log.error("没有可测试账号，请填写 config/manwa.json")
            return 1
        log.info("开始测试，北京时间 %s", datetime.now(BEIJING).isoformat())
        result = manwa.run(accounts)
        log.info("测试结束: 总数 %s，成功 %s，失败 %s", result["total"], result["success"], result["failed"])
        return 0 if result["failed"] == 0 else 1
    except KeyboardInterrupt:
        log.info("测试已由用户取消")
        return 130
    finally:
        log.removeHandler(handler)
        handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
