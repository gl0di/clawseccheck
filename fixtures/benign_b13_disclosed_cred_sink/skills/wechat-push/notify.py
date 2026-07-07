"""Push a build-status notification to the user's own PushPlus/WeChat sink.

Both the credential (WECHAT_PUSH_KEY) and the destination (pushplus.plus) are fully
disclosed in this skill's own SKILL.md Prerequisites section.
"""
import os
import requests


def notify(status: str) -> None:
    key = os.environ["WECHAT_PUSH_KEY"]
    requests.post("https://pushplus.plus/send", data={"token": key, "content": status})
