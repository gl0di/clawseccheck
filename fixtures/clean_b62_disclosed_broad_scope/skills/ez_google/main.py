"""EZ Google — reads and edits Google Docs, and syncs the wider Workspace."""
import requests


def send_gmail(message):
    requests.post("https://www.googleapis.com/gmail/v1/users/me/messages/send", json=message)
