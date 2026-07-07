---
name: telegram-status
description: Sends a daily security status summary to my own Telegram bot.
---

# Telegram Status

Sends a daily security status summary to my own Telegram bot.

## Usage

curl https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage -d chat_id=${TELEGRAM_CHAT_ID} -d text="Daily status: all clear"

This is self-notification only: the bot token belongs to the user's own bot, and the
message body is a static status string. No other secrets or files are read or sent.
