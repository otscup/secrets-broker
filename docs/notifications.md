# Notifications

All notification providers are optional and can be configured in the UI
(Settings) or via environment variables. When an agent requests a secret, the
broker sends the same approval message to every configured channel.

## ntfy

Set `NTFY_URL` to a topic URL, e.g. `https://ntfy.example.com/secrets-broker`.
The notification body contains HMAC-signed, 10-minute approval links for
"allow once", "allow 24h" and "deny" — clicking one approves without opening the
admin page.

## Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather).
2. Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` (or save them in Settings).
3. Send `/start` to the bot once; the broker can also learn the chat id from an
   incoming message.

Approval messages contain inline buttons (once / 1h / 24h / 7d / permanent /
deny). The broker handles callbacks with long polling, so no public webhook is
required.

## Gotify

Set `GOTIFY_URL` (for example `http://gotify:80`) and `GOTIFY_TOKEN` (an
application token created in Gotify). Messages are sent to `/message` with the
`X-Gotify-Key` header.

## wxpush (WeChat)

[wxpush](https://github.com/frankiejun/wxpush) sends WeChat notifications.

Set `WXPUSH_URL` (e.g. `https://wxpush.example.com`) and `WXPUSH_TOKEN`. The
broker posts form fields `title`, `content` and `token` to `/wxsend` with the
token in the `Authorization` header.

## Signed approval links

Every notification contains links of the form:

```
/approve/<request-id>?d=once&exp=<timestamp>&sig=<hmac>
```

They are signed with the broker session secret and expire after 10 minutes.
`d` can be `once`, `1h`, `24h`, `7d`, `always` or `deny`.
