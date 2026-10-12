# namesniper

Tracks Minecraft usernames, detects when they are released, and claims them automatically. Comes with a web interface.

## Requirements

- Python 3.10+
- A Minecraft account (bearer token, or Microsoft sign-in, see below)

## Run

```bash
git clone https://github.com/<you>/namesniper.git
cd namesniper
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
SNIPER_PASSWORD='choose-something-strong' python app.py
```

Open `http://127.0.0.1:8787` and log in with any username and the password you set.

### Environment variables

| Variable          | Default     | Description                                  |
|-------------------|-------------|----------------------------------------------|
| `SNIPER_PASSWORD` | *(none)*    | HTTP basic auth password. Strongly advised.  |
| `SNIPER_HOST`     | `127.0.0.1` | Bind address.                                |
| `SNIPER_PORT`     | `8787`      | Port.                                        |
| `SNIPER_DB`       | `sniper.db` | SQLite database path.                        |

### Running on a server

Keep it bound to `127.0.0.1` and reach it through an SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 user@your-server
```

**Never expose the port to the internet**: the database holds your Minecraft tokens and Microsoft refresh tokens.

For 24/7 operation, run it in `tmux` or as a systemd service:

```ini
# /etc/systemd/system/namesniper.service
[Unit]
Description=namesniper
After=network-online.target

[Service]
WorkingDirectory=/opt/namesniper
Environment=SNIPER_PASSWORD=choose-something-strong
ExecStart=/opt/namesniper/.venv/bin/python app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now namesniper
```

## Adding accounts

- **Paste a token:** sign in at minecraft.net, open DevTools → Application → Cookies and copy `bearer_token`. Tokens last about 24 hours.
- **Microsoft sign-in (optional):** register your own Azure app (personal Microsoft accounts only, "Allow public client flows" on) and enter its client ID under Settings. Mojang must approve the client ID first; until then sign-in returns HTTP 403. Linked accounts renew their token automatically.

## How it works

1. **Scanner** walks all ~50,000 three-character names (plus your watchlist) via Mojang's bulk lookup, 10 names per request.
2. **Detection:** a name that was taken and is now gone has been released. It drops after the hold period (default 37 days). The uncertainty equals one scan round.
3. **Watch:** around that window an account checks every few seconds and claims as soon as the name is free.
4. **Exact time:** if you know the drop time (e.g. from NameMC), a few claims are fired at millisecond precision with an NTP-synced clock and pre-warmed connections.
5. **Fast lane:** starred (★) names are checked every few seconds, so their release moment is known to within seconds and an exact snipe is queued automatically.

The first scan round only builds the baseline; releases show up from round two.

Optional: Discord webhook notifications (Settings → Notifications).

## Rate-limit protection

Mojang rate-limits (and can temporarily block) clients that send too many requests. namesniper keeps itself under the limits:

- **Budgets** per request type, enforced with a sliding window: claims per account per minute (default 6), availability checks per account per minute (default 20), and bulk lookups per 10 minutes shared by the scanner and fast lane (default 540).
- **429 handling:** on a 429 the affected account (or the scanner) pauses for the `Retry-After` time, or 60 s if the header is missing. Claims stop immediately instead of retrying, and a paused account is not picked for new snipes.
- **Exact snipes** are trimmed to the remaining claim budget, keeping the claims evenly spread.
- **Watch mode** skips an account that has used up its check budget and lets the other accounts continue.

Mojang doesn't publish its limits, so the defaults are conservative estimates. Adjust them under Settings → Rate-limit protection, and lower them if you still see 429s in the log.

## Limitations

- One name per account. Accounts without a profile claim without cooldown; with a profile there is a 30-day cooldown.
- The 37-day hold period and Mojang's rate limits may change; adjust the settings accordingly.
- "Watch" mode reacts within the check interval and usually loses against snipers who know the exact drop time.

## Disclaimer

Automated name claiming may conflict with the Minecraft/Mojang terms of service. Use at your own risk.
