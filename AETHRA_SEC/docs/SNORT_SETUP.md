# Snort Setup Guide (Intrusion Detection)

This guide connects **Snort** to AETHRA-SEC so real intrusion alerts appear on
the dashboard. It's written for beginners using a **Windows laboratory** machine.

> 💡 **Want to see alerts working first, without Snort?**
> With AETHRA-SEC running and logged in, open a second Command Prompt and run:
> ```bat
> python tools\send_test_alerts.py
> ```
> Sample alerts will stream into the **Intrusion Alerts** page. The repeated SSH
> alert appears as **one row with a rising occurrence count** — that's the
> deduplication feature. Do this before setting up real Snort so you know the
> app side works.

---

## How the pieces fit together

```
   Snort (detects attacks)  ->  writes alerts to a log file
              │
              ▼
   snort_forwarder.py  (reads new alert lines)
              │  streams over TCP 127.0.0.1:9000
              ▼
   AETHRA-SEC Alert Socket listener  ->  Intrusion Alerts page
```

AETHRA-SEC listens on a socket for alerts in real time. Because stock Snort on
Windows writes alerts to a file, the small included **forwarder** tails that file
and streams new lines to the socket. You never edit files by hand — the forwarder
does the bridging.

---

## Step 1 — Install Snort

1. Download Snort for Windows from <https://www.snort.org/downloads>.
2. Run the installer. By default it installs to `C:\Snort`.
3. Also install **WinPcap/Npcap** if the installer prompts you (Npcap is usually
   already present if you installed Wireshark).

## Step 2 — Get community rules

1. On the Snort downloads page, get the **Community Rules** (`snortrules-...tar.gz`).
2. Extract them so the `.rules` files end up in `C:\Snort\rules`.

## Step 3 — Add a few simple test rules

Create a file `C:\Snort\rules\local.rules` and paste these beginner-friendly
rules (they detect common lab activity):

```
# Detect ICMP pings (ping flood testing)
alert icmp any any -> $HOME_NET any (msg:"ICMP echo request"; itype:8; sid:1000001; rev:1;)

# Detect repeated TCP connection attempts to SSH (brute-force testing)
alert tcp any any -> $HOME_NET 22 (msg:"SSH connection attempt"; flags:S; sid:1000002; rev:1;)

# Detect connections to a web server (HTTP abnormal-traffic testing)
alert tcp any any -> $HOME_NET 80 (msg:"HTTP connection attempt"; flags:S; sid:1000003; rev:1;)
```

## Step 4 — Point snort.conf at your rules

Open `C:\Snort\etc\snort.conf` in Notepad and make sure:

1. `HOME_NET` matches your lab network, e.g.:
   ```
   ipvar HOME_NET 10.0.0.0/24
   ```
2. The rules path is set:
   ```
   var RULE_PATH C:\Snort\rules
   ```
3. Your rule files are included near the bottom, e.g.:
   ```
   include $RULE_PATH\local.rules
   ```

## Step 5 — Find your interface number

List the interfaces Snort can see:

```bat
cd C:\Snort\bin
snort.exe -W
```

Note the **index number** of the network adapter you want to monitor (the
left-most column).

## Step 6 — Configure AETHRA-SEC

In AETHRA-SEC, log in as **admin** and open **Settings → Snort IDS**. Confirm:

- **Snort Executable:** `C:\Snort\bin\snort.exe`
- **Configuration File:** `C:\Snort\etc\snort.conf`
- **Rules Directory:** `C:\Snort\rules`
- **Alert Socket Host / Port:** `127.0.0.1` / `9000`

Click **Save All Settings**.

## Step 7 — Start everything (order matters)

Open **three** Command Prompt windows, all **Run as Administrator**:

**Window 1 — AETHRA-SEC** (if not already running):
```bat
cd path\to\AETHRA_SEC
python main.py
```
Log in. The Alert Socket listener starts automatically.

**Window 2 — Snort** (replace `1` with your interface number from Step 5):
```bat
cd C:\Snort\bin
snort.exe -c C:\Snort\etc\snort.conf -i 1 -A fast -l C:\Snort\log
```
Snort now watches traffic and writes alerts to `C:\Snort\log\alert.ids`.

> You can also start/stop Snort from **Settings → Snort IDS** inside the app.

**Window 3 — The forwarder** (bridges Snort's alerts to AETHRA-SEC):
```bat
cd path\to\AETHRA_SEC
python tools\snort_forwarder.py --file "C:\Snort\log\alert.ids"
```

## Step 8 — Generate some test traffic

From another lab machine (or the same one), create activity that trips a rule —
for example ping the monitored host:

```bat
ping 10.0.0.10
```

Within a second or two, an alert should appear on the **Intrusion Alerts** page,
be classified and severity-scored, show a mitigation recommendation, and update
the dashboard counters.

---

## Troubleshooting

| Problem | Fix |
|--------|-----|
| No alerts appear | Confirm Snort is actually running (Window 2 prints activity) and the forwarder (Window 3) shows `forwarded: ...` lines |
| `snort.exe -W` shows no interfaces | Install/repair **Npcap**; run the prompt **as Administrator** |
| Forwarder says "not reachable" | Start AETHRA-SEC and log in first — the socket only opens after login |
| Snort exits immediately | A `snort.conf` path is wrong; read Snort's error output in Window 2 |
| Wrong network in alerts | Fix `HOME_NET` in `snort.conf` to match your lab subnet |

---

## Safety reminder

Run Snort and any test attacks **only** on an **isolated laboratory network** you
are authorized to use. AETHRA-SEC is a defensive, educational tool: it detects,
classifies, and **recommends** mitigation — it never blocks or attacks anything.
