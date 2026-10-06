# docker-brother-scanner

Container that registers a host as a "Scan to PC" destination on a Brother network scanner (developed against an MFC-L2710DW) and turns panel scans into PDFs, saved to a folder or uploaded to Paperless-ngx. Everything is in `brother_scanner.py`. It uses only the standard library, plus Pillow, which is only needed when brightness/contrast are set.

Brother's own `brscan4` / `brscan-skey` drivers are **not** used: they only exist for i386/amd64. The script speaks the underlying protocols directly:

1. **SNMP v1 SET** (community `internal`) to OID `1.3.6.1.4.1.2435.2.3.9.2.11.1.1.0`, one `TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=<IMAGE|OCR|EMAIL|FILE>;HOST=<ip>:54925;APPNUM=<n>;DURATION=360;BRID=;` string per panel function. Byte-identical to what brscan-skey 0.3.4 sends (pinned by a test).
2. **UDP 54925**: when someone picks this host on the panel, the printer sends a 4-byte header plus `TYPE=BR;BUTTON=SCAN;USER=...;FUNC=...;REGID=n;SEQ=n;`. It always sends to port 54925, whatever port was registered, and sends every event twice, so events are de-duplicated on `(REGID, SEQ)`.
3. **TCP 54921**, Brother's native scan protocol, pulls the pages. The command bytes match a capture of brscan4 scanning this printer.

## Development

```bash
python3 -m unittest discover -s tests       # Pillow tests are skipped if it isn't installed
docker build -t docker-brother-scanner .
docker build --platform linux/arm64 -t docker-brother-scanner:arm64 .   # no emulation needed
docker run --rm --net=host -e PRINTER_IP=<printer-ip> -v "$PWD/out:/output" docker-brother-scanner --scan-now
```

Pushing to `main` runs the tests and publishes `ghcr.io/etgohomeok/docker-brother-scanner:latest` (plus `:sha-<commit>`) for amd64 and arm64 via `.github/workflows/build.yml`.

Only one process per host can own UDP 54925, so a second listener can't be tested next to a running one on the same machine. Stop the other one first.

## Native scan protocol (TCP 54921)

- Greeting: `+OK 200\r\n`, or `-NG 401\r\n` while busy (retry).
- `ESC I \n R=300,300 \n M=CGRAY|GRAY64 \n 0x80` → `00 <len:2 LE> "xdpi,ydpi,source,width_mm,width_px,height_mm,height_px," 00`. Height is `0,0` when the ADF has paper.
- `ESC D \n ADF \n 0x80` → `0x80` if the ADF has paper, `0xC2` if not.
- `ESC X \n R= M= C=JPEG J=MID B=50 N=50 A=x1,y1,x2,y2 S=NORMAL_SCAN P=0 \n 0x80` starts the scan. `A` is in pixels at the scan resolution. Width is rounded down to a multiple of 16 (2464 px at 300 dpi), and ADF scans start 19 px in from the left, as brscan4 does.
- Reply stream: chunks of `type(1) 07 00 page(2 LE) ...(5)`, then for type `0x64` (JPEG) a 2-byte LE length and payload. `0x82` + 9 bytes ends a page; a lone `0x80` ends the scan. All ADF pages arrive on the one connection.
- `M=GRAY64 C=JPEG` works on this model (some Brother models only return grayscale as `C=RLENGTH` PackBits lines). The JPEG has 3 identical channels.
- **The printer ignores `B` (brightness) and `N` (contrast)**, even at 0 or 100 and in `RLENGTH` mode. Brother's driver applies them on the host, which is why the script does it with Pillow.

## Why not eSCL (AirScan)

The printer serves eSCL on port 80 and it works for scans started from the network side, but **not** in reply to a panel button press. The printer holds the eSCL job while the panel says "Connecting to PC", then discards it (HTTP 410) when the panel times out (~85 s). The panel session only accepts the native protocol.

## Testing printer reachability

**Do not use `ping`**: the printer does not respond to ICMP. A failed ping does not mean the printer is offline.

Use HTTP against the printer's web console instead (the printer's IP is `PRINTER_IP` in `.env`):

```bash
curl -sS -o /dev/null -w "HTTP %{http_code} time=%{time_total}s\n" --max-time 10 http://<printer-ip>/
```

A reachable printer returns `HTTP 301`.

**Cold-start delay:** if the printer has been idle, the first HTTP request can take ~4–5 seconds to complete while it wakes up. Subsequent requests answer in ~10 ms. Always allow `--max-time 10` (or longer) on the first probe and retry once before concluding the printer is unreachable.

## Keeping registration alive

The printer drops a destination `DURATION` (360) seconds after its last registration, which makes the panel say "can't find a PC". The script re-registers every `REGISTER_INTERVAL_SECONDS` (default 300, must be under 360) and retries every 30 s if the printer doesn't answer. The Docker healthcheck fails if no registration has succeeded within 360 s.

The old brscan-skey daemon only re-registered about every 10 minutes, so its entry was missing from the panel for several minutes at a time.
