# docker-brother-scanner

Scan-button support for Brother network scanners, without Brother's drivers. Press **Scan** on the printer, choose **to File** (or Image/OCR/E-mail), pick this host, and the pages arrive as a PDF in a folder or in [Paperless-ngx](https://docs.paperless-ngx.com/).

Brother's Linux tools (`brscan-skey`, `brscan4`) only exist for x86. This image speaks the same network protocols in plain Python, so it runs on arm64 (e.g. a Raspberry Pi) as well as amd64. Multi-page documents in the document feeder become one PDF.

Tested with a Brother MFC-L2710DW. Other networked models supported by `brscan4` use the same protocols and may work.

## Example compose file

```yaml
services:
  brother-scanner:
    image: ghcr.io/etgohomeok/docker-brother-scanner:latest
    network_mode: host  # the printer sends button presses to UDP port 54925 on this host
    restart: unless-stopped
    user: "1000:1000"   # owner of the saved PDFs; needs write access to ./scans
    environment:
      PRINTER_IP: 192.168.1.50
      SCAN_DISPLAY_NAME: Office
      TZ: America/Toronto
      # Upload to Paperless-ngx instead of saving to /output:
      # PAPERLESS_URL: http://192.168.1.20:8000
      # PAPERLESS_TOKEN: your-api-token
    volumes:
      - ./scans:/output
```

To test without the printer panel, run a scan directly:

```sh
docker compose run --rm brother-scanner --scan-now
```

## Settings

| Variable | Default | Description |
|---|---|---|
| `PRINTER_IP` | *(required)* | IP address of the printer. |
| `SCAN_DISPLAY_NAME` | host name | Name shown in the printer's "Scan to PC" list. |
| `SCAN_COLOR_MODE` | `color` | `color` or `gray`. |
| `SCAN_RESOLUTION` | `300` | `150`, `200`, `300` or `600` dpi. |
| `SCAN_PAPER_SIZE` | `letter` | `letter`, `legal` or `a4`. |
| `SCAN_BRIGHTNESS` | `0` | `-50` to `50`. Applied in software, which re-encodes the pages. |
| `SCAN_CONTRAST` | `0` | `-50` to `50`. Applied in software, which re-encodes the pages. |
| `FILENAME_PATTERN` | `scan_%Y%m%d_%H%M%S` | [strftime](https://docs.python.org/3/library/time.html#time.strftime) pattern for the file name; `.pdf` is added. |
| `PAPERLESS_URL` | | Paperless-ngx address, e.g. `http://192.168.1.20:8000`. With `PAPERLESS_TOKEN` set too, scans are uploaded instead of saved to `/output`. |
| `PAPERLESS_TOKEN` | | Paperless-ngx API token (from your Paperless profile page). |
| `OUTPUT_DIR` | `/output` | Folder inside the container for saved PDFs. When uploading, PDFs are saved here if Paperless can't be reached. |
| `TZ` | `UTC` | Time zone for file names, e.g. `America/Toronto`. |
| `HOST_IP` | auto | Address the printer should send button presses to. Set it if the wrong network interface is picked. |
| `REGISTER_INTERVAL_SECONDS` | `300` | How often to re-announce this host to the printer. Must be under 360, when the printer drops it from the list. |
| `SNMP_COMMUNITY` | `internal` | SNMP write community, if it was changed on the printer. |
| `LOG_LEVEL` | `INFO` | `DEBUG` also logs every datagram received. |
