#!/usr/bin/env python3
"""Brother "Scan to PC" listener that saves scans as PDFs or uploads them to Paperless-ngx.

Replaces Brother's x86-only brscan-skey + brscan4 binaries with the network
protocols they wrap, so it runs on any architecture (e.g. a Raspberry Pi):

  * SNMP v1 SET registers this host on the printer's "Scan to PC" list.
  * The printer sends a UDP datagram to port 54925 when someone picks this host on the panel.
  * The scan itself is pulled over TCP port 54921 with Brother's native scan protocol.
"""

import io
import logging
import os
import queue
import re
import signal
import socket
import sys
import threading
import time
import urllib.request
import uuid

log = logging.getLogger("brother-scanner")

# --- SNMP registration -------------------------------------------------------

REGISTER_OID = "1.3.6.1.4.1.2435.2.3.9.2.11.1.1.0"
# Seconds the printer keeps a registration before dropping it from the panel.
REGISTRATION_TTL = 360
# Panel functions and the APPNUM brscan-skey uses for each. Registering all of them
# makes this host selectable no matter which Scan sub-menu is used.
FUNCTIONS = {"IMAGE": 1, "OCR": 3, "EMAIL": 2, "FILE": 5}
# The printer sends button events to this port no matter which port is registered.
EVENT_PORT = 54925


def _ber(tag, value):
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def _ber_int(n):
    return _ber(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def _ber_oid(oid):
    parts = [int(p) for p in oid.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(reversed(chunk))
    return _ber(0x06, bytes(out))


def _ber_read(buf, pos):
    """Return (tag, value, next_pos) for the TLV starting at pos."""
    tag, n = buf[pos], buf[pos + 1]
    pos += 2
    if n & 0x80:
        size = n & 0x7F
        n = int.from_bytes(buf[pos:pos + size], "big")
        pos += size
    return tag, buf[pos:pos + n], pos + n


def snmp_set_request(community, request_id, oid, values):
    """Encode an SNMP v1 SetRequest that writes each string in values to oid."""
    varbinds = b"".join(_ber(0x30, _ber_oid(oid) + _ber(0x04, v.encode())) for v in values)
    pdu = _ber(0xA3, _ber_int(request_id) + _ber_int(0) + _ber_int(0) + _ber(0x30, varbinds))
    return _ber(0x30, _ber_int(0) + _ber(0x04, community.encode()) + pdu)


def snmp_response_status(packet):
    """Return (request_id, error_status) from an SNMP v1 GetResponse."""
    try:
        _, message, _ = _ber_read(packet, 0)
        pos = _ber_read(message, 0)[2]          # version
        pos = _ber_read(message, pos)[2]        # community
        tag, pdu, _ = _ber_read(message, pos)
        _, request_id, pos = _ber_read(pdu, 0)
        _, error_status, _ = _ber_read(pdu, pos)
    except IndexError:
        raise ValueError("truncated SNMP reply") from None
    if tag != 0xA2:
        raise ValueError(f"unexpected SNMP PDU type 0x{tag:02x}")
    return int.from_bytes(request_id, "big"), int.from_bytes(error_status, "big")


def registration_strings(display_name, host_ip):
    return [
        f'TYPE=BR;BUTTON=SCAN;USER="{display_name}";FUNC={func};HOST={host_ip}:{EVENT_PORT};'
        f"APPNUM={appnum};DURATION={REGISTRATION_TTL};BRID=;"
        for func, appnum in FUNCTIONS.items()
    ]


def register(cfg, request_id):
    packet = snmp_set_request(
        cfg.snmp_community, request_id, REGISTER_OID,
        registration_strings(cfg.display_name, cfg.host_ip),
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        for _ in range(3):
            sock.sendto(packet, (cfg.printer_ip, 161))
            try:
                reply, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            reply_id, error_status = snmp_response_status(reply)
            if reply_id != request_id:
                continue
            if error_status:
                raise RuntimeError(f"printer rejected registration (SNMP error-status {error_status})")
            return
    raise TimeoutError(f"no SNMP reply from {cfg.printer_ip}")


# --- Button events -----------------------------------------------------------

def parse_event(data):
    """Parse a button datagram into its key/value fields, or None if it isn't one.

    Datagrams are a 4-byte header followed by ASCII, e.g.
    TYPE=BR;BUTTON=SCAN;USER="Office";FUNC=FILE;HOST=192.168.1.10:54925;APPNUM=5;...;SEQ=3;
    """
    text = data.decode("latin-1")
    start = text.find("TYPE=BR;")
    if start < 0:
        return None
    fields = {}
    for item in text[start:].split(";"):
        key, sep, value = item.partition("=")
        if sep:
            fields[key] = value.strip('"')
    return fields


# --- Native scan protocol (TCP 54921) ----------------------------------------
#
# The panel's "Scan to PC" session only accepts this protocol: an eSCL (AirScan)
# job sent in reply to a button press is held, then discarded when the panel times
# out. The command sequence mirrors a capture of Brother's brscan4 driver.

SCAN_PORT = 54921
# Paper sizes in inches.
PAPER_SIZES = {"letter": (8.5, 11), "legal": (8.5, 14), "a4": (8.27, 11.69)}
COLOR_MODES = {"color": "CGRAY", "gray": "GRAY64"}
RESOLUTIONS = (150, 200, 300, 600)

PAGE_END = 0x82
SCAN_END = 0x80
JPEG_CHUNK = 0x64


class ScanError(Exception):
    pass


def _connect(host):
    """Open a scan connection, waiting out "-NG 401" (busy) greetings."""
    for _ in range(30):
        sock = socket.create_connection((host, SCAN_PORT), timeout=30)
        stream = sock.makefile("rb")
        greeting = stream.readline()
        if greeting.startswith(b"+OK"):
            return sock, stream
        stream.close()
        sock.close()
        log.debug("Scanner busy (%r), retrying", greeting.strip())
        time.sleep(1)
    raise ScanError("scanner stayed busy")


def _command(sock, code, params):
    sock.sendall(b"\x1b" + code + b"\n" + b"".join(p.encode("latin-1") + b"\n" for p in params) + b"\x80")


def _read_exact(stream, n):
    data = stream.read(n)
    if len(data) != n:
        raise ScanError("scanner closed the connection mid-scan")
    return data


def scan(host, resolution, color_mode, paper):
    """Scan every page in the ADF (or the glass if it's empty); return one JPEG per page."""
    mode = COLOR_MODES[color_mode]
    sock, stream = _connect(host)
    with sock, stream:
        # ESC I negotiates resolution and reports the scan area:
        # 00 <len:2 LE> "xdpi,ydpi,source,width_mm,width_px,height_mm,height_px," 00
        _command(sock, b"I", [f"R={resolution},{resolution}", f"M={mode}"])
        header = _read_exact(stream, 3)
        if header[0] != 0:
            raise ScanError(f"unexpected reply to ESC I: {header.hex()}")
        reply = _read_exact(stream, int.from_bytes(header[1:3], "little")).rstrip(b"\0,")
        dpi, _, _, _, max_w, _, max_h = (int(v) for v in reply.split(b","))

        # ESC D asks whether the ADF has paper: 0x80 = yes, 0xC2 = no.
        _command(sock, b"D", ["ADF"])
        adf = _read_exact(stream, 1) == b"\x80"

        width = min(round(paper[0] * dpi), max_w) // 16 * 16
        height = round(paper[1] * dpi)
        if not adf:
            height = min(height, max_h)
        # Brother's driver starts ADF scans 19 px (at 300 dpi) in from the left edge.
        x = round(19 * dpi / 300) if adf else 0
        log.info("Scanning from %s at %d dpi in %s", "ADF" if adf else "glass", dpi, color_mode)
        # The printer ignores brightness (B) and contrast (N); see adjust_pages().
        _command(sock, b"X", [
            f"R={dpi},{dpi}", f"M={mode}", "C=JPEG", "J=MID", "B=50", "N=50",
            f"A={x},0,{x + width},{height}", "S=NORMAL_SCAN", "P=0",
        ])

        # The reply is a stream of chunks, each a 10-byte header (type, 07 00,
        # page number:2 LE, ...) plus, for image data, a 2-byte LE length and payload.
        # A PAGE_END header closes each page; a lone SCAN_END byte ends the scan.
        sock.settimeout(120)  # the ADF can pause between pages
        pages = {}
        while True:
            kind = _read_exact(stream, 1)[0]
            if kind == SCAN_END:
                break
            header = _read_exact(stream, 9)
            if kind == PAGE_END:
                log.info("Received page %d", int.from_bytes(header[2:4], "little"))
                continue
            if kind != JPEG_CHUNK:
                raise ScanError(f"unexpected chunk type 0x{kind:02x} (header {header.hex()})")
            length = int.from_bytes(_read_exact(stream, 2), "little")
            page = int.from_bytes(header[2:4], "little")
            pages.setdefault(page, bytearray()).extend(_read_exact(stream, length))
    if not pages:
        raise ScanError("scan finished without any pages")
    return [bytes(pages[p]) for p in sorted(pages)]


def adjust_pages(pages, color_mode, brightness, contrast, dpi):
    """Apply brightness/contrast (-50..50) in software, as Brother's driver does.

    The printer ignores the B and N scan parameters, so the pages are decoded and
    re-encoded. With both at 0 the printer's JPEGs pass through untouched.
    """
    if not brightness and not contrast:
        return pages
    from PIL import Image, ImageEnhance

    adjusted = []
    for jpeg in pages:
        image = Image.open(io.BytesIO(jpeg))
        if color_mode == "gray":
            image = image.convert("L")  # the printer sends gray as 3 identical channels
        if brightness:
            image = ImageEnhance.Brightness(image).enhance(1 + brightness / 100)
        if contrast:
            image = ImageEnhance.Contrast(image).enhance(1 + contrast / 100)
        out = io.BytesIO()
        image.save(out, "JPEG", quality=90, dpi=(dpi, dpi))
        adjusted.append(out.getvalue())
    return adjusted


# --- PDF assembly ------------------------------------------------------------

def jpeg_info(data):
    """Return (width, height, components, dpi or None) from a baseline/progressive JPEG."""
    dpi = None
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            raise ValueError("malformed JPEG")
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        segment = data[pos + 4:pos + 2 + length]
        if marker == 0xE0 and segment[:5] == b"JFIF\0" and len(segment) >= 12 and segment[7] == 1:
            dpi = int.from_bytes(segment[8:10], "big") or None
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            height = int.from_bytes(segment[1:3], "big")
            width = int.from_bytes(segment[3:5], "big")
            return width, height, segment[5], dpi
        pos += 2 + length
    raise ValueError("no frame header found in JPEG")


def jpegs_to_pdf(pages, fallback_dpi):
    """Wrap JPEG pages in a PDF without re-encoding them."""
    colorspaces = {1: "/DeviceGray", 3: "/DeviceRGB"}
    objects = []  # objects[i] is the body of object number i + 1

    def add(body):
        objects.append(body)
        return len(objects)

    add(b"<< /Type /Catalog /Pages 2 0 R >>")
    add(b"")  # page tree, filled in once the pages exist
    kids = []
    for jpeg in pages:
        width, height, components, dpi = jpeg_info(jpeg)
        if components not in colorspaces:
            raise ValueError(f"unsupported JPEG with {components} components")
        scale = 72 / (dpi or fallback_dpi)
        pt_w, pt_h = round(width * scale, 2), round(height * scale, 2)
        image = add(
            f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
            f"/ColorSpace {colorspaces[components]} /BitsPerComponent 8 /Filter /DCTDecode "
            f"/Length {len(jpeg)} >>\nstream\n".encode() + jpeg + b"\nendstream"
        )
        content = f"q {pt_w} 0 0 {pt_h} 0 0 cm /Im0 Do Q".encode()
        contents = add(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")
        kids.append(add(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {pt_w} {pt_h}] "
            f"/Resources << /XObject << /Im0 {image} 0 R >> >> /Contents {contents} 0 R >>".encode()
        ))
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# --- Output ------------------------------------------------------------------

def save_pdf(pdf, output_dir, name):
    """Write pdf to output_dir as name (adding _2, _3... on a clash); return the path."""
    stem = name[:-4]
    suffix = 2
    while os.path.exists(os.path.join(output_dir, name)):
        name = f"{stem}_{suffix}.pdf"
        suffix += 1
    final = os.path.join(output_dir, name)
    # Write under a hidden name first so folder watchers never see a partial file.
    # ("._" is in Paperless-ngx's built-in ignore list.)
    partial = os.path.join(output_dir, f"._{name}.part")
    with open(partial, "wb") as f:
        f.write(pdf)
    os.chmod(partial, 0o644)
    os.replace(partial, final)
    return final


def upload_to_paperless(url, token, pdf, name):
    """POST the PDF to Paperless-ngx's document API; return the consumption task id."""
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="document"; filename="{name}"\r\n'
        "Content-Type: application/pdf\r\n\r\n"
    ).encode() + pdf + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        f"{url}/api/documents/post_document/", data=body, method="POST",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read().decode().strip().strip('"')


def deliver(cfg, pdf):
    name = time.strftime(cfg.filename_pattern) + ".pdf"
    if not cfg.paperless_url:
        return save_pdf(pdf, cfg.output_dir, name)
    for attempt in range(3):
        try:
            task = upload_to_paperless(cfg.paperless_url, cfg.paperless_token, pdf, name)
            return f"Paperless (task {task})"
        except OSError as e:
            log.warning("Upload to Paperless failed (%s)", e)
            if attempt < 2:
                time.sleep(10)
    # Don't lose the scan: fall back to the output folder if one is mounted.
    if os.access(cfg.output_dir, os.W_OK):
        return save_pdf(pdf, cfg.output_dir, name)
    raise RuntimeError("upload failed and no writable OUTPUT_DIR to fall back to; scan discarded")


# --- Daemon ------------------------------------------------------------------

def _int_in_range(env, key, default, low, high):
    value = int(env.get(key, default))
    if not low <= value <= high:
        raise ValueError(f"{key} must be between {low} and {high}")
    return value


class Config:
    def __init__(self, env):
        self.printer_ip = env.get("PRINTER_IP", "").strip()
        if not self.printer_ip:
            raise ValueError("PRINTER_IP is not set")
        self.display_name = env.get("SCAN_DISPLAY_NAME", "").strip() or socket.gethostname().split(".")[0]
        if re.search(r'[";]', self.display_name):
            raise ValueError("SCAN_DISPLAY_NAME can't contain '\"' or ';'")
        self.host_ip = env.get("HOST_IP", "").strip() or detect_host_ip(self.printer_ip)

        self.color_mode = env.get("SCAN_COLOR_MODE", "color").lower()
        if self.color_mode not in COLOR_MODES:
            raise ValueError(f"SCAN_COLOR_MODE must be one of {', '.join(COLOR_MODES)}")
        self.resolution = int(env.get("SCAN_RESOLUTION", "300"))
        if self.resolution not in RESOLUTIONS:
            raise ValueError(f"SCAN_RESOLUTION must be one of {', '.join(map(str, RESOLUTIONS))}")
        paper = env.get("SCAN_PAPER_SIZE", "letter").lower()
        if paper not in PAPER_SIZES:
            raise ValueError(f"SCAN_PAPER_SIZE must be one of {', '.join(PAPER_SIZES)}")
        self.paper = PAPER_SIZES[paper]
        self.brightness = _int_in_range(env, "SCAN_BRIGHTNESS", "0", -50, 50)
        self.contrast = _int_in_range(env, "SCAN_CONTRAST", "0", -50, 50)

        self.filename_pattern = env.get("FILENAME_PATTERN", "scan_%Y%m%d_%H%M%S").strip()
        if self.filename_pattern.lower().endswith(".pdf"):
            self.filename_pattern = self.filename_pattern[:-4]
        if not time.strftime(self.filename_pattern) or "/" in time.strftime(self.filename_pattern):
            raise ValueError("FILENAME_PATTERN must produce a non-empty name without '/'")
        self.output_dir = env.get("OUTPUT_DIR", "/output")
        self.paperless_url = env.get("PAPERLESS_URL", "").strip().rstrip("/")
        self.paperless_token = env.get("PAPERLESS_TOKEN", "").strip()
        if bool(self.paperless_url) != bool(self.paperless_token):
            raise ValueError("set both PAPERLESS_URL and PAPERLESS_TOKEN, or neither")
        if self.paperless_url and not re.match(r"https?://", self.paperless_url):
            raise ValueError("PAPERLESS_URL must start with http:// or https://")

        self.register_interval = _int_in_range(env, "REGISTER_INTERVAL_SECONDS", "300", 10, REGISTRATION_TTL - 1)
        self.snmp_community = env.get("SNMP_COMMUNITY", "internal")


def detect_host_ip(printer_ip):
    """The local address the kernel would use to reach the printer (no packets are sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((printer_ip, 161))
        return sock.getsockname()[0]


def check_paperless(cfg):
    """Log whether the Paperless URL and token work; scans are still attempted either way."""
    request = urllib.request.Request(
        f"{cfg.paperless_url}/api/documents/?page_size=1",
        headers={"Authorization": f"Token {cfg.paperless_token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            log.info("Uploading scans to Paperless at %s", cfg.paperless_url)
    except OSError as e:
        log.warning("Can't reach Paperless at %s yet (%s)", cfg.paperless_url, e)


def scan_and_deliver(cfg):
    started = time.monotonic()
    pages = scan(cfg.printer_ip, cfg.resolution, cfg.color_mode, cfg.paper)
    pages = adjust_pages(pages, cfg.color_mode, cfg.brightness, cfg.contrast, cfg.resolution)
    destination = deliver(cfg, jpegs_to_pdf(pages, cfg.resolution))
    log.info("Saved %d page(s) to %s in %.0fs", len(pages), destination, time.monotonic() - started)


def scan_worker(cfg, jobs):
    while True:
        jobs.get()
        try:
            scan_and_deliver(cfg)
        except Exception:
            log.exception("Scan failed")


HEALTH_FILE = "/tmp/last-registration"


def run(cfg):
    log.info("Printer %s, registering %s as %r every %ds",
             cfg.printer_ip, cfg.host_ip, cfg.display_name, cfg.register_interval)
    if cfg.paperless_url:
        check_paperless(cfg)
    elif not os.access(cfg.output_dir, os.W_OK):
        raise PermissionError(f"output directory {cfg.output_dir} is not writable")

    jobs = queue.Queue()
    threading.Thread(target=scan_worker, args=(cfg, jobs), daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", EVENT_PORT))
    sock.settimeout(1)

    request_id = 1
    next_register = 0.0
    seen = {}  # (REGID, SEQ) -> time; the printer sends every event more than once
    while True:
        now = time.monotonic()
        if now >= next_register:
            try:
                register(cfg, request_id)
                next_register = now + cfg.register_interval
                with open(HEALTH_FILE, "w") as f:
                    f.write(str(int(time.time())))
                log.debug("Registered with printer")
            except (OSError, ValueError, RuntimeError) as e:
                # The printer is often just asleep; retry well inside the TTL.
                log.warning("Registration failed (%s); retrying in 30s", e)
                next_register = now + 30
            request_id = request_id % 0x7FFFFFFF + 1

        try:
            data, (addr, _) = sock.recvfrom(2048)
        except socket.timeout:
            continue
        event = parse_event(data)
        if addr != cfg.printer_ip or not event:
            log.debug("Ignoring datagram from %s: %r", addr, data[:80])
            continue
        if event.get("BUTTON") != "SCAN" or event.get("USER") != cfg.display_name:
            continue
        key = (event.get("REGID"), event.get("SEQ"))
        now = time.monotonic()
        seen = {k: t for k, t in seen.items() if now - t < 60}
        if key in seen:
            continue
        seen[key] = now
        log.info("Scan button pressed (Scan to %s)", event.get("FUNC", "?"))
        jobs.put(event)


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if sys.argv[1:] == ["--healthcheck"]:
        try:
            with open(HEALTH_FILE) as f:
                age = time.time() - int(f.read())
        except (OSError, ValueError):
            return 1
        return 0 if age < REGISTRATION_TTL else 1
    try:
        cfg = Config(os.environ)
    except ValueError as e:
        log.error("%s", e)
        return 1
    if sys.argv[1:] == ["--scan-now"]:
        scan_and_deliver(cfg)
        return 0
    try:
        run(cfg)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
