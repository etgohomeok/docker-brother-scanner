"""Tests for brother_scanner.py. Run with: python -m unittest discover -s tests"""

import base64
import email.parser
import email.policy
import http.server
import logging
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import brother_scanner as bs  # noqa: E402

try:
    import PIL  # noqa: F401
except ImportError:
    PIL = None

# 16x8 px, 1 channel, 150 dpi.
GRAY_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEAlgCWAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcp"
    "LDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAAIABABAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgED"
    "AwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RF"
    "RkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJ"
    "ytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/ACiv/9k="
)
# 8x8 px, 3 channels, 300 dpi.
RGB_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEBLAEsAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcp"
    "LDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy"
    "MjIyMjIyMjIyMjIyMjL/wAARCAAIAAgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAA"
    "AgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6"
    "Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXG"
    "x8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREA"
    "AgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5"
    "OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPE"
    "xcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwCOiiivmj7A/9k="
)

# SNMP SET captured from Brother's brscan-skey 0.3.4, with the panel name and host address
# swapped for same-length placeholders so every BER length byte is unchanged.
BRSCAN_SKEY_REGISTRATION = bytes.fromhex(
    "308202040201000408696e7465726e616ca38201f3020200c9020100020100308201e53078060f2b06010401930302030902"
    "0b0101000465545950453d42523b425554544f4e3d5343414e3b555345523d224d795363616e6e6572223b46554e433d494d"
    "4147453b484f53543d3139382e35312e3130302e31303a35343932353b4150504e554d3d313b4455524154494f4e3d333630"
    "3b425249443d3b3076060f2b060104019303020309020b0101000463545950453d42523b425554544f4e3d5343414e3b5553"
    "45523d224d795363616e6e6572223b46554e433d4f43523b484f53543d3139382e35312e3130302e31303a35343932353b41"
    "50504e554d3d333b4455524154494f4e3d3336303b425249443d3b3078060f2b060104019303020309020b01010004655459"
    "50453d42523b425554544f4e3d5343414e3b555345523d224d795363616e6e6572223b46554e433d454d41494c3b484f5354"
    "3d3139382e35312e3130302e31303a35343932353b4150504e554d3d323b4455524154494f4e3d3336303b425249443d3b30"
    "77060f2b060104019303020309020b0101000464545950453d42523b425554544f4e3d5343414e3b555345523d224d795363"
    "616e6e6572223b46554e433d46494c453b484f53543d3139382e35312e3130302e31303a35343932353b4150504e554d3d35"
    "3b4455524154494f4e3d3336303b425249443d3b"
)


def setUpModule():
    logging.getLogger("brother-scanner").setLevel(logging.CRITICAL)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def config(**env):
    return bs.Config({"PRINTER_IP": "127.0.0.1", **env})


class SnmpTest(unittest.TestCase):
    def test_registration_matches_brscan_skey(self):
        packet = bs.snmp_set_request(
            "internal", 0xC9, bs.REGISTER_OID, bs.registration_strings("MyScanner", "198.51.100.10"))
        self.assertEqual(packet, BRSCAN_SKEY_REGISTRATION)

    def test_reply_parsing(self):
        # The printer answers with the same message as a GetResponse (PDU tag 0xA2).
        reply = bytearray(BRSCAN_SKEY_REGISTRATION)
        reply[reply.index(0xA3)] = 0xA2
        self.assertEqual(bs.snmp_response_status(bytes(reply)), (0xC9, 0))
        with self.assertRaises(ValueError):
            bs.snmp_response_status(BRSCAN_SKEY_REGISTRATION)  # a request, not a response
        with self.assertRaises(ValueError):
            bs.snmp_response_status(bytes(reply[:20]))


class EventTest(unittest.TestCase):
    def test_parse_event(self):
        event = bs.parse_event(
            b'\x02\x00z0TYPE=BR;BUTTON=SCAN;USER="Office";FUNC=FILE;HOST=198.51.100.10:54925;'
            b"APPNUM=5;P1=0;P2=0;P3=0;P4=0;REGID=59830;SEQ=5;")
        self.assertEqual(event["USER"], "Office")
        self.assertEqual(event["FUNC"], "FILE")
        self.assertEqual((event["REGID"], event["SEQ"]), ("59830", "5"))
        self.assertIsNone(bs.parse_event(b"\x00\x01garbage"))


def area_reply(text):
    payload = text.encode() + b"\0"
    return b"\x00" + len(payload).to_bytes(2, "little") + payload


def scan_stream(pages, chunk_size=100):
    """Encode pages the way the printer sends them after ESC X."""
    out = bytearray()
    for number, jpeg in enumerate(pages, start=1):
        header = bytes([0x07, 0x00]) + number.to_bytes(2, "little") + bytes([0x84, 0, 0, 0, 0])
        for i in range(0, len(jpeg), chunk_size):
            chunk = jpeg[i:i + chunk_size]
            out += bytes([0x64]) + header + len(chunk).to_bytes(2, "little") + chunk
        out += bytes([0x82]) + header
    return bytes(out + b"\x80")


class FakeScanner:
    """Serves one scan on localhost, replying to each command in turn."""

    def __init__(self, replies, busy_first=False):
        self.commands = []
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._serve, args=(replies, busy_first), daemon=True).start()

    def _serve(self, replies, busy_first):
        if busy_first:
            conn, _ = self.server.accept()
            conn.sendall(b"-NG 401\r\n")
            conn.close()
        conn, _ = self.server.accept()
        with conn:
            conn.sendall(b"+OK 200\r\n")
            for reply in replies:
                command = b""
                while not command.endswith(b"\x80"):
                    command += conn.recv(4096)
                self.commands.append(command)
                conn.sendall(reply)
        self.server.close()


class ScanTest(unittest.TestCase):
    def scan(self, replies, color_mode, paper, busy_first=False):
        scanner = FakeScanner(replies, busy_first)
        with mock.patch.object(bs, "SCAN_PORT", scanner.port), mock.patch("time.sleep"):
            pages = bs.scan("127.0.0.1", 300, color_mode, bs.PAPER_SIZES[paper])
        return pages, scanner.commands

    def test_adf_pages(self):
        pages, commands = self.scan(
            [area_reply("300,300,1,209,2479,0,0,"), b"\x80", scan_stream([GRAY_JPEG, RGB_JPEG, GRAY_JPEG])],
            "color", "letter", busy_first=True)
        self.assertEqual(pages, [GRAY_JPEG, RGB_JPEG, GRAY_JPEG])
        # The same commands brscan4 sends (captured), apart from the scan height.
        self.assertEqual(commands, [
            b"\x1bI\nR=300,300\nM=CGRAY\n\x80",
            b"\x1bD\nADF\n\x80",
            b"\x1bX\nR=300,300\nM=CGRAY\nC=JPEG\nJ=MID\nB=50\nN=50\nA=19,0,2483,3300\nS=NORMAL_SCAN\nP=0\n\x80",
        ])

    def test_glass_is_clamped_to_scan_area(self):
        pages, commands = self.scan(
            [area_reply("300,300,2,209,2479,291,3437,"), b"\xc2", scan_stream([RGB_JPEG])], "gray", "a4")
        self.assertEqual(pages, [RGB_JPEG])
        self.assertIn(b"M=GRAY64\n", commands[2])
        self.assertIn(b"A=0,0,2464,3437\n", commands[2])

    def test_unknown_chunk_type(self):
        with self.assertRaises(bs.ScanError):
            self.scan([area_reply("300,300,2,209,2479,291,3437,"), b"\xc2", b"\x65" + bytes(20)],
                      "color", "letter")


class PdfTest(unittest.TestCase):
    def test_jpeg_info(self):
        self.assertEqual(bs.jpeg_info(GRAY_JPEG), (16, 8, 1, 150))
        self.assertEqual(bs.jpeg_info(RGB_JPEG), (8, 8, 3, 300))

    def test_pdf_structure(self):
        pdf = bs.jpegs_to_pdf([GRAY_JPEG, RGB_JPEG], 300)
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"/Count 2", pdf)
        self.assertIn(b"/MediaBox [0 0 7.68 3.84]", pdf)  # 16x8 px at 150 dpi
        self.assertIn(b"/MediaBox [0 0 1.92 1.92]", pdf)  # 8x8 px at 300 dpi
        self.assertIn(b"/DeviceGray", pdf)
        self.assertIn(b"/DeviceRGB", pdf)
        # Every xref entry must point at its object.
        xref = int(pdf.rsplit(b"startxref\n", 1)[1].split()[0])
        lines = pdf[xref:].split(b"\n")
        count = int(lines[1].split()[1])
        for number, line in enumerate(lines[3:2 + count], start=1):
            offset = int(line.split()[0])
            self.assertTrue(pdf[offset:].startswith(f"{number} 0 obj".encode()), number)


@unittest.skipIf(PIL is None, "Pillow not installed")
class AdjustTest(unittest.TestCase):
    def test_passthrough_without_adjustments(self):
        pages = [RGB_JPEG]
        self.assertIs(bs.adjust_pages(pages, "color", 0, 0, 300), pages)

    def test_brightness_and_gray(self):
        from PIL import Image, ImageStat
        import io

        darker, = bs.adjust_pages([RGB_JPEG], "gray", -50, 0, 300)
        self.assertEqual(bs.jpeg_info(darker), (8, 8, 1, 300))
        original = ImageStat.Stat(Image.open(io.BytesIO(RGB_JPEG)).convert("L")).mean[0]
        self.assertLess(ImageStat.Stat(Image.open(io.BytesIO(darker))).mean[0], original * 0.6)


class FakePaperless(http.server.BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakePaperless.requests.append((self.path, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'"0b6e2a38-task"')

    def log_message(self, *args):
        pass


class OutputTest(unittest.TestCase):
    def test_save_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            first = bs.save_pdf(b"one", d, "scan.pdf")
            second = bs.save_pdf(b"two", d, "scan.pdf")
            self.assertEqual(os.path.basename(second), "scan_2.pdf")
            self.assertEqual(sorted(os.listdir(d)), ["scan.pdf", "scan_2.pdf"])
            with open(first, "rb") as f:
                self.assertEqual(f.read(), b"one")

    def test_folder_output_uses_filename_pattern(self):
        with tempfile.TemporaryDirectory() as d:
            path = bs.deliver(config(OUTPUT_DIR=d, FILENAME_PATTERN="office-%Y.pdf"), b"%PDF")
            self.assertEqual(os.path.basename(path), time.strftime("office-%Y.pdf"))

    def test_paperless_upload(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), FakePaperless)
        threading.Thread(target=server.handle_request, daemon=True).start()
        cfg = config(PAPERLESS_URL=f"http://127.0.0.1:{server.server_port}/", PAPERLESS_TOKEN="secret",
                     FILENAME_PATTERN="doc")
        self.assertEqual(bs.deliver(cfg, b"%PDF-1.4 test"), "Paperless (task 0b6e2a38-task)")
        server.server_close()

        path, headers, body = FakePaperless.requests[-1]
        self.assertEqual(path, "/api/documents/post_document/")
        self.assertEqual(headers["Authorization"], "Token secret")
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            f"Content-Type: {headers['Content-Type']}\r\n\r\n".encode() + body)
        part, = message.iter_parts()
        self.assertEqual(part.get_param("name", header="content-disposition"), "document")
        self.assertEqual(part.get_filename(), "doc.pdf")
        self.assertEqual(part.get_content(), b"%PDF-1.4 test")

    def test_failed_upload_falls_back_to_folder(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("time.sleep"):
            cfg = config(PAPERLESS_URL=f"http://127.0.0.1:{free_port()}", PAPERLESS_TOKEN="t",
                         OUTPUT_DIR=d, FILENAME_PATTERN="doc")
            self.assertEqual(bs.deliver(cfg, b"%PDF"), os.path.join(d, "doc.pdf"))


class ConfigTest(unittest.TestCase):
    def test_defaults(self):
        cfg = config()
        self.assertEqual(cfg.color_mode, "color")
        self.assertEqual(cfg.resolution, 300)
        self.assertEqual(cfg.paper, bs.PAPER_SIZES["letter"])
        self.assertEqual((cfg.brightness, cfg.contrast), (0, 0))
        self.assertEqual(cfg.display_name, socket.gethostname().split(".")[0])
        self.assertEqual(cfg.host_ip, "127.0.0.1")
        self.assertEqual(cfg.paperless_url, "")

    def test_invalid_values(self):
        for env in [
            {"PRINTER_IP": ""},
            {"SCAN_COLOR_MODE": "sepia"},
            {"SCAN_RESOLUTION": "250"},
            {"SCAN_PAPER_SIZE": "tabloid"},
            {"SCAN_BRIGHTNESS": "51"},
            {"SCAN_CONTRAST": "-51"},
            {"SCAN_DISPLAY_NAME": 'a"b'},
            {"FILENAME_PATTERN": "a/b"},
            {"PAPERLESS_URL": "http://paperless:8000"},
            {"PAPERLESS_URL": "paperless:8000", "PAPERLESS_TOKEN": "t"},
            {"REGISTER_INTERVAL_SECONDS": "360"},
        ]:
            with self.subTest(env=env), self.assertRaises(ValueError):
                config(**env)


class DaemonTest(unittest.TestCase):
    def test_duplicate_and_foreign_events_are_ignored(self):
        scans, registrations = [], []
        port = free_port(socket.SOCK_DGRAM)
        with tempfile.TemporaryDirectory() as d:
            patches = [
                mock.patch.object(bs, "EVENT_PORT", port),
                mock.patch.object(bs, "HEALTH_FILE", os.path.join(d, "health")),
                mock.patch.object(bs, "register", lambda cfg, rid: registrations.append(rid)),
                mock.patch.object(bs, "scan_and_deliver", lambda cfg: scans.append(cfg)),
            ]
            for p in patches:
                p.start()
                self.addCleanup(p.stop)
            cfg = config(SCAN_DISPLAY_NAME="Office", OUTPUT_DIR=d, REGISTER_INTERVAL_SECONDS="359")
            threading.Thread(target=bs.run, args=(cfg,), daemon=True).start()
            time.sleep(0.3)

            def press(user, seq):
                msg = f'TYPE=BR;BUTTON=SCAN;USER="{user}";FUNC=FILE;APPNUM=5;REGID=1;SEQ={seq};'.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"\x02\x00" + bytes([len(msg)]) + b"0" + msg, ("127.0.0.1", port))

            press("Office", 7)
            press("Office", 7)  # the printer repeats every event
            press("Someone", 8)  # another host's panel entry
            press("Office", 9)
            time.sleep(0.5)
            self.assertEqual(len(scans), 2)
            self.assertEqual(registrations, [1])
            sys.argv, argv = ["brother_scanner.py", "--healthcheck"], sys.argv
            try:
                self.assertEqual(bs.main(), 0)
            finally:
                sys.argv = argv


if __name__ == "__main__":
    unittest.main()
