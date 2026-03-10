from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha224
from ipaddress import ip_address
import re
from socket import socket
from typing import Any
from urllib.parse import urljoin, urlparse
import socket as socket_lib
import ssl
import json

@dataclass(frozen=True)
class ProxyConfig:
	remote_addr: str = "ty-5.tr202513.com"
	remote_port: int = 443
	password: str = "6XOYipS4auCYCD9PJQ"
	verify: bool = False
	verify_hostname: bool = True
	sni: str = ""
	alpn: tuple[str, ...] = ("h2", "http/1.1")


@dataclass(frozen=True)
class SimpleHttpResponse:
	status_code: int
	headers: dict[str, str]
	content: bytes
	url: str

	@property
	def text(self) -> str:
		content_type = self.headers.get("content-type", "")
		charset = "utf-8"
		for part in content_type.split(";"):
			part = part.strip()
			if part.lower().startswith("charset="):
				charset = part.split("=", 1)[1].strip() or "utf-8"
				break

		try:
			return self.content.decode(charset, errors="replace")
		except LookupError:
			return self.content.decode("utf-8", errors="replace")

	@property
	def readable_text(self) -> str:
		return decode_escaped_text(self.text)


def decode_escaped_text(text: str) -> str:
	text = re.sub(
		r"\\u([0-9a-fA-F]{4})",
		lambda match: chr(int(match.group(1), 16)),
		text,
	)
	text = re.sub(
		r"\\U([0-9a-fA-F]{8})",
		lambda match: chr(int(match.group(1), 16)),
		text,
	)
	text = re.sub(
		r"\\x([0-9a-fA-F]{2})",
		lambda match: chr(int(match.group(1), 16)),
		text,
	)
	return text


class TrojanTunnelStream:
	def __init__(self, proxy_config: ProxyConfig, timeout: int) -> None:
		self.proxy_config = proxy_config
		self.timeout = timeout
		self.sock: socket | None = None

	def __enter__(self) -> TrojanTunnelStream:
		return self

	def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
		self.close()

	def connect(self, target_host: str, target_port: int) -> None:
		raw_socket = socket_lib.create_connection(
			(self.proxy_config.remote_addr, self.proxy_config.remote_port),
			timeout=self.timeout,
		)
		ssl_context = ssl.create_default_context()
		ssl_context.check_hostname = self.proxy_config.verify and self.proxy_config.verify_hostname
		ssl_context.verify_mode = ssl.CERT_REQUIRED if self.proxy_config.verify else ssl.CERT_NONE
		ssl_context.set_alpn_protocols(list(self.proxy_config.alpn))
		server_hostname = self.proxy_config.sni or self.proxy_config.remote_addr
		self.sock = ssl_context.wrap_socket(raw_socket, server_hostname=server_hostname)
		self.sock.settimeout(self.timeout)
		self.sock.sendall(self._build_trojan_request(target_host, target_port))

	def _build_trojan_request(self, target_host: str, target_port: int) -> bytes:
		password = sha224(self.proxy_config.password.encode("utf-8")).hexdigest().encode("ascii")
		address = self._encode_address(target_host)
		port = target_port.to_bytes(2, byteorder="big")
		return password + b"\r\n" + b"\x01" + address + port + b"\r\n"

	def _encode_address(self, target_host: str) -> bytes:
		try:
			ip_value = ip_address(target_host)
		except ValueError:
			host_bytes = target_host.encode("idna")
			return b"\x03" + bytes([len(host_bytes)]) + host_bytes

		if ip_value.version == 4:
			return b"\x01" + ip_value.packed

		return b"\x04" + ip_value.packed

	def sendall(self, data: bytes) -> None:
		if self.sock is None:
			raise RuntimeError("tunnel is not connected")
		self.sock.sendall(data)

	def recv(self, size: int = 65536) -> bytes:
		if self.sock is None:
			raise RuntimeError("tunnel is not connected")
		return self.sock.recv(size)

	def close(self) -> None:
		if self.sock is None:
			return
		try:
			self.sock.close()
		finally:
			self.sock = None


class TlsOverTrojanStream:
	def __init__(self, stream: TrojanTunnelStream, server_hostname: str) -> None:
		self.stream = stream
		self.incoming = ssl.MemoryBIO()
		self.outgoing = ssl.MemoryBIO()
		self.context = ssl.create_default_context()
		self.ssl_object = self.context.wrap_bio(
			self.incoming,
			self.outgoing,
			server_side=False,
			server_hostname=server_hostname,
		)

	def do_handshake(self) -> None:
		while True:
			try:
				self.ssl_object.do_handshake()
				self._flush_outgoing()
				return
			except ssl.SSLWantWriteError:
				self._flush_outgoing()
			except ssl.SSLWantReadError:
				self._flush_outgoing()
				self._feed_incoming()

	def sendall(self, data: bytes) -> None:
		view = memoryview(data)
		while view:
			try:
				written = self.ssl_object.write(view)
				view = view[written:]
				self._flush_outgoing()
			except ssl.SSLWantWriteError:
				self._flush_outgoing()
			except ssl.SSLWantReadError:
				self._flush_outgoing()
				self._feed_incoming()

	def recv_all(self) -> bytes:
		chunks: list[bytes] = []
		while True:
			try:
				chunk = self.ssl_object.read(65536)
				if chunk:
					chunks.append(chunk)
					continue
			except ssl.SSLWantReadError:
				self._flush_outgoing()
				if not self._feed_incoming():
					break
				continue
			except ssl.SSLZeroReturnError:
				break

			self._flush_outgoing()
			if not self._feed_incoming():
				break

		self._flush_outgoing()
		return b"".join(chunks)

	def _flush_outgoing(self) -> None:
		while True:
			data = self.outgoing.read()
			if not data:
				return
			self.stream.sendall(data)

	def _feed_incoming(self) -> bool:
		data = self.stream.recv()
		if not data:
			return False
		self.incoming.write(data)
		return True


class ProxyHttpClient:
	def __init__(self, proxy_config: ProxyConfig, timeout: int = 10) -> None:
		self.proxy_config = proxy_config
		self.timeout = timeout

	def request(self, method: str, url: str, **kwargs: Any) -> SimpleHttpResponse:
		if kwargs:
			raise ValueError(f"unsupported request options: {', '.join(sorted(kwargs))}")

		redirect_limit = 5
		current_url = url
		current_method = method.upper()

		for _ in range(redirect_limit + 1):
			response = self._single_request(current_method, current_url)
			location = response.headers.get("location")
			if response.status_code not in {301, 302, 303, 307, 308} or not location:
				return response

			current_url = urljoin(current_url, location)
			if response.status_code == 303:
				current_method = "GET"

		raise RuntimeError("too many redirects")

	def _single_request(self, method: str, url: str) -> SimpleHttpResponse:
		parsed = urlparse(url)
		if parsed.scheme not in {"http", "https"}:
			raise ValueError(f"unsupported scheme: {parsed.scheme}")

		host = parsed.hostname
		if not host:
			raise ValueError("url is missing host")

		port = parsed.port or (443 if parsed.scheme == "https" else 80)
		path = parsed.path or "/"
		if parsed.query:
			path = f"{path}?{parsed.query}"

		request_data = self._build_http_request(method, host, path)
		with TrojanTunnelStream(self.proxy_config, timeout=self.timeout) as tunnel:
			tunnel.connect(host, port)
			if parsed.scheme == "https":
				raw_response = self._https_request(tunnel, host, request_data)
			else:
				tunnel.sendall(request_data)
				raw_response = self._read_plain_response(tunnel)

			return self._parse_response(url, raw_response)

	def _build_http_request(self, method: str, host: str, path: str) -> bytes:
		headers = [
			f"{method} {path} HTTP/1.1",
			f"Host: {host}",
			"User-Agent: PythonTrojanHttpClient/1.0",
			"Accept: */*",
			"Accept-Encoding: identity",
			"Connection: close",
			"",
			"",
		]
		return "\r\n".join(headers).encode("utf-8")

	def _https_request(self, tunnel: TrojanTunnelStream, host: str, request_data: bytes) -> bytes:
		tls_stream = TlsOverTrojanStream(tunnel, server_hostname=host)
		tls_stream.do_handshake()
		tls_stream.sendall(request_data)
		return tls_stream.recv_all()

	def _read_plain_response(self, tunnel: TrojanTunnelStream) -> bytes:
		chunks: list[bytes] = []
		while True:
			chunk = tunnel.recv()
			if not chunk:
				break
			chunks.append(chunk)
		return b"".join(chunks)

	def _parse_response(self, url: str, raw_response: bytes) -> SimpleHttpResponse:
		if b"\r\n\r\n" not in raw_response:
			raise RuntimeError("invalid HTTP response received from proxy tunnel")

		headers_part, body = raw_response.split(b"\r\n\r\n", 1)
		header_lines = headers_part.decode("iso-8859-1").split("\r\n")
		status_line = header_lines[0]
		try:
			_, status_code_text, _ = status_line.split(" ", 2)
		except ValueError as exc:
			raise RuntimeError(f"invalid HTTP status line: {status_line}") from exc

		headers: dict[str, str] = {}
		for line in header_lines[1:]:
			if not line or ":" not in line:
				continue
			name, value = line.split(":", 1)
			headers[name.strip().lower()] = value.strip()

		if headers.get("transfer-encoding", "").lower() == "chunked":
			body = self._decode_chunked_body(body)

		return SimpleHttpResponse(
			status_code=int(status_code_text),
			headers=headers,
			content=body,
			url=url,
		)

	def _decode_chunked_body(self, body: bytes) -> bytes:
		result = bytearray()
		index = 0
		while True:
			line_end = body.find(b"\r\n", index)
			if line_end == -1:
				break

			size_text = body[index:line_end].split(b";", 1)[0]
			size = int(size_text, 16)
			index = line_end + 2
			if size == 0:
				break

			result.extend(body[index:index + size])
			index += size + 2

		return bytes(result)

	def get(self, url: str, **kwargs: Any) -> SimpleHttpResponse:
		return self.request("GET", url, **kwargs)

	def post(self, url: str, **kwargs: Any) -> SimpleHttpResponse:
		return self.request("POST", url, **kwargs)


PROXY_CONFIG = ProxyConfig()
http_client = ProxyHttpClient(PROXY_CONFIG)


def http_get(url: str, **kwargs: Any) -> str:
	response = http_client.get(url, **kwargs)
	return response.readable_text


if __name__ == "__main__":
	target_url = "http://66capanoglu.com:8080/player_api.php?username=zehra@senol&password=15082022&action=get_live_categories"
	target_stream = "http://66capanoglu.com:8080/player_api.php?username=zehra@senol&password=15082022&action=get_live_streams"
	try:
		cats = json.loads(http_client.get(target_url).readable_text)
		cat_map = {c["category_id"]: c["category_name"] for c in cats}
		streams = json.loads(http_client.get(target_stream).readable_text)
		lines = ["#EXTM3U"]
		for s in streams:
			name      = s.get("name", "Unbekannt")
			logo      = s.get("stream_icon", "")
			group     = cat_map.get(s.get("category_id", ""), "Live TV")
			stream_id = s.get("stream_id")
			ext       = s.get("container_extension", "ts")
			url       = f"http://66capanoglu.com:8080/live/zehra@senol/15082022/{stream_id}.{ext}"
			lines.append(f'#EXTINF:-1 tvg-logo="{logo}" group-title="{group}",{name}')
			lines.append(url)

		with open("live.m3u", "w", encoding="utf-8") as f:
			f.write("\n".join(lines))
	except Exception as exc:
		print("request failed:", exc)
		print(
			"remote proxy endpoint:",
			f"{PROXY_CONFIG.remote_addr}:{PROXY_CONFIG.remote_port}",
		)
