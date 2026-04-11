#!/usr/bin/env python3
"""
Hole-punch interop client (py-libp2p), matching hole-punch-interop/README.md.

Redis: relay addresses on RELAY_TCP_ADDRESS / RELAY_QUIC_ADDRESS; listener publishes
LISTEN_CLIENT_PEER_ID after a successful relay reservation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import json
import logging
import os
import socket
import sys
import time
from types import MethodType
from typing import cast

import multiaddr
from multiaddr.exceptions import ProtocolLookupError
import redis
import trio

from libp2p import create_yamux_muxer_option, new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.crypto.x25519 import create_new_key_pair as create_new_x25519_key_pair
from libp2p.connection_types import ConnectionType
from libp2p.custom_types import TProtocol
from libp2p.host.basic_host import BasicHost
from libp2p.host.ping import PingService
from libp2p.identity.identify.identify import ID as IDENTIFY_PROTOCOL_ID
from libp2p.identity.identify.pb.identify_pb2 import Identify
from libp2p.io.trio import TrioTCPStream
from libp2p.network.connection.raw_connection import RawConnection
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
from libp2p.relay.circuit_v2.dcutr import (
    MAX_HOLE_PUNCH_ATTEMPTS,
    PROTOCOL_ID as DCUTR_PROTOCOL_ID,
    DCUtRProtocol,
)
from libp2p.relay.circuit_v2.pb.dcutr_pb2 import HolePunch
from libp2p.security.noise.transport import (
    PROTOCOL_ID as NOISE_PROTOCOL_ID,
    Transport as NoiseTransport,
)
from libp2p.tools.anyio_service import background_trio_service
from libp2p.transport.exceptions import OpenConnectionError
from libp2p.transport.transport_registry import register_transport
from libp2p.utils.multiaddr_utils import extract_ip_from_multiaddr, multiaddr_from_socket
from libp2p.utils.varint import encode_uvarint, read_length_prefixed_protobuf

logger = logging.getLogger("hole_punch_client")

RELAY_TCP_ADDRESS = "RELAY_TCP_ADDRESS"
RELAY_QUIC_ADDRESS = "RELAY_QUIC_ADDRESS"
LISTEN_CLIENT_PEER_ID = "LISTEN_CLIENT_PEER_ID"
LEGACY_HOP_PROTOCOL_ID = TProtocol("/libp2p/circuit/relay/0.2.0/hop")
LEGACY_STOP_PROTOCOL_ID = TProtocol("/libp2p/circuit/relay/0.2.0/stop")


class _LegacyHopType(IntEnum):
    RESERVE = 0
    CONNECT = 1
    STATUS = 2


class _LegacyStopType(IntEnum):
    CONNECT = 0
    STATUS = 1


class _LegacyStatus(IntEnum):
    OK = 100
    RESERVATION_REFUSED = 200
    RESOURCE_LIMIT_EXCEEDED = 201
    PERMISSION_DENIED = 202
    CONNECTION_FAILED = 203
    NO_RESERVATION = 204
    MALFORMED_MESSAGE = 400
    UNEXPECTED_MESSAGE = 401


@dataclass(frozen=True)
class _LegacyPeer:
    peer_id: bytes
    addrs: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class _LegacyReservation:
    expire: int | None = None
    addrs: tuple[bytes, ...] = ()
    voucher: bytes | None = None


@dataclass(frozen=True)
class _LegacyLimit:
    duration: int | None = None
    data: int | None = None


@dataclass(frozen=True)
class _LegacyHopMessage:
    type: int
    peer: _LegacyPeer | None = None
    reservation: _LegacyReservation | None = None
    limit: _LegacyLimit | None = None
    status: int | None = None


@dataclass(frozen=True)
class _LegacyStopMessage:
    type: int
    peer: _LegacyPeer | None = None
    limit: _LegacyLimit | None = None
    status: int | None = None


class _LegacyProtoError(ValueError):
    pass


class _HolePunchTCPListener:
    def __init__(self, handler_function, transport: "_HolePunchTCP") -> None:
        self.listeners: list[trio.SocketListener] = []
        self.handler = handler_function
        self._transport = transport

    async def listen(self, maddr: multiaddr.Multiaddr, nursery: trio.Nursery) -> None:
        try:
            tcp_port_str = maddr.value_for_protocol("tcp")
        except ProtocolLookupError:
            raise OpenConnectionError(
                f"Cannot listen: TCP port is missing in multiaddress {maddr}"
            ) from None

        if tcp_port_str is None:
            raise OpenConnectionError(
                f"Cannot listen: TCP port is missing in multiaddress {maddr}"
            )

        try:
            tcp_port = int(tcp_port_str)
        except ValueError as error:
            raise OpenConnectionError(
                f"Cannot listen: invalid TCP port {tcp_port_str!r} in {maddr}"
            ) from error

        host_str = extract_ip_from_multiaddr(maddr) or "0.0.0.0"
        family = socket.AF_INET6 if ":" in host_str else socket.AF_INET

        sock = trio.socket.socket(family, trio.socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        await sock.bind((host_str, tcp_port))
        sock.listen()

        listener = trio.SocketListener(sock)
        self.listeners.append(listener)
        self._transport.set_shared_port(sock.getsockname()[1])

        async def handler(stream: trio.SocketStream) -> None:
            remote_host = ""
            remote_port = 0
            try:
                tcp_stream = TrioTCPStream(stream)
                remote_tuple = tcp_stream.get_remote_address()
                if remote_tuple is not None:
                    remote_host, remote_port = remote_tuple
                await self.handler(tcp_stream)
            except Exception as exc:
                logger.warning(
                    "incoming TCP connection from %s:%s failed: %s",
                    remote_host,
                    remote_port,
                    f"{type(exc).__name__}: {exc!r}",
                )

        nursery.start_soon(trio.serve_listeners, handler, [listener])

    def get_addrs(self) -> tuple[multiaddr.Multiaddr, ...]:
        return tuple(
            multiaddr_from_socket(listener.socket) for listener in self.listeners
        )

    async def close(self) -> None:
        async with trio.open_nursery() as nursery:
            for listener in self.listeners:
                nursery.start_soon(listener.aclose)


class _HolePunchTCP:
    def __init__(self) -> None:
        self._shared_port: int | None = None

    def set_shared_port(self, port: int) -> None:
        if self._shared_port is None:
            logger.info("using shared TCP hole-punch port %s", port)
        self._shared_port = port

    async def dial(self, maddr: multiaddr.Multiaddr) -> RawConnection:
        host_str = extract_ip_from_multiaddr(maddr)
        port_str = maddr.value_for_protocol("tcp")

        if host_str is None:
            raise OpenConnectionError(
                f"Failed to dial {maddr}: IP address not found in multiaddr."
            )
        if port_str is None:
            raise OpenConnectionError(
                f"Failed to dial {maddr}: TCP port not found in multiaddr."
            )

        try:
            port_int = int(port_str)
        except ValueError as error:
            raise OpenConnectionError(
                f"Failed to dial {maddr}: invalid TCP port {port_str!r}."
            ) from error

        family = socket.AF_INET6 if ":" in host_str else socket.AF_INET
        bind_host = "::" if family == socket.AF_INET6 else "0.0.0.0"
        sock = trio.socket.socket(family, trio.socket.SOCK_STREAM)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            if self._shared_port is not None:
                await sock.bind((bind_host, self._shared_port))

            await sock.connect((host_str, port_int))
            stream = trio.SocketStream(sock)
            return RawConnection(TrioTCPStream(stream), True)
        except OSError as error:
            try:
                sock.close()
            except Exception:
                pass
            raise OpenConnectionError(
                f"Failed to open TCP stream to {maddr}: {error}"
            ) from error
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

    def create_listener(self, handler_function) -> _HolePunchTCPListener:
        return _HolePunchTCPListener(handler_function, self)


def _redis() -> redis.Redis:
    return redis.Redis(
        host="redis",
        port=6379,
        decode_responses=True,
        socket_timeout=None,
        socket_connect_timeout=30,
    )


def _relay_key(tp: str) -> str:
    if tp == "tcp":
        return RELAY_TCP_ADDRESS
    if tp == "quic":
        return RELAY_QUIC_ADDRESS
    raise ValueError(f"TRANSPORT must be tcp or quic, got {tp!r}")


def _pop_relay(r: redis.Redis, tp: str) -> str:
    key = _relay_key(tp)
    item = r.blpop(key, timeout=0)
    if not item:
        raise RuntimeError(f"empty blpop for {key}")
    _, val = item
    return val


def _push(r: redis.Redis, key: str, value: str) -> None:
    r.rpush(key, value)


def _pop_listener_id(r: redis.Redis) -> str:
    item = r.blpop(LISTEN_CLIENT_PEER_ID, timeout=0)
    if not item:
        raise RuntimeError("empty blpop for LISTEN_CLIENT_PEER_ID")
    _, val = item
    return val


def _listen_maddr(tp: str) -> multiaddr.Multiaddr:
    if tp == "tcp":
        return multiaddr.Multiaddr("/ip4/0.0.0.0/tcp/0")
    if tp == "quic":
        return multiaddr.Multiaddr("/ip4/0.0.0.0/udp/0/quic-v1")
    raise ValueError(tp)


def _make_host(tp: str):
    if tp == "tcp":
        register_transport("tcp", _HolePunchTCP)

    key_pair = create_new_key_pair()
    noise_kp = create_new_x25519_key_pair()
    noise_transport = NoiseTransport(
        libp2p_keypair=key_pair,
        noise_privkey=noise_kp.private_key,
        early_data=None,
    )
    sec_opt = {NOISE_PROTOCOL_ID: noise_transport}
    return new_host(
        key_pair=key_pair,
        muxer_opt=create_yamux_muxer_option(),
        sec_opt=sec_opt,
        listen_addrs=[_listen_maddr(tp)],
        enable_quic=(tp == "quic"),
    )


def _encode_varint_field(field_no: int, value: int) -> bytes:
    return encode_uvarint((field_no << 3) | 0) + encode_uvarint(value)


def _encode_bytes_field(field_no: int, value: bytes) -> bytes:
    return encode_uvarint((field_no << 3) | 2) + encode_uvarint(len(value)) + value


def _encode_legacy_peer(peer: _LegacyPeer) -> bytes:
    data = bytearray()
    data.extend(_encode_bytes_field(1, peer.peer_id))
    for addr in peer.addrs:
        data.extend(_encode_bytes_field(2, addr))
    return bytes(data)


def _encode_legacy_reservation(reservation: _LegacyReservation) -> bytes:
    data = bytearray()
    if reservation.expire is not None:
        data.extend(_encode_varint_field(1, reservation.expire))
    for addr in reservation.addrs:
        data.extend(_encode_bytes_field(2, addr))
    if reservation.voucher:
        data.extend(_encode_bytes_field(3, reservation.voucher))
    return bytes(data)


def _encode_legacy_limit(limit: _LegacyLimit) -> bytes:
    data = bytearray()
    if limit.duration is not None:
        data.extend(_encode_varint_field(1, limit.duration))
    if limit.data is not None:
        data.extend(_encode_varint_field(2, limit.data))
    return bytes(data)


def _encode_legacy_hop(message: _LegacyHopMessage) -> bytes:
    data = bytearray()
    data.extend(_encode_varint_field(1, int(message.type)))
    if message.peer is not None:
        data.extend(_encode_bytes_field(2, _encode_legacy_peer(message.peer)))
    if message.reservation is not None:
        data.extend(
            _encode_bytes_field(3, _encode_legacy_reservation(message.reservation))
        )
    if message.limit is not None:
        data.extend(_encode_bytes_field(4, _encode_legacy_limit(message.limit)))
    if message.status is not None:
        data.extend(_encode_varint_field(5, int(message.status)))
    return bytes(data)


def _encode_legacy_stop(message: _LegacyStopMessage) -> bytes:
    data = bytearray()
    data.extend(_encode_varint_field(1, int(message.type)))
    if message.peer is not None:
        data.extend(_encode_bytes_field(2, _encode_legacy_peer(message.peer)))
    if message.limit is not None:
        data.extend(_encode_bytes_field(3, _encode_legacy_limit(message.limit)))
    if message.status is not None:
        data.extend(_encode_varint_field(4, int(message.status)))
    return bytes(data)


def _read_wire_varint(data: bytes, idx: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if idx >= len(data):
            raise _LegacyProtoError("truncated varint")
        byte = data[idx]
        idx += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, idx
        shift += 7
        if shift >= 64:
            raise _LegacyProtoError("varint too long")


def _read_wire_bytes(data: bytes, idx: int) -> tuple[bytes, int]:
    length, idx = _read_wire_varint(data, idx)
    end = idx + length
    if end > len(data):
        raise _LegacyProtoError("truncated length-delimited field")
    return data[idx:end], end


def _skip_unknown_field(data: bytes, idx: int, wire_type: int) -> int:
    if wire_type == 0:
        _, idx = _read_wire_varint(data, idx)
        return idx
    if wire_type == 2:
        _, idx = _read_wire_bytes(data, idx)
        return idx
    raise _LegacyProtoError(f"unsupported wire type {wire_type}")


def _parse_legacy_peer(data: bytes) -> _LegacyPeer:
    peer_id = b""
    addrs: list[bytes] = []
    idx = 0
    while idx < len(data):
        tag, idx = _read_wire_varint(data, idx)
        field_no, wire_type = tag >> 3, tag & 7
        if field_no == 1 and wire_type == 2:
            peer_id, idx = _read_wire_bytes(data, idx)
        elif field_no == 2 and wire_type == 2:
            addr, idx = _read_wire_bytes(data, idx)
            addrs.append(addr)
        else:
            idx = _skip_unknown_field(data, idx, wire_type)
    if not peer_id:
        raise _LegacyProtoError("legacy peer missing id")
    return _LegacyPeer(peer_id=peer_id, addrs=tuple(addrs))


def _parse_legacy_reservation(data: bytes) -> _LegacyReservation:
    expire: int | None = None
    addrs: list[bytes] = []
    voucher: bytes | None = None
    idx = 0
    while idx < len(data):
        tag, idx = _read_wire_varint(data, idx)
        field_no, wire_type = tag >> 3, tag & 7
        if field_no == 1 and wire_type == 0:
            expire, idx = _read_wire_varint(data, idx)
        elif field_no == 2 and wire_type == 2:
            addr, idx = _read_wire_bytes(data, idx)
            addrs.append(addr)
        elif field_no == 3 and wire_type == 2:
            voucher, idx = _read_wire_bytes(data, idx)
        else:
            idx = _skip_unknown_field(data, idx, wire_type)
    return _LegacyReservation(expire=expire, addrs=tuple(addrs), voucher=voucher)


def _parse_legacy_limit(data: bytes) -> _LegacyLimit:
    duration: int | None = None
    size_limit: int | None = None
    idx = 0
    while idx < len(data):
        tag, idx = _read_wire_varint(data, idx)
        field_no, wire_type = tag >> 3, tag & 7
        if field_no == 1 and wire_type == 0:
            duration, idx = _read_wire_varint(data, idx)
        elif field_no == 2 and wire_type == 0:
            size_limit, idx = _read_wire_varint(data, idx)
        else:
            idx = _skip_unknown_field(data, idx, wire_type)
    return _LegacyLimit(duration=duration, data=size_limit)


def _parse_legacy_hop(data: bytes) -> _LegacyHopMessage:
    message_type: int | None = None
    peer: _LegacyPeer | None = None
    reservation: _LegacyReservation | None = None
    limit: _LegacyLimit | None = None
    status: int | None = None
    idx = 0
    while idx < len(data):
        tag, idx = _read_wire_varint(data, idx)
        field_no, wire_type = tag >> 3, tag & 7
        if field_no == 1 and wire_type == 0:
            message_type, idx = _read_wire_varint(data, idx)
        elif field_no == 2 and wire_type == 2:
            peer_bytes, idx = _read_wire_bytes(data, idx)
            peer = _parse_legacy_peer(peer_bytes)
        elif field_no == 3 and wire_type == 2:
            reservation_bytes, idx = _read_wire_bytes(data, idx)
            reservation = _parse_legacy_reservation(reservation_bytes)
        elif field_no == 4 and wire_type == 2:
            limit_bytes, idx = _read_wire_bytes(data, idx)
            limit = _parse_legacy_limit(limit_bytes)
        elif field_no == 5 and wire_type == 0:
            status, idx = _read_wire_varint(data, idx)
        else:
            idx = _skip_unknown_field(data, idx, wire_type)
    if message_type is None:
        raise _LegacyProtoError("legacy hop message missing type")
    return _LegacyHopMessage(
        type=message_type,
        peer=peer,
        reservation=reservation,
        limit=limit,
        status=status,
    )


def _parse_legacy_stop(data: bytes) -> _LegacyStopMessage:
    message_type: int | None = None
    peer: _LegacyPeer | None = None
    limit: _LegacyLimit | None = None
    status: int | None = None
    idx = 0
    while idx < len(data):
        tag, idx = _read_wire_varint(data, idx)
        field_no, wire_type = tag >> 3, tag & 7
        if field_no == 1 and wire_type == 0:
            message_type, idx = _read_wire_varint(data, idx)
        elif field_no == 2 and wire_type == 2:
            peer_bytes, idx = _read_wire_bytes(data, idx)
            peer = _parse_legacy_peer(peer_bytes)
        elif field_no == 3 and wire_type == 2:
            limit_bytes, idx = _read_wire_bytes(data, idx)
            limit = _parse_legacy_limit(limit_bytes)
        elif field_no == 4 and wire_type == 0:
            status, idx = _read_wire_varint(data, idx)
        else:
            idx = _skip_unknown_field(data, idx, wire_type)
    if message_type is None:
        raise _LegacyProtoError("legacy stop message missing type")
    return _LegacyStopMessage(type=message_type, peer=peer, limit=limit, status=status)


def _legacy_status_name(status: int | None) -> str:
    if status is None:
        return "missing"
    try:
        return _LegacyStatus(status).name
    except ValueError:
        return f"UNKNOWN({status})"


async def _read_exact(stream, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = await stream.read(remaining)
        if not chunk:
            raise EOFError(f"expected {size} bytes, got {size - remaining}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


async def _read_legacy_message(stream) -> bytes:
    prefix = bytearray()
    while True:
        byte = await _read_exact(stream, 1)
        prefix.extend(byte)
        if byte[0] & 0x80 == 0:
            break
    message_len, _ = _read_wire_varint(bytes(prefix), 0)
    return await _read_exact(stream, message_len)


async def _write_legacy_message(stream, payload: bytes) -> None:
    await stream.write(encode_uvarint(len(payload)) + payload)


async def _connect_relay(host: BasicHost, relay_info: PeerInfo, attempts: int = 10) -> None:
    last_exc: BaseException | None = None
    for i in range(attempts):
        try:
            with trio.fail_after(30):
                await host.connect(relay_info)
            return
        except BaseException as exc:
            last_exc = exc
            logger.warning(
                "connect to relay attempt %s/%s failed: %s", i + 1, attempts, exc
            )
            await trio.sleep(1.0 + float(i))
    assert last_exc is not None
    raise last_exc


async def _reserve_with_legacy_relay(host: BasicHost, relay_peer_id: ID) -> None:
    stream = None
    try:
        with trio.fail_after(15):
            stream = await host.new_stream(relay_peer_id, [LEGACY_HOP_PROTOCOL_ID])
        request = _encode_legacy_hop(
            _LegacyHopMessage(type=_LegacyHopType.RESERVE),
        )
        await _write_legacy_message(stream, request)
        response = _parse_legacy_hop(await _read_legacy_message(stream))
        if response.type != _LegacyHopType.STATUS:
            raise RuntimeError(f"unexpected relay hop response type {response.type}")
        if response.status != _LegacyStatus.OK:
            raise RuntimeError(
                f"relay reservation failed with {_legacy_status_name(response.status)}"
            )
        logger.info("legacy relay reservation established with %s", relay_peer_id)
    finally:
        if stream is not None:
            try:
                await stream.close()
            except Exception:
                pass


async def _dial_via_legacy_relay(
    host: BasicHost,
    relay_peer_id: ID,
    dest_peer_id: ID,
    circuit_ma: multiaddr.Multiaddr,
) -> None:
    stream = None
    try:
        with trio.fail_after(15):
            stream = await host.new_stream(relay_peer_id, [LEGACY_HOP_PROTOCOL_ID])
        request = _encode_legacy_hop(
            _LegacyHopMessage(
                type=_LegacyHopType.CONNECT,
                peer=_LegacyPeer(peer_id=dest_peer_id.to_bytes()),
            )
        )
        await _write_legacy_message(stream, request)
        response = _parse_legacy_hop(await _read_legacy_message(stream))
        if response.type != _LegacyHopType.STATUS:
            raise RuntimeError(f"unexpected relay hop response type {response.type}")
        if response.status != _LegacyStatus.OK:
            raise RuntimeError(
                f"relay connect failed with {_legacy_status_name(response.status)}"
            )
        raw_conn = RawConnection(
            stream=stream,
            initiator=True,
            connection_type=ConnectionType.RELAYED,
            addresses=[circuit_ma],
        )
        await host.upgrade_outbound_connection(raw_conn, dest_peer_id)
        stream = None
    finally:
        if stream is not None:
            try:
                await stream.close()
            except Exception:
                pass


async def _close_relayed_to_peer(host: BasicHost, peer_id: ID) -> None:
    net = host.get_network()
    for conn in list(net.get_connections(peer_id)):
        try:
            if conn.get_connection_type() == ConnectionType.RELAYED:
                await conn.close()
        except Exception as exc:
            logger.debug("could not close relayed conn: %s", exc)


def _normalize_observed_addr(addr: multiaddr.Multiaddr, tp: str) -> multiaddr.Multiaddr:
    parts = str(addr).strip("/").split("/")
    if len(parts) < 4:
        raise ValueError(f"unexpected observed address {addr}")

    network_proto, host, _, port, *rest = parts
    if network_proto not in ("ip4", "ip6"):
        raise ValueError(f"unsupported observed address {addr}")

    if tp == "tcp":
        return multiaddr.Multiaddr(f"/{network_proto}/{host}/tcp/{port}")
    if tp == "quic":
        return multiaddr.Multiaddr(f"/{network_proto}/{host}/udp/{port}/quic-v1")

    raise ValueError(tp)


def _is_relay_addr(addr: multiaddr.Multiaddr) -> bool:
    return "/p2p-circuit" in str(addr)


def _strip_p2p_suffix(addr: multiaddr.Multiaddr) -> multiaddr.Multiaddr:
    try:
        peer_id_str = addr.get_peer_id()
    except Exception:
        peer_id_str = None

    if not peer_id_str:
        return addr

    try:
        return addr.decapsulate(multiaddr.Multiaddr(f"/p2p/{peer_id_str}"))
    except Exception:
        return addr


async def _identify_observed_addrs(
    host: BasicHost, relay_peer_id: ID, tp: str, attempts: int = 6
) -> list[bytes]:
    last_exc: BaseException | None = None

    for i in range(attempts):
        stream = None
        try:
            with trio.fail_after(15):
                stream = await host.new_stream(relay_peer_id, [IDENTIFY_PROTOCOL_ID])
                payload = await read_length_prefixed_protobuf(
                    stream, use_varint_format=True
                )

            identify_msg = Identify()
            identify_msg.ParseFromString(payload)

            if not identify_msg.observed_addr:
                raise RuntimeError("identify response did not include observed_addr")

            observed_addr = _normalize_observed_addr(
                multiaddr.Multiaddr(identify_msg.observed_addr), tp
            )
            logger.info(
                "using observed address via relay %s: %s", relay_peer_id, observed_addr
            )
            return [observed_addr.to_bytes()]
        except BaseException as exc:
            last_exc = exc
            logger.warning(
                "identify observed address attempt %s/%s failed: %s",
                i + 1,
                attempts,
                exc,
            )
            await trio.sleep(0.5 + float(i) * 0.25)
        finally:
            if stream is not None:
                try:
                    await stream.close()
                except Exception:
                    pass

    assert last_exc is not None
    raise RuntimeError(
        f"could not determine observed address via relay {relay_peer_id}"
    ) from last_exc


def _install_observed_addr_provider(
    dcutr: DCUtRProtocol, host: BasicHost, relay_peer_id: ID, tp: str
) -> None:
    cached: list[bytes] | None = None

    async def _provider() -> list[bytes]:
        nonlocal cached
        if cached is None:
            cached = await _identify_observed_addrs(host, relay_peer_id, tp)
        return list(cached)

    dcutr._get_observed_addrs = _provider  # type: ignore[method-assign, assignment]


async def _handle_legacy_stop_stream(
    host: BasicHost, dcutr: DCUtRProtocol, stream
) -> None:
    try:
        stop_msg = _parse_legacy_stop(await _read_legacy_message(stream))
        if stop_msg.type != _LegacyStopType.CONNECT:
            raise RuntimeError(f"unexpected legacy stop type {stop_msg.type}")
        if stop_msg.peer is None:
            raise RuntimeError("legacy stop connect missing source peer")

        relay_peer_id = stream.muxed_conn.peer_id
        source_peer_id = ID(stop_msg.peer.peer_id)
        logger.info(
            "received legacy STOP CONNECT from relay %s for source %s",
            relay_peer_id,
            source_peer_id,
        )
        await _write_legacy_message(
            stream,
            _encode_legacy_stop(
                _LegacyStopMessage(
                    type=_LegacyStopType.STATUS,
                    status=_LegacyStatus.OK,
                )
            ),
        )

        ma = multiaddr.Multiaddr(
            f"/p2p/{relay_peer_id.to_base58()}/p2p-circuit/p2p/{source_peer_id.to_base58()}"
        )
        raw_conn = RawConnection(
            stream=stream,
            initiator=False,
            connection_type=ConnectionType.RELAYED,
            addresses=[ma],
        )
        logger.info(
            "upgrading inbound relayed connection for %s via relay %s",
            source_peer_id,
            relay_peer_id,
        )
        await host.upgrade_inbound_connection(raw_conn, ma)
        logger.info("inbound relayed connection upgraded for %s", source_peer_id)
        logger.info("starting DCUtR as relayed listener toward %s", source_peer_id)
        if not await dcutr.initiate_hole_punch(source_peer_id):
            logger.warning(
                "DCUtR initiation from relayed listener failed for %s",
                source_peer_id,
            )
    except Exception as exc:
        logger.error("legacy stop handler failed: %s", exc)
        try:
            await _write_legacy_message(
                stream,
                _encode_legacy_stop(
                    _LegacyStopMessage(
                        type=_LegacyStopType.STATUS,
                        status=_LegacyStatus.CONNECTION_FAILED,
                    )
                ),
            )
        except Exception:
            pass
        try:
            await stream.reset()
        except Exception:
            try:
                await stream.close()
            except Exception:
                pass


def _install_dcutr_framing_patch(dcutr: DCUtRProtocol) -> None:
    def _decode_observed_addrs(self: DCUtRProtocol, addr_bytes: list[bytes]) -> list[multiaddr.Multiaddr]:
        result: list[multiaddr.Multiaddr] = []

        for addr_byte in addr_bytes:
            try:
                addr = _strip_p2p_suffix(multiaddr.Multiaddr(addr_byte))
                if str(addr).startswith("/ip"):
                    result.append(addr)
            except Exception as exc:
                logger.debug("error decoding multiaddr: %s", exc)

        return result

    async def _verify_direct_connection(self: DCUtRProtocol, peer_id: ID) -> bool:
        network = self.host.get_network()
        conn_or_conns = network.connections.get(peer_id)
        if not conn_or_conns:
            return False

        connections = conn_or_conns if isinstance(conn_or_conns, list) else [conn_or_conns]

        for conn in connections:
            try:
                if conn.get_connection_type() != ConnectionType.DIRECT:
                    continue
            except Exception as exc:
                logger.debug(
                    "could not read connection type for %s: %s", peer_id, exc
                )
                continue

            actual_addrs = getattr(conn, "_actual_transport_addresses", None)
            if actual_addrs:
                if any(not _is_relay_addr(addr) for addr in actual_addrs):
                    return True
                continue

            try:
                muxed_conn = getattr(conn, "muxed_conn", None)
                raw_conn = getattr(muxed_conn, "raw_conn", None)
                raw_addrs = raw_conn.get_transport_addresses() if raw_conn else []
                if raw_addrs:
                    if any(not _is_relay_addr(addr) for addr in raw_addrs):
                        return True
                    continue
            except Exception as exc:
                logger.debug(
                    "could not read raw transport addresses for %s: %s", peer_id, exc
                )

        return False

    async def _dial_peer(self: DCUtRProtocol, peer_id: ID, addr: multiaddr.Multiaddr) -> None:
        try:
            dial_addr = _strip_p2p_suffix(addr)
            logger.info(
                "attempting direct hole-punch dial to %s at %s",
                peer_id,
                dial_addr,
            )

            network = self.host.get_network()
            direct_dial = getattr(network, "_dial_addr_single_attempt", None)
            if direct_dial is None:
                raise RuntimeError("swarm direct dial helper unavailable")

            with trio.fail_after(self.dial_timeout):
                await direct_dial(dial_addr, peer_id)

            await trio.sleep(0.1)

            if await self._verify_direct_connection(peer_id):
                logger.info(
                    "verified direct hole-punch connection to %s at %s",
                    peer_id,
                    dial_addr,
                )
                self._direct_connections.add(peer_id)
            else:
                logger.info(
                    "hole-punch dial reached %s at %s without a direct connection",
                    peer_id,
                    dial_addr,
                )
        except trio.TooSlowError:
            logger.warning("timeout dialing %s at %s", peer_id, addr)
        except Exception as exc:
            logger.warning(
                "error dialing %s at %s: %s",
                peer_id,
                addr,
                f"{type(exc).__name__}: {exc!r}",
            )

    async def _handle_dcutr_stream(self: DCUtRProtocol, stream) -> None:
        try:
            remote_peer_id = stream.muxed_conn.peer_id
            logger.info("received DCUtR stream from %s", remote_peer_id)

            if await self._have_direct_connection(remote_peer_id):
                logger.info("already have direct connection to %s", remote_peer_id)
                await stream.close()
                return

            if remote_peer_id in self._in_progress:
                logger.info("hole punch already in progress with %s", remote_peer_id)
                await stream.close()
                return

            self._in_progress.add(remote_peer_id)

            try:
                with trio.fail_after(self.read_timeout):
                    msg_bytes = await _read_legacy_message(stream)

                connect_msg = HolePunch()
                connect_msg.ParseFromString(msg_bytes)
                if connect_msg.type != HolePunch.CONNECT:
                    logger.warning(
                        "expected DCUtR CONNECT from %s, got %s",
                        remote_peer_id,
                        connect_msg.type,
                    )
                    await stream.close()
                    return

                peer_addrs = self._decode_observed_addrs(list(connect_msg.ObsAddrs))
                if peer_addrs:
                    self.host.get_peerstore().add_addrs(remote_peer_id, peer_addrs, 600)

                our_addrs = await self._get_observed_addrs()
                response = HolePunch()
                response.type = HolePunch.CONNECT
                response.ObsAddrs.extend(our_addrs)
                with trio.fail_after(self.write_timeout):
                    await _write_legacy_message(stream, response.SerializeToString())

                early_attempt_done = trio.Event()
                early_attempt_success = False

                async def _early_attempt() -> None:
                    nonlocal early_attempt_success
                    try:
                        if not peer_addrs:
                            return
                        # Python responder overhead is noticeably higher than Rust's.
                        # Pre-punch slightly before SYNC handling completes so the
                        # router has state when the remote SYN arrives.
                        await trio.sleep(0.02)
                        logger.info(
                            "starting early pre-SYNC hole-punch attempt toward %s",
                            remote_peer_id,
                        )
                        early_attempt_success = await self._perform_hole_punch(
                            remote_peer_id, peer_addrs
                        )
                    except Exception as exc:
                        logger.debug(
                            "early hole-punch attempt failed for %s: %s",
                            remote_peer_id,
                            exc,
                        )
                    finally:
                        early_attempt_done.set()

                async with trio.open_nursery() as nursery:
                    nursery.start_soon(_early_attempt)

                    with trio.fail_after(self.read_timeout):
                        sync_bytes = await _read_legacy_message(stream)

                    sync_msg = HolePunch()
                    sync_msg.ParseFromString(sync_bytes)
                    if sync_msg.type != HolePunch.SYNC:
                        logger.warning(
                            "expected DCUtR SYNC from %s, got %s",
                            remote_peer_id,
                            sync_msg.type,
                        )
                        await stream.close()
                        return

                    await early_attempt_done.wait()

                success = early_attempt_success
                if not success:
                    success = await self._perform_hole_punch(remote_peer_id, peer_addrs)
                if success:
                    logger.info(
                        "successfully established direct connection with %s",
                        remote_peer_id,
                    )
                else:
                    logger.warning(
                        "failed to establish direct connection with %s",
                        remote_peer_id,
                    )

            except trio.TooSlowError:
                logger.warning("timeout in DCUtR protocol with peer %s", remote_peer_id)
            except Exception as exc:
                logger.error(
                    "error in DCUtR protocol with peer %s: %s",
                    remote_peer_id,
                    exc,
                )
            finally:
                self._in_progress.discard(remote_peer_id)
                await stream.close()

        except Exception as exc:
            logger.error("error handling DCUtR stream: %s", exc)
            await stream.close()

    async def initiate_hole_punch(self: DCUtRProtocol, peer_id: ID) -> bool:
        if await self._have_direct_connection(peer_id):
            logger.info("already have direct connection to %s", peer_id)
            return True

        if peer_id in self._in_progress:
            logger.info("hole punch already in progress with %s", peer_id)
            return False

        attempts = self._hole_punch_attempts.get(peer_id, 0)
        if attempts >= MAX_HOLE_PUNCH_ATTEMPTS:
            logger.warning("maximum hole punch attempts reached for %s", peer_id)
            return False

        self._in_progress.add(peer_id)
        self._hole_punch_attempts[peer_id] = attempts + 1

        try:
            stream = await self.host.new_stream(peer_id, [DCUTR_PROTOCOL_ID])
            if not stream:
                logger.warning("failed to open DCUtR stream to %s", peer_id)
                return False

            try:
                our_addrs = await self._get_observed_addrs()
                connect_msg = HolePunch()
                connect_msg.type = HolePunch.CONNECT
                connect_msg.ObsAddrs.extend(our_addrs)

                start_time = time.time()
                with trio.fail_after(self.write_timeout):
                    await _write_legacy_message(stream, connect_msg.SerializeToString())

                with trio.fail_after(self.read_timeout):
                    resp_bytes = await _read_legacy_message(stream)

                rtt = time.time() - start_time
                resp = HolePunch()
                resp.ParseFromString(resp_bytes)
                if resp.type != HolePunch.CONNECT:
                    logger.warning("expected DCUtR CONNECT from %s, got %s", peer_id, resp.type)
                    return False

                peer_addrs = self._decode_observed_addrs(list(resp.ObsAddrs))
                if peer_addrs:
                    self.host.get_peerstore().add_addrs(peer_id, peer_addrs, 600)

                # In this Docker NAT harness, Python responder overhead is already
                # high enough that waiting before the direct dial causes Rust's SYN
                # to arrive first and get reset. Punch immediately after SYNC.
                punch_time = time.time()
                sync_msg = HolePunch()
                sync_msg.type = HolePunch.SYNC
                with trio.fail_after(self.write_timeout):
                    await _write_legacy_message(stream, sync_msg.SerializeToString())

                success = await self._perform_hole_punch(
                    peer_id, peer_addrs, punch_time
                )
                if success:
                    logger.info(
                        "successfully established direct connection with %s",
                        peer_id,
                    )
                else:
                    logger.warning(
                        "failed to establish direct connection with %s",
                        peer_id,
                    )
                return success

            except trio.TooSlowError:
                logger.warning("timeout in DCUtR protocol with peer %s", peer_id)
                return False
            except Exception as exc:
                logger.error("error in DCUtR protocol with peer %s: %s", peer_id, exc)
                return False
            finally:
                await stream.close()

        except Exception as exc:
            logger.error("error initiating hole punch with peer %s: %s", peer_id, exc)
            return False
        finally:
            self._in_progress.discard(peer_id)

    dcutr._decode_observed_addrs = MethodType(_decode_observed_addrs, dcutr)  # type: ignore[method-assign]
    dcutr._verify_direct_connection = MethodType(_verify_direct_connection, dcutr)  # type: ignore[method-assign]
    dcutr._dial_peer = MethodType(_dial_peer, dcutr)  # type: ignore[method-assign]
    dcutr._handle_dcutr_stream = MethodType(_handle_dcutr_stream, dcutr)  # type: ignore[method-assign]
    dcutr.initiate_hole_punch = MethodType(initiate_hole_punch, dcutr)  # type: ignore[method-assign]


async def run_listener(tp: str) -> None:
    r = _redis()
    relay_str = _pop_relay(r, tp)
    relay_maddr = multiaddr.Multiaddr(relay_str)
    relay_info = info_from_p2p_addr(relay_maddr)
    relay_peer_id = relay_info.peer_id

    host = cast(BasicHost, _make_host(tp))
    dcutr = DCUtRProtocol(host)
    _install_dcutr_framing_patch(dcutr)
    _install_observed_addr_provider(dcutr, host, relay_peer_id, tp)
    host.set_stream_handler(
        LEGACY_STOP_PROTOCOL_ID,
        lambda stream: _handle_legacy_stop_stream(host, dcutr, stream),
    )

    async with host.run([_listen_maddr(tp)]):
        async with background_trio_service(dcutr):
            await _connect_relay(host, relay_info)
            await dcutr._get_observed_addrs()
            await trio.sleep(2.0)
            await _reserve_with_legacy_relay(host, relay_peer_id)
            _push(r, LISTEN_CLIENT_PEER_ID, str(host.get_id()))
            logger.info("listener ready, peer_id=%s", host.get_id())
            await trio.sleep_forever()


async def run_dial(tp: str) -> None:
    r = _redis()
    relay_str = _pop_relay(r, tp)
    relay_maddr = multiaddr.Multiaddr(relay_str)
    relay_info = info_from_p2p_addr(relay_maddr)
    relay_peer_id = relay_info.peer_id

    host = cast(BasicHost, _make_host(tp))
    dcutr = DCUtRProtocol(host)
    _install_dcutr_framing_patch(dcutr)
    _install_observed_addr_provider(dcutr, host, relay_peer_id, tp)
    host.set_stream_handler(
        LEGACY_STOP_PROTOCOL_ID,
        lambda stream: _handle_legacy_stop_stream(host, dcutr, stream),
    )

    async with host.run([_listen_maddr(tp)]):
        async with background_trio_service(dcutr):
            await _connect_relay(host, relay_info)
            await dcutr._get_observed_addrs()
            await trio.sleep(2.0)

            listener_str = _pop_listener_id(r)
            listener_id = ID.from_string(listener_str)
            circuit_ma = multiaddr.Multiaddr(
                f"{relay_str.rstrip('/')}/p2p-circuit/p2p/{listener_id}"
            )
            host.get_peerstore().add_addr(listener_id, circuit_ma, 3600)
            await _dial_via_legacy_relay(host, relay_peer_id, listener_id, circuit_ma)
            await dcutr.event_started.wait()

            if not await dcutr.initiate_hole_punch(listener_id):
                raise RuntimeError("DCUtR hole punch failed")

            await trio.sleep(0.5)
            await _close_relayed_to_peer(host, listener_id)

            ping = PingService(host)
            rtts = await ping.ping(listener_id, 1)
            rtt_us = rtts[0]
            rtt_ms = max(0, int(round(rtt_us / 1000.0)))

            sys.stdout.write(
                json.dumps({"rtt_to_holepunched_peer_millis": rtt_ms}) + "\n"
            )
            sys.stdout.flush()


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    _setup_logging()
    try:
        mode = os.environ["MODE"].lower()
        tp = os.environ["TRANSPORT"].lower()
        if mode not in ("listen", "dial"):
            raise ValueError("MODE must be listen or dial")
        if tp not in ("tcp", "quic"):
            raise ValueError("TRANSPORT must be tcp or quic")
        if mode == "listen":
            trio.run(run_listener, tp)
        else:
            trio.run(run_dial, tp)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        logger.exception("hole-punch-client failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
