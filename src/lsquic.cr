require "./lsquic/*"
require "http/headers"
require "socket"

PATH    = "/watch?v=QmyhcjpsF6E"
METHOD  = "GET"
HEADERS = HTTP::Headers{
  ":method"    => METHOD,
  ":scheme"    => "https",
  ":path"      => PATH,
  ":authority" => "www.youtube.com",
  "user-agent" => "Chrome/78.0.3904.97 Linux x86_64",
  # "content-type"   => "application/octet-stream"
  # "content-length" => "0",
}

# Crystal will try to be smart and optimize away our dependencies, this "pins" them
OpenSSL::SSL::Context::Client.new

engine_flags = LibLsquic::LSENG_HTTP
LibLsquic.engine_init_settings(out engine_settings, engine_flags)
engine_settings.es_ua = "Chrome/78.0.3904.97 Linux x86_64"
engine_settings.es_ecn = 0

LibLsquic.global_init(engine_flags & LibLsquic::LSENG_SERVER ? LibLsquic::GLOBAL_SERVER : LibLsquic::GLOBAL_CLIENT)

err_buf = Bytes.new(0x100)
err_code = LibLsquic.engine_check_settings(pointerof(engine_settings), engine_flags, err_buf, err_buf.size)
raise String.new(err_buf) if err_code != 0

stream_if = LibLsquic::StreamIf.new
stream_if.on_new_conn = ->(stream_if_ctx : Void*, c : LibLsquic::ConnT) { LibLsquic.conn_make_stream(c); stream_if_ctx }
stream_if.on_conn_closed = ->(c : LibLsquic::ConnT) { Box.box(nil) }

stream_if.on_new_stream = ->(stream_if_ctx : Void*, s : LibLsquic::StreamT) do
  # TODO: Accept server push(?)
  if LibLsquic.stream_is_pushed(s) != 0
    return stream_if_ctx
  end

  LibLsquic.stream_wantwrite(s, 1)

  stream_if_ctx
end

stream_if.on_read = ->(s : LibLsquic::StreamT, stream_if_ctx : Void*) do
  buffer = Bytes.new(0x200)
  bytes_read = LibLsquic.stream_read(s, buffer, buffer.size)
  if bytes_read > 0
    print String.new(buffer[0, bytes_read])
  elsif bytes_read == 0
    LibLsquic.stream_shutdown(s, 0)
  elsif LibLsquic.stream_is_rejected(s)
    LibLsquic.stream_close(s)
  else
    raise "Could not read stream"
  end

  stream_if_ctx
end

stream_if.on_write = ->(s : LibLsquic::StreamT, stream_if_ctx : Void*) do
  # TODO: Handle if ctx has written headers(?)

  headers = HEADERS.map do |name, values|
    value = values[0]

    name_vec = LibLsquic::Iovec.new
    name_vec.iov_base = name.to_slice
    name_vec.iov_len = name.bytesize

    value_vec = LibLsquic::Iovec.new
    value_vec.iov_base = value.to_slice
    value_vec.iov_len = value.bytesize

    header = LibLsquic::HttpHeader.new
    header.name = name_vec
    header.value = value_vec

    header
  end

  http_headers = LibLsquic::HttpHeaders.new
  http_headers.count = headers.size
  http_headers.headers = headers.to_unsafe

  # For payload, last argument is 0
  raise "Could not send headers" if LibLsquic.stream_send_headers(s, pointerof(http_headers), 1) != 0

  LibLsquic.stream_shutdown(s, 1)
  LibLsquic.stream_wantwrite(s, 0)
  LibLsquic.stream_wantread(s, 1)

  stream_if_ctx
end

stream_if.on_close = ->(s : LibLsquic::StreamT, stream_if_ctx : Void*) do
  LibLsquic.conn_close(LibLsquic.stream_conn(s))
  stream_if_ctx
end

engine_api = LibLsquic::EngineApi.new
engine_api.ea_settings = pointerof(engine_settings)
engine_api.ea_stream_if = pointerof(stream_if)
engine_api.ea_stream_if_ctx = Box.box(IO::Memory.new) # TODO

engine_api.ea_packets_out = ->(peer_ctx : Void*, specs : LibLsquic::OutSpec*, count : LibC::UInt) do
  count.times do |i|
    spec = specs[i]
    peer_ctx = Box(PeerCtx).unbox(spec.peer_ctx)

    spec.iovlen.times do |j|
      iov = spec.iov[j]
      peer_ctx.socket.send(iov.iov_base.to_slice(iov.iov_len), to: peer_ctx.peer_addr)
    end
  end

  count.to_i32
end

engine = LibLsquic.engine_new(engine_flags, pointerof(engine_api))

hostname = "www.youtube.com"
port = 443

local_addr = Socket::IPAddress.new("0.0.0.0", 0)
peer_addr = Socket::IPAddress.new("172.217.5.14", port)

struct PeerCtx
  property socket : UDPSocket
  property local_addr : Socket::IPAddress
  property peer_addr : Socket::IPAddress

  def initialize(local_addr, peer_addr)
    @socket = UDPSocket.new
    @local_addr = local_addr
    @peer_addr = peer_addr

    @socket.bind @local_addr
  end
end

peer_ctx = PeerCtx.new(local_addr, peer_addr)
conn = LibLsquic.engine_connect(engine, LibLsquic::Version::Lsqver046, peer_ctx.socket.local_address, peer_addr, Box.box(peer_ctx), nil, hostname, 0, nil, 0, nil, 0)

loop do
  LibLsquic.engine_process_conns(engine)

  if LibLsquic.engine_earliest_adv_tick(engine, out diff) == 0
    break
  end

  buffer = Bytes.new(0x600)
  bytes_read = peer_ctx.socket.read(buffer)
  LibLsquic.engine_packet_in(engine, buffer[0, bytes_read], bytes_read, peer_ctx.socket.local_address, peer_addr, Box.box(peer_ctx), 0)
end
