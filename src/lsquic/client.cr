require "http/headers"
require "http/client"
require "socket/udp_socket"

struct QUIC::PeerCtx
  property socket : UDPSocket

  def initialize(@socket)
  end

  def local_address
    @socket.local_address
  end

  def remote_address
    @socket.remote_address
  end
end

struct QUIC::StreamCtx
  property requests : Array(HTTP::Request)
  property io : IO

  def initialize
    @requests = [] of HTTP::Request
    @io = IO::Memory.new
  end
end

class QUIC::Client
  ENGINE_FLAGS = LibLsquic::LSENG_HTTP
  LibLsquic.global_init(ENGINE_FLAGS & LibLsquic::LSENG_SERVER ? LibLsquic::GLOBAL_SERVER : LibLsquic::GLOBAL_CLIENT)

  # The set of possible valid body types.
  alias BodyType = String | Bytes | IO | Nil

  getter host : String
  getter port : Int32
  getter! tls : OpenSSL::SSL::Context::Client

  @peer_ctx : PeerCtx | Nil
  @engine : LibLsquic::EngineT | Nil
  @conn : LibLsquic::ConnT | Nil
  @engine : LibLsquic::EngineT | Nil
  @engine_settings : LibLsquic::EngineSettings
  @stream_if : LibLsquic::StreamIf
  @engine_api : LibLsquic::EngineApi

  @dns_timeout : Float64?
  @connect_timeout : Float64?
  @read_timeout : Float64?

  def initialize(@host : String, port = nil, tls : Bool | OpenSSL::SSL::Context::Client = false)
    check_host_only(@host)

    @tls = case tls
           when true
             OpenSSL::SSL::Context::Client.new
           when OpenSSL::SSL::Context::Client
             tls
           when false
             nil
           end

    @port = (port || 443).to_i

    LibLsquic.engine_init_settings(out @engine_settings, ENGINE_FLAGS)
    @engine_settings.es_ua = "Chrome/78.0.3904.97 Linux x86_64"
    @engine_settings.es_ecn = 0

    err_buf = Bytes.new(0x100)
    err_code = LibLsquic.engine_check_settings(pointerof(@engine_settings), ENGINE_FLAGS, err_buf, err_buf.size)
    raise String.new(err_buf) if err_code != 0

    @stream_if = LibLsquic::StreamIf.new
    @stream_if.on_new_conn = ->(stream_if_ctx : Void*, c : LibLsquic::ConnT) { stream_if_ctx }
    @stream_if.on_conn_closed = ->(c : LibLsquic::ConnT) do
      Box.box(nil)
    end

    @stream_if.on_new_stream = ->(stream_if_ctx : Void*, s : LibLsquic::StreamT) do
      if LibLsquic.stream_is_pushed(s) != 0
        return stream_if_ctx
      end

      LibLsquic.stream_wantwrite(s, 1)
      stream_if_ctx
    end

    @stream_if.on_write = ->(s : LibLsquic::StreamT, stream_if_ctx : Void*) do
      request = Box(StreamCtx).unbox(stream_if_ctx).requests.shift
      raise "No request" if !request

      headers = [] of LibLsquic::HttpHeader
      (request.headers.to_a.sort_by { |k, v| {":authority", ":path", ":scheme", ":method"}.index(k) || -1 }).reverse.each do |tuple|
        name, values = tuple
        name = name.downcase

        values.each do |value|
          name_vec = LibLsquic::Iovec.new
          name_vec.iov_base = name.to_slice
          name_vec.iov_len = name.bytesize

          value_vec = LibLsquic::Iovec.new
          value_vec.iov_base = value.to_slice
          value_vec.iov_len = value.bytesize

          header = LibLsquic::HttpHeader.new
          header.name = name_vec
          header.value = value_vec

          headers << header
        end
      end

      http_headers = LibLsquic::HttpHeaders.new
      http_headers.count = headers.size
      http_headers.headers = headers.to_unsafe

      # For payload, last argument is 0
      raise "Could not send headers" if LibLsquic.stream_send_headers(s, pointerof(http_headers), request.body ? 0 : 1) != 0

      if request.body
        body = request.body.not_nil!.gets_to_end
        LibLsquic.stream_write(s, body, body.bytesize)
        LibLsquic.stream_flush(s)
      end

      LibLsquic.stream_shutdown(s, 1)
      LibLsquic.stream_wantwrite(s, 0)
      LibLsquic.stream_wantread(s, 1)

      stream_if_ctx
    end

    @stream_if.on_read = ->(s : LibLsquic::StreamT, stream_if_ctx : Void*) do
      stream_ctx = Box(StreamCtx).unbox(stream_if_ctx)

      buffer = Bytes.new(0x200)
      bytes_read = LibLsquic.stream_read(s, buffer, buffer.size)
      if bytes_read > 0
        stream_ctx.io.write buffer[0, bytes_read]
      elsif bytes_read == 0
        LibLsquic.stream_shutdown(s, 0)
      elsif LibLsquic.stream_is_rejected(s)
        LibLsquic.stream_close(s)
      else
        raise "Could not read stream"
      end

      stream_if_ctx
    end

    # TODO: Allow engine to break with existing connections
    @stream_if.on_close = ->(s : LibLsquic::StreamT, stream_if_ctx : Void*) do
      LibLsquic.conn_close(LibLsquic.stream_conn(s))
      stream_if_ctx
    end

    @engine_api = LibLsquic::EngineApi.new
    @engine_api.ea_settings = pointerof(@engine_settings)
    @engine_api.ea_stream_if = pointerof(@stream_if)

    @stream_ctx = StreamCtx.new
    @engine_api.ea_stream_if_ctx = Box.box(@stream_ctx) # TODO

    @engine_api.ea_packets_out = ->(peer_ctx : Void*, specs : LibLsquic::OutSpec*, count : LibC::UInt) do
      packets_out = 0

      count.times do |i|
        spec = specs[i]
        peer_ctx = Box(PeerCtx).unbox(spec.peer_ctx)
        spec.iovlen.times do |j|
          iov = spec.iov[j]
          begin
            peer_ctx.socket.send(iov.iov_base.to_slice(iov.iov_len), to: peer_ctx.remote_address)
            packets_out += 1
          rescue ex
          end
        end
      end

      packets_out
    end
  end

  private def check_host_only(string : String)
    # When parsing a URI with just a host
    # we end up with a URI with just a path
    uri = URI.parse(string)
    if uri.scheme || uri.host || uri.port || uri.query || uri.user || uri.password || uri.path.includes?('/')
      raise_invalid_host(string)
    end
  rescue URI::Error
    raise_invalid_host(string)
  end

  private def raise_invalid_host(string : String)
    raise ArgumentError.new("The string passed to create an HTTP::Client must be just a host, not #{string.inspect}")
  end

  def self.new(uri : URI, tls = nil)
    tls = tls_flag(uri, tls)
    host = validate_host(uri)
    new(host, uri.port, tls)
  end

  def self.new(uri : URI, tls = nil)
    tls = tls_flag(uri, tls)
    host = validate_host(uri)
    client = new(host, uri.port, tls)
    begin
      yield client
    ensure
      client.close
    end
  end

  def self.new(host : String, port = nil, tls = false)
    client = new(host, port, tls)
    begin
      yield client
    ensure
      client.close
    end
  end

  # Configures this client to perform basic authentication in every
  # request.
  def basic_auth(username, password)
    header = "Basic #{Base64.strict_encode("#{username}:#{password}")}"
    before_request do |request|
      request.headers["Authorization"] = header
    end
  end

  def read_timeout=(read_timeout : Number)
    @read_timeout = read_timeout.to_f
  end

  def read_timeout=(read_timeout : Time::Span)
    self.read_timeout = read_timeout.total_seconds
  end

  def connect_timeout=(connect_timeout : Number)
    @connect_timeout = connect_timeout.to_f
  end

  def connect_timeout=(connect_timeout : Time::Span)
    self.connect_timeout = connect_timeout.total_seconds
  end

  def dns_timeout=(dns_timeout : Number)
    @dns_timeout = dns_timeout.to_f
  end

  def dns_timeout=(dns_timeout : Time::Span)
    self.dns_timeout = dns_timeout.total_seconds
  end

  def before_request(&callback : HTTP::Request ->)
    before_request = @before_request ||= [] of (HTTP::Request ->)
    before_request << callback
  end

  {% for method in %w(get post put head delete patch options) %}
    def {{method.id}}(path, headers : HTTP::Headers? = nil, body : BodyType = nil) : HTTP::Client::Response
      exec {{method.upcase}}, path, headers, body
    end

    def {{method.id}}(path, headers : HTTP::Headers? = nil, body : BodyType = nil)
      exec {{method.upcase}}, path, headers, body do |response|
        yield response
      end
    end

    def self.{{method.id}}(url : String | URI, headers : HTTP::Headers? = nil, body : BodyType = nil, tls = nil) : HTTP::Client::Response
      exec {{method.upcase}}, url, headers, body, tls
    end

    def self.{{method.id}}(url : String | URI, headers : HTTP::Headers? = nil, body : BodyType = nil, tls = nil)
      exec {{method.upcase}}, url, headers, body, tls do |response|
        yield response
      end
    end

    def {{method.id}}(path, headers : HTTP::Headers? = nil, *, form : String | IO) : HTTP::Client::Response
      request = new_request({{method.upcase}}, path, headers, form)
      request.headers["Content-Type"] = "application/x-www-form-urlencoded"
      exec request
    end

    def {{method.id}}(path, headers : HTTP::Headers? = nil, *, form : String | IO)
      request = new_request({{method.upcase}}, path, headers, form)
      request.headers["Content-Type"] = "application/x-www-form-urlencoded"
      exec(request) do |response|
        yield response
      end
    end

    def {{method.id}}(path, headers : HTTP::Headers? = nil, *, form : Hash(String, String) | NamedTuple) : HTTP::Client::Response
      body = HTTP::Params.encode(form)
      {{method.id}} path, form: body, headers: headers
    end

    def {{method.id}}(path, headers : HTTP::Headers? = nil, *, form : Hash(String, String) | NamedTuple)
      body = HTTP::Params.encode(form)
      {{method.id}}(path, form: body, headers: headers) do |response|
        yield response
      end
    end

    def self.{{method.id}}(url, headers : HTTP::Headers? = nil, tls = nil, *, form : String | IO | Hash) : HTTP::Client::Response
      exec(url, tls) do |client, path|
        client.{{method.id}}(path, form: form, headers: headers)
      end
    end

    def self.{{method.id}}(url, headers : HTTP::Headers? = nil, tls = nil, *, form : String | IO | Hash)
      exec(url, tls) do |client, path|
        client.{{method.id}}(path, form: form, headers: headers) do |response|
          yield response
        end
      end
    end
  {% end %}

  def exec(request : HTTP::Request) : HTTP::Client::Response
    exec_internal(request)
  end

  private def exec_internal(request)
    response = exec_internal_single(request)
    return handle_response(response) if response

    # Server probably closed the connection, so retry one
    close
    request.body.try &.rewind
    response = exec_internal_single(request)
    return handle_response(response) if response

    raise "Unexpected end of http response"
  end

  private def exec_internal_single(request)
    send_request(request)
    @stream_ctx.io.rewind

    HTTP::Client::Response.from_io?(@stream_ctx.io, ignore_body: request.ignore_body?)
  end

  private def handle_response(response)
    close # unless response.keep_alive?
    response
  end

  def exec(request : HTTP::Request, &block)
    exec_internal(request) do |response|
      yield response
    end
  end

  private def exec_internal(request, &block : Response -> T) : T forall T
    exec_internal_single(request) do |response|
      if response
        return handle_response(response) { yield response }
      end

      # Server probably closed the connection, so retry once
      close
      request.body.try &.rewind
      exec_internal_single(request) do |response|
        if response
          return handle_response(response) do
            yield response
          end
        end
      end
    end
    raise "Unexpected end of http response"
  end

  private def exec_internal_single(request)
    send_request(request)
    HTTP::Client::Response.from_io?(stream_ctx.io, ignore_body: request.ignore_body?) do |response|
      yield response
    end
  end

  private def handle_response(response)
    value = yield
    response.body_io?.try &.close
    close # unless response.keep_alive?
    value
  end

  private def send_request(request)
    set_defaults request
    run_before_request_callbacks(request)

    @stream_ctx.requests << request
    LibLsquic.conn_make_stream(conn)

    run_engine
  end

  private def set_defaults(request)
    request.headers[":method"] ||= request.method
    request.headers[":scheme"] ||= "https"
    request.headers[":path"] ||= request.resource
    request.headers[":authority"] ||= host_header
    request.headers["user-agent"] ||= "Chrome/78.0.3904.97 Linux x86_64"
  end

  private def self.default_one_shot_headers(headers)
    headers ||= HTTP::Headers.new
    headers["Connection"] ||= "close"
    headers
  end

  private def run_before_request_callbacks(request)
    @before_request.try &.each &.call(request)
  end

  def exec(method : String, path, headers : HTTP::Headers? = nil, body : BodyType = nil) : HTTP::Client::Response
    exec new_request method, path, headers, body
  end

  def exec(method : String, path, headers : HTTP::Headers? = nil, body : BodyType = nil)
    exec(new_request(method, path, headers, body)) do |response|
      yield response
    end
  end

  def self.exec(method, url : String | URI, headers : HTTP::Headers? = nil, body : BodyType = nil, tls = nil) : HTTP::Client::Response
    headers = default_one_shot_headers(headers)
    exec(url, tls) do |client, path|
      client.exec method, path, headers, body
    end
  end

  def self.exec(method, url : String | URI, headers : HTTP::Headers? = nil, body : BodyType = nil, tls = nil)
    headers = default_one_shot_headers(headers)
    exec(url, tls) do |client, path|
      client.exec(method, path, headers, body) do |response|
        yield response
      end
    end
  end

  def close
    # @conn.try { |c| LibLsquic.conn_close(c) }
    @conn = nil
  end

  private def new_request(method, path, headers, body : BodyType)
    HTTP::Request.new(method, path, headers, body)
  end

  private def engine
    engine = @engine
    return engine if engine

    engine = LibLsquic.engine_new(ENGINE_FLAGS, pointerof(@engine_api))
    @engine = engine
  end

  def run_engine
    buffer = Bytes.new(0x600)

    loop do
      LibLsquic.engine_process_conns(engine)

      if LibLsquic.engine_earliest_adv_tick(engine, out diff) == 0
        break
        # else
        #   sleep (diff / 1000000).seconds
        #   sleep (diff % 1000000).microseconds
      end

      bytes_read = peer_ctx.socket.read(buffer)
      LibLsquic.engine_packet_in(engine, buffer[0, bytes_read], bytes_read, peer_ctx.local_address, peer_ctx.remote_address, Box.box(peer_ctx), 0)
    end
  end

  private def peer_ctx
    peer_ctx = @peer_ctx
    return peer_ctx if peer_ctx

    hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1..-2] : @host
    socket = UDPSocket.new
    socket.bind Socket::IPAddress.new("0.0.0.0", 0)
    socket.read_timeout = @read_timeout if @read_timeout
    Socket::Addrinfo.udp(host, port, timeout: @dns_timeout) do |addrinfo|
      socket.connect(addrinfo, timeout: @connect_timeout) do |error|
        error
      end
    end
    socket.sync = false

    peer_ctx = PeerCtx.new(socket)
    @peer_ctx = peer_ctx
  end

  def conn
    conn = @conn
    return conn if conn

    hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1..-2] : @host
    conn = LibLsquic.engine_connect(engine, LibLsquic::Version::Lsqver046, peer_ctx.local_address, peer_ctx.remote_address, Box.box(peer_ctx), nil, hostname, 0, nil, 0, nil, 0)
    @conn = conn
  end

  private def host_header
    if (@tls && @port != 443) || (!@tls && @port != 80)
      "#{@host}:#{@port}"
    else
      @host
    end
  end

  private def self.exec(string : String, tls = nil)
    uri = URI.parse(string)

    unless uri.scheme && uri.host
      # Assume http if no scheme and host are specified
      uri = URI.parse("http://#{string}")
    end

    exec(uri, tls) do |client, path|
      yield client, path
    end
  end

  protected def self.tls_flag(uri, context : OpenSSL::SSL::Context::Client?)
    scheme = uri.scheme
    case {scheme, context}
    when {nil, _}
      raise ArgumentError.new("Missing scheme: #{uri}")
    when {"http", nil}
      false
    when {"http", OpenSSL::SSL::Context::Client}
      raise ArgumentError.new("TLS context given for HTTP URI")
    when {"https", nil}
      true
    when {"https", OpenSSL::SSL::Context::Client}
      context
    else
      raise ArgumentError.new "Unsupported scheme: #{scheme}"
    end
  end

  protected def self.validate_host(uri)
    host = uri.host
    return host if host && !host.empty?

    raise ArgumentError.new %(Request URI must have host (URI is: #{uri}))
  end

  private def self.exec(uri : URI, tls = nil)
    tls = tls_flag(uri, tls)
    host = validate_host(uri)

    port = uri.port
    path = uri.full_path
    user = uri.user
    password = uri.password

    HTTP::Client.new(host, port, tls) do |client|
      if user && password
        client.basic_auth(user, password)
      end
      yield client, path
    end
  end
end
