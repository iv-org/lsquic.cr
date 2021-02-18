require "http"
require "socket"

module QUIC
  class StreamCtx
    property request : HTTP::Request
    property io : IO::ChanneledPipe

    def initialize(@request, @io)
    end
  end

  class Client
    REQUIRED_HEADERS = {":method", ":scheme", ":path", ":authority"}

    def self.stream_readf(stream_if_ctx : Void*, buf : UInt8*, buf_len : LibC::SizeT, fin : LibC::Int)
      stream_ctx = Box(StreamCtx).unbox(stream_if_ctx)
      stream_ctx.io.write Slice.new(buf, buf_len)
      buf_len
    end

    def self.on_new_conn(stream_if_ctx : Void*, c : LibLsquic::ConnT)
      stream_if_ctx
    end

    def self.on_conn_closed(c : LibLsquic::ConnT)
      Box.box(nil)
    end

    def self.on_new_stream(stream_if_ctx : Void*, s : LibLsquic::StreamT)
      stream_ctx = LibLsquic.stream_conn(s)
        .try { |c| LibLsquic.conn_get_ctx(c) }
        .try { |c| Box(StreamCtx).unbox(c) }

      return Box.box(stream_ctx) if LibLsquic.stream_is_pushed(s) != 0

      LibLsquic.stream_wantwrite(s, 1)
      Box.box(stream_ctx)
    end

    def self.on_write(s : LibLsquic::StreamT, stream_if_ctx : Void*)
      stream_ctx = Box(StreamCtx).unbox(stream_if_ctx)
      request_headers = stream_ctx.request.headers

      headers = [] of LibLsquic::LsxpackHeader
      REQUIRED_HEADERS.each do |name|
        value = stream_ctx.request.headers[name]
        headers << LibLsquic::LsxpackHeader.new(
          buf: "#{name}#{value}",
          name_len: name.bytesize,
          name_offset: 0,
          val_len: value.bytesize,
          val_offset: name.bytesize
        )
      end

      request_headers.each do |name, values|
        name = name.downcase
        next if REQUIRED_HEADERS.includes? name
        headers << LibLsquic::LsxpackHeader.new(
          buf: "#{name}#{values[0]}",
          name_len: name.bytesize,
          name_offset: 0,
          val_len: values[0].bytesize,
          val_offset: name.bytesize
        )
      end

      http_headers = LibLsquic::HttpHeaders.new(count: headers.size, headers: headers.to_unsafe)

      raise "Could not send headers" if LibLsquic.stream_send_headers(s, pointerof(http_headers), stream_ctx.request.body ? 0 : 1) != 0

      if body = stream_ctx.request.body.try &.gets_to_end
        LibLsquic.stream_write(s, body, body.bytesize)
        LibLsquic.stream_flush(s)
      end

      LibLsquic.stream_shutdown(s, 1)
      LibLsquic.stream_wantwrite(s, 0)
      LibLsquic.stream_wantread(s, 1)

      Box.box(stream_ctx)
    end

    def self.on_read(s : LibLsquic::StreamT, stream_if_ctx : Void*)
      stream_ctx = Box(StreamCtx).unbox(stream_if_ctx)
      bytes_read = LibLsquic.stream_readf(s, ->stream_readf, Box.box(stream_ctx))

      if bytes_read > 0
        # Nothing
      elsif bytes_read == 0
        LibLsquic.stream_shutdown(s, 0)
        LibLsquic.stream_wantread(s, 0)
      elsif LibLsquic.stream_is_rejected(s) == 1
        LibLsquic.stream_close(s)
      else
        # raise "Could not read response"
      end

      stream_if_ctx
    end

    def self.on_close(s : LibLsquic::StreamT, stream_if_ctx : Void*)
      stream_ctx = Box(StreamCtx).unbox(stream_if_ctx)
      stream_ctx.io.close
      GC.free stream_if_ctx
      stream_if_ctx
    end

    def self.ea_packets_out(peer_ctx : Void*, specs : LibLsquic::OutSpec*, count : LibC::UInt)
      packets_out = 0

      count.times do |i|
        spec = specs[i]
        socket = Box(UDPSocket).unbox(spec.peer_ctx)
        spec.iovlen.times do |j|
          iov = spec.iov[j]
          begin
            socket.send(iov.iov_base.to_slice(iov.iov_len), to: socket.remote_address)
            packets_out += 1
          rescue ex
            break
          end
        end
      end

      packets_out
    end

    ENGINE_FLAGS = LibLsquic::LSENG_HTTP
    LibLsquic.global_init(ENGINE_FLAGS & LibLsquic::LSENG_SERVER ? LibLsquic::GLOBAL_SERVER : LibLsquic::GLOBAL_CLIENT)

    property family : Socket::Family = Socket::Family::INET

    # The set of possible valid body types.
    alias BodyType = String | Bytes | IO | Nil

    getter host : String
    getter port : Int32
    getter! tls : OpenSSL::SSL::Context::Client

    @stream_channel : Channel(StreamCtx?)
    @dns_timeout : Float64?
    @connect_timeout : Float64?
    @read_timeout : Float64?
    @socket : UDPSocket?
    @stream_ctx : StreamCtx?
    @process_fiber : Fiber

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
      @stream_channel = Channel(StreamCtx?).new(20)
      @stream_ctx = nil
      @engine_open = false
      @process_fiber = Fiber.new { puts "process_fiber started before run_engine" }
    end

    def run_engine
      LibLsquic.engine_init_settings(out engine_settings, ENGINE_FLAGS)
      engine_settings.es_ua = "Chrome/83.0.4103.61 Linux x86_64"
      engine_settings.es_ecn = 0

      err_buf = Bytes.new(0x100)
      err_code = LibLsquic.engine_check_settings(pointerof(engine_settings), ENGINE_FLAGS, err_buf, err_buf.size)
      raise String.new(err_buf) if err_code != 0

      stream_if = LibLsquic::StreamIf.new
      stream_if.on_new_conn = ->QUIC::Client.on_new_conn(Void*, LibLsquic::ConnT)
      stream_if.on_conn_closed = ->QUIC::Client.on_conn_closed(LibLsquic::ConnT)
      stream_if.on_new_stream = ->QUIC::Client.on_new_stream(Void*, LibLsquic::StreamT)
      stream_if.on_write = ->QUIC::Client.on_write(LibLsquic::StreamT, Void*)
      stream_if.on_read = ->QUIC::Client.on_read(LibLsquic::StreamT, Void*)
      stream_if.on_close = ->QUIC::Client.on_close(LibLsquic::StreamT, Void*)

      engine_api = LibLsquic::EngineApi.new
      engine_api.ea_settings = pointerof(engine_settings)
      engine_api.ea_stream_if = pointerof(stream_if)
      engine_api.ea_packets_out = ->QUIC::Client.ea_packets_out(Void*, LibLsquic::OutSpec*, LibC::UInt)

      # logger_if = LibLsquic::LoggerIf.new
      # logger_if.log_buf = ->(logger_ctx : Void*, msg_buf : LibC::Char*, msg_size : LibC::SizeT) { puts String.new(msg_buf); 0 }
      # LibLsquic.logger_init(pointerof(logger_if), nil, LibLsquic::LoggerTimestampStyle::LltsHhmmssms)
      # LibLsquic.set_log_level("debug")

      engine = LibLsquic.engine_new(ENGINE_FLAGS, pointerof(engine_api))
      hostname = host.starts_with?('[') && host.ends_with?(']') ? host[1..-2] : host
      @engine_open = true

      conn = LibLsquic.engine_connect(
        engine,
        LibLsquic::Version::Lsqver050,
        socket.local_address,
        socket.remote_address,
        Box.box(socket), nil,
        hostname, 0,
        nil, 0,
        nil, 0
      )
      spawn do
        while stream_ctx = @stream_channel.receive
          LibLsquic.conn_set_ctx(conn, Box.box(stream_ctx))
          LibLsquic.conn_make_stream(conn)
          client_process_conns(engine)
        end
        @engine_open = false
        LibLsquic.engine_destroy(engine)
        @socket.try &.close
        @socket = nil
      end

      @process_fiber = spawn do
        loop do
          sleep
          LibLsquic.engine_process_conns(engine)
          diff = 0
          # check advisory time
          if LibLsquic.engine_earliest_adv_tick(engine, pointerof(diff)) != 0
            Crystal::Scheduler.current_fiber.resume_event.add(diff.microseconds)
          end
        end
      end

      begin
        buffers = [] of Bytes
        bytes_read = [] of Int32
        loop do
          # wait until the socket has something.
          socket.wait_readable
          # read available messages from the socket into the buffers.
          buffers_read = 0
          loop do
            if (buffers_read >= buffers.size)
              buffers.push(Bytes.new(0x600))
              bytes_read.push(0)
            end
            bytes_read[buffers_read] = LibC.recv(socket.fd, buffers[buffers_read], buffers[buffers_read].size, 0).to_i32
            if bytes_read[buffers_read] == -1
              if Errno.value == Errno::EAGAIN || Errno.value == Errno::EWOULDBLOCK
                # no more messages are currently available to read from the socket.
                break
              else
                raise IO::Error.from_errno("failed to read from socket")
              end
            end
            buffers_read += 1
          end
          break if !@engine_open
          buffers[0, buffers_read].zip(bytes_read) do |buffer, bytes|
            LibLsquic.engine_packet_in(engine, buffer[0, bytes], bytes, socket.local_address, socket.remote_address, Box.box(socket), 0) if bytes != 0
          end
          client_process_conns(engine)
        end
        @socket.try &.close
        @socket = nil
      rescue IO::Error
        # may have already been closed
      end
    end

    def client_process_conns(engine)
      Crystal::Scheduler.yield @process_fiber
    end

    def socket : UDPSocket
      socket = @socket
      return socket.not_nil! if @socket

      socket = UDPSocket.new @family
      case @family
      when Socket::Family::INET
        socket.bind Socket::IPAddress.new("0.0.0.0", 0)
      when Socket::Family::INET6
        socket.bind Socket::IPAddress.new("::", 0)
      else
        socket.bind Socket::IPAddress.new("0.0.0.0", 0)
      end

      Socket::Addrinfo.udp(@host, @port, timeout: @dns_timeout, family: @family) do |addrinfo|
        socket.connect(addrinfo, timeout: @connect_timeout) do |error|
          close
          error
        end
      end

      socket.read_timeout = @read_timeout if @read_timeout
      socket.sync = false

      @socket = socket
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

      raise "Unexpected end of http response"
    end

    private def exec_internal_single(request)
      io = send_request(request)
      HTTP::Client::Response.from_io?(io, ignore_body: request.ignore_body?)
    end

    private def handle_response(response)
      # close unless response.keep_alive?
      response
    end

    def exec(request : HTTP::Request, &block)
      exec_internal(request) do |response|
        yield response
      end
    end

    private def exec_internal(request, &block : HTTP::Client::Response -> T) : T forall T
      exec_internal_single(request) do |response|
        if response
          return handle_response(response) { yield response }
        end
      end
      raise "Unexpected end of http response"
    end

    private def exec_internal_single(request)
      io = send_request(request)
      HTTP::Client::Response.from_io?(io, ignore_body: request.ignore_body?) do |response|
        yield response
      end
    end

    private def handle_response(response)
      value = yield
      response.body_io?.try &.close
      # close unless response.keep_alive?
      value
    end

    private def send_request(request)
      set_defaults request
      run_before_request_callbacks(request)

      spawn run_engine if !@engine_open

      reader, writer = IO::ChanneledPipe.new
      # See https://github.com/crystal-lang/crystal/blob/0.32.0/src/openssl/ssl/context.cr#L126
      @stream_ctx = StreamCtx.new(request, writer)
      @stream_channel.send @stream_ctx
      reader
    end

    private def set_defaults(request)
      request.headers[":method"] ||= request.method
      request.headers[":scheme"] ||= "https"
      request.headers[":path"] ||= request.resource
      request.headers[":authority"] ||= host_header
      request.headers["user-agent"] ||= "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36"
    end

    private def self.default_one_shot_headers(headers)
      headers ||= HTTP::Headers.new
      headers["connection"] ||= "close"
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
      @stream_channel.send nil
      Fiber.yield
    end

    private def new_request(method, path, headers, body : BodyType)
      HTTP::Request.new(method, path, headers, body)
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
end
