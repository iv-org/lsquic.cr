require "openssl"

@[Link(ldflags: "#{__DIR__}/ext/liblsquic.a #{__DIR__}/ext/libcrypto.a")]
lib LibCrypto
  fun evp_ripemd160 = EVP_sha1 : EVP_MD
  fun sk_free = sk_free(st : Void*)
  fun sk_num = sk_num(x0 : Void*) : Int
  fun sk_pop_free = sk_pop_free(st : Void*, callback : (Void*) ->)
  fun sk_value = sk_value(x0 : Void*, x1 : Int) : Void*
end

@[Link(ldflags: "#{__DIR__}/ext/libssl.a")]
lib LibSSL
  fun ssl_set_tlsext_host_name = SSL_set_tlsext_host_name(handle : SSL, name : Char*) : Long
  fun ssl_ctx_set_tmp_ecdh = SSL_CTX_set_tmp_ecdh(ctx : SSLContext, parg : Void*) : ULong
  fun ssl_ctx_get_mode = SSL_CTX_get_mode(ctx : SSLContext) : ULong
  fun ssl_ctx_set_mode = SSL_CTX_set_mode(ctx : SSLContext, mode : ULong) : ULong
  fun ssl_ctx_clear_mode = SSL_CTX_clear_mode(ctx : SSLContext, mode : ULong) : ULong
end

abstract class OpenSSL::SSL::Context
  def set_tmp_ecdh_key(curve = LibCrypto::NID_X9_62_prime256v1)
    key = LibCrypto.ec_key_new_by_curve_name(curve)
    raise OpenSSL::Error.new("ec_key_new_by_curve_name") if key.null?
    LibSSL.ssl_ctx_set_tmp_ecdh(@handle, key)
    LibCrypto.ec_key_free(key)
  end

  # Returns the current modes set on the TLS context.
  def modes
    OpenSSL::SSL::Modes.new LibSSL.ssl_ctx_get_mode(@handle)
  end

  # Adds modes to the TLS context.
  def add_modes(mode : OpenSSL::SSL::Modes)
    OpenSSL::SSL::Modes.new LibSSL.ssl_ctx_set_mode(@handle, mode)
  end

  # Removes modes from the TLS context.
  def remove_modes(mode : OpenSSL::SSL::Modes)
    OpenSSL::SSL::Modes.new LibSSL.ssl_ctx_clear_mode(@handle, mode)
  end
end

struct OpenSSL::BIO
  CRYSTAL_BIO_BORING = begin
    bwrite = LibCrypto::BioMethodWriteOld.new do |bio, data, len|
      io = Box(IO).unbox(BIO.get_data(bio))
      io.write Slice.new(data, len)
      len
    end

    bwrite_ex = LibCrypto::BioMethodWrite.new do |bio, data, len, writep|
      count = len > Int32::MAX ? Int32::MAX : len.to_i
      io = Box(IO).unbox(BIO.get_data(bio))
      io.write Slice.new(data, count)
      writep.value = LibC::SizeT.new(count)
      1
    end

    bread = LibCrypto::BioMethodReadOld.new do |bio, buffer, len|
      io = Box(IO).unbox(BIO.get_data(bio))
      io.flush
      io.read(Slice.new(buffer, len)).to_i
    end

    bread_ex = LibCrypto::BioMethodWrite.new do |bio, buffer, len, readp|
      count = len > Int32::MAX ? Int32::MAX : len.to_i
      io = Box(IO).unbox(BIO.get_data(bio))
      io.flush
      ret = io.read Slice.new(buffer, count)
      readp.value = LibC::SizeT.new(ret)
      1
    end

    ctrl = LibCrypto::BioMethodCtrl.new do |bio, cmd, num, ptr|
      io = Box(IO).unbox(BIO.get_data(bio))

      val = case cmd
            when LibCrypto::CTRL_FLUSH
              io.flush
              1
            when LibCrypto::CTRL_PUSH, LibCrypto::CTRL_POP
              0
            else
              STDERR.puts "WARNING: Unsupported BIO ctrl call (#{cmd})"
              0
            end
      LibCrypto::Long.new(val)
    end

    create = LibCrypto::BioMethodCreate.new do |bio|
      {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
        LibCrypto.BIO_set_shutdown(bio, 1)
        LibCrypto.BIO_set_init(bio, 1)
        # bio.value.num = -1
      {% else %}
        bio.value.shutdown = 1
        bio.value.init = 1
        bio.value.num = -1
      {% end %}
      1
    end

    destroy = LibCrypto::BioMethodDestroy.new do |bio|
      BIO.set_data(bio, Pointer(Void).null)
      1
    end

    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      biom = LibCrypto.BIO_meth_new(Int32::MAX, "Crystal BIO")

      LibCrypto.BIO_meth_set_write(biom, bwrite)
      LibCrypto.BIO_meth_set_read(biom, bread)
      LibCrypto.BIO_meth_set_ctrl(biom, ctrl)
      LibCrypto.BIO_meth_set_create(biom, create)
      LibCrypto.BIO_meth_set_destroy(biom, destroy)
      biom
    {% else %}
      biom = Pointer(LibCrypto::BioMethod).malloc(1)
      biom.value.type_id = Int32::MAX
      biom.value.name = "Crystal BIO"
      biom.value.bwrite = bwrite
      biom.value.bread = bread
      biom.value.ctrl = ctrl
      biom.value.create = create
      biom.value.destroy = destroy
      biom
    {% end %}
  end

  def initialize(@io : IO)
    @bio = LibCrypto.BIO_new(CRYSTAL_BIO_BORING)

    # We need to store a reference to the box because it's
    # stored in `@bio.value.ptr`, but that lives in C-land,
    # not in Crystal-land.
    @boxed_io = Box(IO).box(io)

    BIO.set_data(@bio, @boxed_io)
  end
end

abstract class OpenSSL::SSL::Socket < IO
  class Client < Socket
    def initialize(io, context : Context::Client = Context::Client.new, sync_close : Bool = false, hostname : String? = nil)
      super(io, context, sync_close)
      begin
        if hostname
          LibSSL.ssl_set_tlsext_host_name(@ssl, hostname)

          {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0 %}
            param = LibSSL.ssl_get0_param(@ssl)

            if ::Socket.ip?(hostname)
              unless LibCrypto.x509_verify_param_set1_ip_asc(param, hostname) == 1
                raise OpenSSL::Error.new("X509_VERIFY_PARAM_set1_ip_asc")
              end
            else
              unless LibCrypto.x509_verify_param_set1_host(param, hostname, hostname.bytesize) == 1
                raise OpenSSL::Error.new("X509_VERIFY_PARAM_set1_host")
              end
            end
          {% else %}
            context.set_cert_verify_callback(hostname)
          {% end %}
        end

        ret = LibSSL.ssl_connect(@ssl)
        unless ret == 1
          raise OpenSSL::SSL::Error.new(@ssl, ret, "SSL_connect")
        end
      rescue ex
        LibSSL.ssl_free(@ssl) # GC never calls finalize, avoid mem leak
        raise ex
      end
    end
  end
end
