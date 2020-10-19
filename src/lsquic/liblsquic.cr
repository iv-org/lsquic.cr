@[Link(ldflags: "#{__DIR__}/ext/liblsquic.a")]
lib LibLsquic
  LSENG_SERVER                               = 1
  LSENG_HTTP                                 = 2
  LSENG_HTTP_SERVER                          = LSENG_SERVER | LSENG_HTTP
  GLOBAL_CLIENT                              =   1
  GLOBAL_SERVER                              =   2
  MAJOR_VERSION                              =   2
  MINOR_VERSION                              =  23
  PATCH_VERSION                              =   1
  EXPERIMENTAL_Q098                          =   0
  DEPRECATED_VERSIONS                        =   0
  DF_MAX_STREAMS_IN                          = 100
  DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER  =   0
  DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT =   0
  DF_INIT_MAX_STREAMS_UNI_CLIENT             = 100
  DF_INIT_MAX_STREAMS_UNI_SERVER             =   3
  DF_IDLE_TIMEOUT                            =  30
  DF_PING_PERIOD                             =  15
  DF_SILENT_CLOSE                            =   1
  DF_MAX_HEADER_LIST_SIZE                    =   0
  DF_UA                                      = "LSQUIC"
  DF_STTL                                    = 86400
  DF_SUPPORT_NSTP                            =     0
  DF_SUPPORT_PUSH                            =     1
  DF_SUPPORT_TCID0                           =     1
  DF_HONOR_PRST                              =     0
  DF_SEND_PRST                               =     0
  DF_PROGRESS_CHECK                          =  1000
  DF_RW_ONCE                                 =     0
  DF_PROC_TIME_THRESH                        =     0
  DF_PACE_PACKETS                            =     1
  DF_CLOCK_GRANULARITY                       =  1000
  DF_SCID_LEN                                =     8
  DF_SCID_ISS_RATE                           =    60
  DF_QPACK_DEC_MAX_BLOCKED                   =   100
  DF_QPACK_DEC_MAX_SIZE                      =  4096
  DF_QPACK_ENC_MAX_BLOCKED                   =   100
  DF_QPACK_ENC_MAX_SIZE                      =  4096
  DF_ECN                                     =     0
  DF_ALLOW_MIGRATION                         =     1
  DF_QL_BITS                                 =     2
  DF_SPIN                                    =     1
  DF_DELAYED_ACKS                            =     0
  DF_TIMESTAMPS                              =     1
  DF_CC_ALGO                                 =     3
  LSQUIC_DF_CC_RTT_THRESH                    =  1500
  LSQUIC_DF_DATAGRAMS                        =     0
  LSQUIC_DF_OPTIMISTIC_NAT                   =     1
  LSQUIC_DF_EXT_HTTP_PRIO                    =     1
  DF_MAX_UDP_PAYLOAD_SIZE_RX                 =     0
  DF_GREASE_QUIC_BIT                         =     1
  DF_NOPROGRESS_TIMEOUT_SERVER               =    60
  DF_NOPROGRESS_TIMEOUT_CLIENT               =     0

  struct Cid
    len : UInt8
    u_cid : CidUCid
  end

  union CidUCid
    buf : LibC::UInt8T[20]
    id : LibC::UInt64T
  end

  alias Engine = Void
  alias Conn = Void
  alias ConnCtx = Void
  alias Stream = Void
  alias StreamCtx = Void

  struct HttpHeaders
    count : LibC::Int
    headers : LsxpackHeader*
  end

  struct LsxpackHeader
    buf : LibC::Char*
    name_hash : LibC::UInt32T
    nameval_hash : LibC::UInt32T
    name_offset : LibC::UInt16T
    name_len : LibC::UInt16T
    val_offset : LibC::UInt16T
    val_len : LibC::UInt16T
    chain_next_idx : LibC::UInt16T
    hpack_index : LibC::UInt8T
    qpack_index : LibC::UInt8T
    app_index : LibC::UInt8T
    flags : LibC::UInt8T
    indexed_type : LibC::UInt8T
    dec_overhead : LibC::UInt8T
  end

  struct Iovec
    iov_base : UInt8*
    iov_len : LibC::SizeT
  end

  struct StreamIf
    on_new_conn : (Void*, ConnT -> Void*)
    on_goaway_received : (ConnT -> Void*)
    on_conn_closed : (ConnT -> Void*)
    on_new_stream : (Void*, StreamT -> Void*)
    on_read : (StreamT, Void* -> Void*)
    on_write : (StreamT, Void* -> Void*)
    on_close : (StreamT, Void* -> Void*)
    on_dg_write : (ConnT, Void*, LibC::SizeT -> LibC::SizeT)
    on_datagram : (ConnT, Void*, LibC::SizeT -> Void*)
    on_hsk_done : (ConnT, HskStatus -> Void*)
    on_new_token : (ConnT, UInt8*, LibC::SizeT -> Void*)
    on_zero_rtt_info : (ConnT, UInt8*, LibC::SizeT -> Void*)
  end

  type ConnT = Void*
  type StreamT = Void*
  enum HskStatus
    LsqHskFail     = 0
    LsqHskOk       = 1
    LsqHsk0RttOk   = 2
    LsqHsk0RttFail = 3
  end

  struct EngineSettings
    es_versions : LibC::UInt
    es_cfcw : LibC::UInt
    es_sfcw : LibC::UInt
    es_max_cfcw : LibC::UInt
    es_max_sfcw : LibC::UInt
    es_max_streams_in : LibC::UInt
    es_handshake_to : LibC::ULong
    es_idle_conn_to : LibC::ULong
    es_silent_close : LibC::Int
    es_max_header_list_size : LibC::UInt
    es_ua : LibC::Char*
    es_sttl : LibC::UInt64T
    es_pdmd : LibC::UInt32T
    es_aead : LibC::UInt32T
    es_kexs : LibC::UInt32T
    es_max_inchoate : LibC::UInt
    es_support_push : LibC::Int
    es_support_tcid0 : LibC::Int
    es_support_nstp : LibC::Int
    es_honor_prst : LibC::Int
    es_send_prst : LibC::Int
    es_progress_check : LibC::UInt
    es_rw_once : LibC::Int
    es_proc_time_thresh : LibC::UInt
    es_pace_packets : LibC::Int
    es_clock_granularity : LibC::UInt
    es_cc_algo : LibC::UInt
    es_cc_rtt_thresh : LibC::UInt
    es_noprogress_timeout : LibC::UInt
    es_init_max_data : LibC::UInt
    es_init_max_stream_data_bidi_remote : LibC::UInt
    es_init_max_stream_data_bidi_local : LibC::UInt
    es_init_max_stream_data_uni : LibC::UInt
    es_init_max_streams_bidi : LibC::UInt
    es_init_max_streams_uni : LibC::UInt
    es_idle_timeout : LibC::UInt
    es_ping_period : LibC::UInt
    es_scid_len : LibC::UInt
    es_scid_iss_rate : LibC::UInt
    es_qpack_dec_max_size : LibC::UInt
    es_qpack_dec_max_blocked : LibC::UInt
    es_qpack_enc_max_size : LibC::UInt
    es_qpack_enc_max_blocked : LibC::UInt
    es_ecn : LibC::Int
    es_allow_migration : LibC::Int
    es_ql_bits : LibC::Int
    es_spin : LibC::Int
    es_delayed_acks : LibC::Int
    es_timestamps : LibC::Int
    es_max_packet_size_rx : LibC::UInt16T
    es_grease_quic_bit : LibC::Int
    es_dplpmtud : LibC::Int
    es_base_plpmtu : LibC::UInt16T
    es_max_plpmtu : LibC::UInt16T
    es_mtu_probe_timer : LibC::UInt
    es_datagrams : LibC::Int
    es_optimistic_nat : LibC::Int
    es_ext_http_prio : LibC::Int
  end

  fun engine_init_settings = lsquic_engine_init_settings(x0 : EngineSettings*, engine_flags : LibC::UInt)
  fun engine_check_settings = lsquic_engine_check_settings(settings : EngineSettings*, engine_flags : LibC::UInt, err_buf : LibC::Char*, err_buf_sz : LibC::SizeT) : LibC::Int

  struct OutSpec
    iov : Iovec*
    iovlen : LibC::SizeT
    local_sa : LibC::Sockaddr*
    dest_sa : LibC::Sockaddr*
    peer_ctx : Void*
    conn_ctx : ConnCtx*
    ecn : LibC::Int
  end

  struct SharedHashIf
    shi_insert : (Void*, Void*, LibC::UInt, Void*, LibC::UInt, TimeT -> LibC::Int)
    shi_delete : (Void*, Void*, LibC::UInt -> LibC::Int)
    shi_lookup : (Void*, Void*, LibC::UInt, Void**, LibC::UInt* -> LibC::Int)
  end

  alias TimeT = LibC::Long

  struct PackoutMemIf
    pmi_allocate : (Void*, Void*, ConnCtx*, LibC::UShort, LibC::Char -> Void*)
    pmi_release : (Void*, Void*, Void*, LibC::Char -> Void)
    pmi_return : (Void*, Void*, Void*, LibC::Char -> Void)
  end

  struct HsetIf
    hsi_create_header_set : (Void*, StreamT, LibC::Int -> Void*)
    hsi_prepare_decode : (Void*, LsxpackHeader*, LibC::SizeT -> LsxpackHeader*)
    hsi_process_header : (Void*, LsxpackHeader* -> LibC::Int)
    hsi_discard_header_set : (Void* -> Void)
    hsi_flags : HsiFlag
  end

  enum HsiFlag
    HsiHttp1X      = 2
    HsiHashName    = 4
    HsiHashNameval = 8
  end

  struct KeylogIf
    kli_open : (Void*, ConnT -> Void*)
    kli_log_line : (Void*, LibC::Char* -> Void)
    kli_close : (Void* -> Void)
  end

  struct EngineApi
    ea_settings : EngineSettings*
    ea_stream_if : StreamIf*
    ea_stream_if_ctx : Void*
    ea_packets_out : PacketsOutF
    ea_packets_out_ctx : Void*
    ea_lookup_cert : LookupCertF
    ea_cert_lu_ctx : Void*
    ea_get_ssl_ctx : (Void* -> SslCtxSt*)
    ea_shi : SharedHashIf*
    ea_shi_ctx : Void*
    ea_pmi : PackoutMemIf*
    ea_pmi_ctx : Void*
    ea_new_scids : CidsUpdateF
    ea_live_scids : CidsUpdateF
    ea_old_scids : CidsUpdateF
    ea_cids_update_ctx : Void*
    ea_verify_cert : (Void*, StackStX509* -> LibC::Int)
    ea_verify_ctx : Void*
    ea_hsi_if : HsetIf*
    ea_hsi_ctx : Void*
    ea_keylog_if : KeylogIf*
    ea_keylog_ctx : Void*
    ea_alpn : LibC::Char*
    ea_generate_scid : (ConnT*, CidT*, LibC::UInt -> Void*)
  end

  alias PacketsOutF = (Void*, OutSpec*, LibC::UInt -> LibC::Int)
  alias SslCtxSt = Void
  alias Sockaddr = LibC::Sockaddr
  alias LookupCertF = (Void*, Sockaddr*, LibC::Char* -> SslCtxSt*)
  type CidT = Cid
  alias CidsUpdateF = (Void*, Void**, CidT*, LibC::UInt -> Void)
  alias StackStX509 = Void
  fun engine_new = lsquic_engine_new(engine_flags : LibC::UInt, api : EngineApi*) : EngineT
  type EngineT = Void*
  fun engine_connect = lsquic_engine_connect(x0 : EngineT, x1 : Version, local_sa : Sockaddr*, peer_sa : Sockaddr*, peer_ctx : Void*, conn_ctx : Void*, hostname : LibC::Char*, base_plpmtu : LibC::UShort, sess_resume : UInt8*, sess_resume_len : LibC::SizeT, token : UInt8*, token_sz : LibC::SizeT) : ConnT

  enum Version
    Lsqver043    = 0
    Lsqver046    = 1
    Lsqver050    = 2
    LsqverId27   = 3
    LsqverId28   = 4
    LsqverId29   = 5
    LsqverId30   = 6
    LsqverId31   = 7
    LsqverVerneg = 8
    NLsqver      = 9
  end

  fun engine_packet_in = lsquic_engine_packet_in(x0 : EngineT, packet_in_data : UInt8*, packet_in_size : LibC::SizeT, sa_local : Sockaddr*, sa_peer : Sockaddr*, peer_ctx : Void*, ecn : LibC::Int) : LibC::Int
  fun engine_process_conns = lsquic_engine_process_conns(engine : EngineT)
  fun engine_has_unsent_packets = lsquic_engine_has_unsent_packets(engine : EngineT) : LibC::Int
  fun engine_send_unsent_packets = lsquic_engine_send_unsent_packets(engine : EngineT)
  fun engine_destroy = lsquic_engine_destroy(x0 : EngineT)
  fun conn_n_avail_streams = lsquic_conn_n_avail_streams(x0 : ConnT) : LibC::UInt
  fun conn_make_stream = lsquic_conn_make_stream(x0 : ConnT) : Void*
  fun conn_n_pending_streams = lsquic_conn_n_pending_streams(x0 : ConnT) : LibC::UInt
  fun conn_cancel_pending_streams = lsquic_conn_cancel_pending_streams(x0 : ConnT, n : LibC::UInt) : LibC::UInt
  fun conn_going_away = lsquic_conn_going_away(x0 : ConnT)
  fun conn_close = lsquic_conn_close(x0 : ConnT)
  fun stream_wantread = lsquic_stream_wantread(s : StreamT, is_want : LibC::Int) : LibC::Int
  fun stream_read = lsquic_stream_read(s : StreamT, buf : Void*, len : LibC::SizeT) : LibC::SizeT
  fun stream_readv = lsquic_stream_readv(s : StreamT, vec : Iovec*, iovcnt : LibC::Int) : LibC::SizeT
  fun stream_readf = lsquic_stream_readf(s : StreamT, readf : (Void*, UInt8*, LibC::SizeT, LibC::Int -> LibC::SizeT), ctx : Void*) : LibC::SizeT
  fun stream_wantwrite = lsquic_stream_wantwrite(s : StreamT, is_want : LibC::Int) : LibC::Int
  fun stream_write = lsquic_stream_write(s : StreamT, buf : Void*, len : LibC::SizeT) : LibC::SizeT
  fun stream_writev = lsquic_stream_writev(s : StreamT, vec : Iovec*, count : LibC::Int) : LibC::SizeT
  fun stream_pwritev = lsquic_stream_pwritev(s : StreamT, preadv : (Void*, Iovec, LibC::Int -> LibC::SizeT), user_data : Void*, n_to_write : LibC::SizeT) : LibC::SizeT

  struct Reader
    lsqr_read : (Void*, Void*, LibC::SizeT -> LibC::SizeT)
    lsqr_size : (Void* -> LibC::SizeT)
    lsqr_ctx : Void*
  end

  fun stream_writef = lsquic_stream_writef(x0 : StreamT, x1 : Reader*) : LibC::SizeT
  fun stream_flush = lsquic_stream_flush(s : StreamT) : LibC::Int
  fun stream_send_headers = lsquic_stream_send_headers(s : StreamT, headers : HttpHeaders*, eos : LibC::Int) : LibC::Int
  fun stream_get_hset = lsquic_stream_get_hset(x0 : StreamT) : Void*
  fun conn_push_stream = lsquic_conn_push_stream(c : ConnT, hdr_set : Void*, s : StreamT, headers : HttpHeaders*) : LibC::Int
  fun conn_is_push_enabled = lsquic_conn_is_push_enabled(x0 : ConnT) : LibC::Int
  fun stream_shutdown = lsquic_stream_shutdown(s : StreamT, how : LibC::Int) : LibC::Int
  fun stream_close = lsquic_stream_close(s : StreamT) : LibC::Int
  fun conn_get_server_cert_chain = lsquic_conn_get_server_cert_chain(x0 : ConnT) : StackStX509*
  fun stream_id = lsquic_stream_id(s : StreamT) : StreamIdT
  alias StreamIdT = LibC::UInt64T
  fun stream_get_ctx = lsquic_stream_get_ctx(s : StreamT) : Void*
  fun stream_is_pushed = lsquic_stream_is_pushed(s : StreamT) : LibC::Int
  fun stream_is_rejected = lsquic_stream_is_rejected(s : StreamT) : LibC::Int
  fun stream_refuse_push = lsquic_stream_refuse_push(s : StreamT) : LibC::Int
  fun stream_push_info = lsquic_stream_push_info(x0 : StreamT, ref_stream_id : StreamIdT*, hdr_set : Void**) : LibC::Int
  fun stream_priority = lsquic_stream_priority(s : StreamT) : LibC::UInt
  fun stream_set_priority = lsquic_stream_set_priority(s : StreamT, priority : LibC::UInt) : LibC::Int
  
  struct ExtHttpPrio
    urgency : UInt8
    incremental : LibC::Char
  end

  fun stream_get_http_prio = lsquic_stream_get_http_prio(s : StreamT, ext_http_prio : ExtHttpPrio* ) : LibC::Int
  fun stream_set_http_prio = lsquic_stream_set_http_prio(s : StreamT, ext_http_prio : ExtHttpPrio* ) : LibC::Int
  fun stream_conn = lsquic_stream_conn(s : StreamT) : ConnT
  fun conn_id = lsquic_conn_id(c : ConnT) : CidT*
  fun conn_get_engine = lsquic_conn_get_engine(c : ConnT) : EngineT
  fun conn_get_sockaddr = lsquic_conn_get_sockaddr(c : ConnT, local : Sockaddr**, peer : Sockaddr**) : LibC::Int
  fun conn_want_datagram_write = lsquic_conn_want_datagram_write(c : ConnT, is_want : LibC::Int) : LibC::Int
  fun conn_get_min_datagram_size = lsquic_conn_get_min_datagram_size(c : ConnT) : LibC::SizeT
  fun conn_set_min_datagram_size = lsquic_conn_set_min_datagram_size(c : ConnT, sz : LibC::SizeT) : LibC::Int

  struct LoggerIf
    log_buf : (Void*, LibC::Char*, LibC::SizeT -> LibC::Int)
  end

  fun logger_init = lsquic_logger_init(x0 : LoggerIf*, logger_ctx : Void*, x2 : LoggerTimestampStyle)

  enum LoggerTimestampStyle
    LltsNone             = 0
    LltsHhmmssms         = 1
    LltsYyyymmddHhmmssms = 2
    LltsChromelike       = 3
    LltsHhmmssus         = 4
    LltsYyyymmddHhmmssus = 5
    NLlts                = 6
  end

  fun set_log_level = lsquic_set_log_level(log_level : LibC::Char*) : LibC::Int
  fun logger_lopt = lsquic_logger_lopt(optarg : LibC::Char*) : LibC::Int
  fun engine_quic_versions = lsquic_engine_quic_versions(x0 : EngineT) : LibC::UInt
  fun global_init = lsquic_global_init(flags : LibC::Int) : LibC::Int
  fun global_cleanup = lsquic_global_cleanup
  fun conn_quic_version = lsquic_conn_quic_version(c : ConnT) : Version
  fun conn_crypto_keysize = lsquic_conn_crypto_keysize(c : ConnT) : LibC::Int
  fun conn_crypto_alg_keysize = lsquic_conn_crypto_alg_keysize(c : ConnT) : LibC::Int
  fun conn_crypto_ver = lsquic_conn_crypto_ver(c : ConnT) : CryptoVer
  enum CryptoVer
    LsqCryQuic   = 0
    LsqCryTlSv13 = 1
  end

  fun conn_crypto_cipher = lsquic_conn_crypto_cipher(c : ConnT) : LibC::Char*
  fun str2ver = lsquic_str2ver(str : LibC::Char*, len : LibC::SizeT) : Version
  fun alpn2ver = lsquic_alpn2ver(alpn : LibC::Char*, len : LibC::SizeT) : Version
  fun engine_cooldown = lsquic_engine_cooldown(x0 : EngineT)
  fun conn_get_ctx = lsquic_conn_get_ctx(x0 : ConnT) : Void*
  fun conn_set_ctx = lsquic_conn_set_ctx(x0 : ConnT, x1 : Void*)
  fun conn_get_peer_ctx = lsquic_conn_get_peer_ctx(x0 : ConnT, local_sa : Sockaddr*) : Void*
  fun conn_abort = lsquic_conn_abort(x0 : ConnT)
  fun get_alt_svc_versions = lsquic_get_alt_svc_versions(versions : LibC::UInt) : LibC::Char*
  fun get_h3_alpns = lsquic_get_h3_alpns(versions : LibC::UInt) : LibC::Char**
  fun is_valid_hs_packet = lsquic_is_valid_hs_packet(x0 : EngineT, x1 : UInt8*, x2 : LibC::SizeT) : LibC::Int
  fun cid_from_packet = lsquic_cid_from_packet(x0 : UInt8*, bufsz : LibC::SizeT, cid : CidT*) : LibC::Int
  fun engine_earliest_adv_tick = lsquic_engine_earliest_adv_tick(engine : EngineT, diff : LibC::Int*) : LibC::Int
  fun engine_count_attq = lsquic_engine_count_attq(engine : EngineT, from_now : LibC::Int) : LibC::UInt
  fun conn_status = lsquic_conn_status(x0 : ConnT, errbuf : LibC::Char*, bufsz : LibC::SizeT) : ConnStatus

  enum ConnStatus
    LsconnStHskInProgress = 0
    LsconnStConnected     = 1
    LsconnStHskFailure    = 2
    LsconnStGoingAway     = 3
    LsconnStTimedOut      = 4
    LsconnStReset         = 5
    LsconnStUserAborted   = 6
    LsconnStError         = 7
    LsconnStClosed        = 8
    LsconnStPeerGoingAway = 9
  end

  $lsquic_ver2str : LibC::Char*[7]
end
