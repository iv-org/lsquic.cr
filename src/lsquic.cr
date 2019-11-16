require "./lsquic/*"

module QUIC
  VERSION      = "0.1.0"
  QUIC_VERSION = "#{LibLsquic::MAJOR_VERSION}.#{LibLsquic::MINOR_VERSION}.#{LibLsquic::PATCH_VERSION}"
end
