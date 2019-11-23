require "./lsquic/*"

module QUIC
  VERSION = "#{LibLsquic::MAJOR_VERSION}.#{LibLsquic::MINOR_VERSION}.#{LibLsquic::PATCH_VERSION}"
end
