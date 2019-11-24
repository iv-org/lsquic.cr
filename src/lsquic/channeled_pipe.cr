# Based on https://github.com/anykeyh/channeled_pipe/blob/master/src/channeled_pipe/channeled_pipe.cr
class IO::ChanneledPipe < IO
  BUFFER_SIZE = 8192

  include IO::Buffered

  @channel : Channel(Bytes?)
  @direction : Symbol
  @buffer : Bytes?

  getter? closed = false

  protected def initialize(@channel, @direction)
  end

  def unbuffered_read(slice : Bytes)
    raise "Cannot read from write side" if @direction == :w
    return 0 if @channel.closed? && !@buffer

    buffer = @buffer

    if buffer
      bytes_read = {slice.size, buffer.size}.min
      slice.copy_from(buffer.to_unsafe, bytes_read)

      if buffer.size == bytes_read
        @buffer = nil
      else
        @buffer = buffer[bytes_read, buffer.size - bytes_read]
      end

      return bytes_read
    else
      buffer = @channel.receive

      if buffer
        bytes_read = {slice.size, buffer.size}.min
        slice.copy_from(buffer.to_unsafe, bytes_read)

        if buffer.size > bytes_read
          @buffer = buffer[bytes_read, buffer.size - bytes_read]
        end

        return bytes_read
      else
        @channel.close
        return 0
      end
    end
  end

  def unbuffered_write(slice : Bytes)
    raise "Write not allowed on read side" if @direction == :r
    raise "Closed stream" if @closed
    @channel.send slice.clone
  end

  def close_channel
    @channel.close
  end

  def unbuffered_flush
    # Nothing
  end

  def unbuffered_rewind
    raise IO::Error.new("Can't rewind")
  end

  def unbuffered_close
    return if @closed
    @closed = true
    @channel.send nil
  end

  def self.new(mem = BUFFER_SIZE)
    mem = BUFFER_SIZE if mem <= 0

    capacity = (mem / BUFFER_SIZE) +
               ((mem % BUFFER_SIZE != 0) ? 1 : 0)

    channel = Channel(Bytes?).new(capacity: mem)

    {
      ChanneledPipe.new(channel, :r),
      ChanneledPipe.new(channel, :w),
    }
  end
end
