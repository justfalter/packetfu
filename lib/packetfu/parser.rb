require 'set'
require 'stringio'
module PacketFu

  class Buffer
    def initialize(str = nil)
      @sio = StringIO.new
      @sio.set_encoding(Encoding::ASCII_8BIT)
      @sio.string = str unless str.nil?
    end

    # Returns the number of bytes remaining in the buffer.
    # @return [Integer] 
    def remaining_bytes
      @sio.length - @sio.pos
    end

    # @param [Integer] len The length to read
    # @return [String] 
    # @raise [EOFError] if an attempt to read beyond the end of the buffer is
    # made
    def read(len)
      ret = @sio.read(len)
      if ret.length != len
        @sio.pos = @sio.length
        raise EOFError.new
      end
      ret
    end

    # @return [String] returns the remaining buffer data
    def read_remaining()
      @sio.read()
    end

    # @return [Integer] the offset from the beginning of the buffer.
    def offset()
      @sio.pos
    end

    # Allows for attempts to read from the buffer. If the specificed block 
    # returns nil, then we assume a failure 
    def try()
      start = @sio.pos
      ret = yield()
      return ret
    ensure
      # Rewind in the event of any failure
      if ret.nil?
        @sio.pos = start
      end
    end
  end

  class ParseFailed < StandardError
  end

  # This is an interface that defines the packet parser.
  class AbstractParserInterface
    def initialize()
    end

    # @param [String] str The string that carries the packet data.
    def parse(str, args = {})
      parse_buffer(Buffer.new(str), args)
    end

    # @param [Buffer] buffer
    # @param [Hash] args
    # @param [Array] headers An array of headers that have been built up
    def parse_buffer(buffer, args = {}, headers = [])
      # Create and add our header...
      header = parse_header(buffer)
      headers << header

      if sub_parser = get_sub_parser(header)
        return sub_parser.parse_buffer(buffer, args, headers)
      end

      # Return the work product
      create_work_product(buffer, args, headers)
    end

    # Parses the buffer into the header object.
    # @param [Buffer] buffer
    # @return [Object] whatever the header object happens to be.
    def parse_header(buffer)
      raise NotImplementedError.new("#{self.class}#parse_header is not yet implemented")
    end
    
    # @return [ParserInterface] returns an instance of a ParserInterface that
    #  is intended to continue parsing beneath this level.
    def get_sub_parser(header)
      nil
    end

    def error!(msg)
      raise ParseFailed.new(msg)
    end
  end

  # This acts as an interface between the legacy behavior of PacketFu's 
  # packet implementation and 
  class LegacyParserInterface < AbstractParserInterface
    def initialize(header_klass, packet_klass)
      @header_klass = header_klass
      @packet_klass = packet_klass
      super()
    end

    def parse_header(buffer)
      header = @header_klass.new
      buffer.try { header.read_buffer(buffer) }
      header
    end

    def create_work_product(buffer, args = {}, headers = [])
      args[:headers] = headers
      ret = @packet_klass.new(args)
      ret.payload = buffer.read_remaining()
      ret
    end
  end

  class TCPParserImpl < LegacyParserInterface
    def initialize()
      super(TCPHeader, TCPPacket)
    end
  end

  TCPParser = TCPParserImpl.new

  class UDPParserImpl < LegacyParserInterface
    def initialize()
      super(UDPHeader, UDPPacket)
    end
  end

  UDPParser = UDPParserImpl.new

  class ICMPParserImpl < LegacyParserInterface
    def initialize()
      super(ICMPHeader, ICMPPacket)
    end
  end

  ICMPParser = ICMPParserImpl.new

  class ARPParserImpl < LegacyParserInterface
    def initialize()
      super(ARPHeader, ARPPacket)
    end
  end

  ARPParser = ARPParserImpl.new

  class IPParserImpl < LegacyParserInterface
    IP_TYPE_MAP = {
      1 => ICMPParser,
      6 => TCPParser, 
      17 => UDPParser,
    }

    def initialize()
      super(IPHeader, IPPacket)
    end

    def get_sub_parser(header)
      return IP_TYPE_MAP[header[:ip_proto].to_i]
    end
  end

  IPParser = IPParserImpl.new


  class IPv6ParserImpl < LegacyParserInterface
    def initialize()
      super(IPv6Header, IPv6Packet)
    end
  end

  IPv6Parser = IPv6ParserImpl.new

  class EthParserImpl < LegacyParserInterface
    ETH_TYPE_MAP = {
      0x0800 => IPParser,
      0x0806 => ARPParser,
      0x86dd => IPv6Parser
    }

    def initialize()
      super(EthHeader, EthPacket)
    end

    def get_sub_parser(header)
      return ETH_TYPE_MAP[header.eth_proto]
    end

  end

  EthParser = EthParserImpl.new
end


