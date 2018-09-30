require "aez/version"

module AEZ

  BLOCK_SIZE = 16
  EXTRACTED_KEY_SIZE = 3 * 16

  autoload :Functions, 'aez/functions'
  autoload :State, 'aez/state'
  autoload :AESRound, 'aez/aes_round'

  class ::String
    # convert hex to binary
    def htb
      [self].pack('H*')
    end

    # convert binary to hex
    def bth
      unpack('H*').first
    end

    def bti
      bth.to_i(16)
    end
  end

  class ::Integer
    def to_even_hex(byte_len = nil)
      hex = to_s(16)
      if byte_len
        hex.rjust(byte_len * 2, '0')
      else
        hex.rjust((hex.length / 2.0).ceil * 2, '0')
      end
    end
  end

end
