require "aez/version"
require 'blake2b'

module AEZ

  BLOCK_SIZE = 16
  EXTRACTED_KEY_SIZE = 3 * 16

  autoload :Functions, 'aez/functions'
  autoload :State, 'aez/state'
  autoload :AESRound, 'aez/aes_round'

  extend Functions

  module_function

  # @param [String] key a key with binary format.
  # @param [String] nonce a nonce with binary format.
  # @param [String] additional_data
  # @param [Integer] tau
  # @param [String] plain_text plain text with binary format which are encrypt target.
  def encrypt(key, nonce, additional_data, tau, plain_text)
    additional_data ||= ''
    state = AEZ::State.new
    state.init(key)
    delta = state.aez_hash(nonce, additional_data, tau * 8)
    x = mk_block(plain_text.length + tau)
    if !plain_text || plain_text.length == 0
      x = state.aez_prf(delta, tau, x)
    else
      x[0, plain_text.length] = plain_text
      x = state.encipher(delta, x, x)
    end
    x
  end

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

    def itb
      to_even_hex.htb
    end
  end

end
