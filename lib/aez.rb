# frozen_string_literal: true

require 'aez/version'
require 'ffi'

# AEZv5 ruby binding.
# [AEZv5](https://web.cs.ucdavis.edu/~rogaway/aez)
module AEZ

  class Error; end

  MAX_CIPHER_TXT_LENGTH = 2**32 - 1

  extend FFI::Library

  lib_name = 'aezv5'
  file_name =
    case RbConfig::CONFIG['host_os'].downcase
    when /darwin|mac os/
      "#{lib_name}.dylib"
    when /linux/
      "#{lib_name}.so"
    end

  ffi_lib File.expand_path(file_name, __dir__)

  attach_function :aez_setup, [:pointer, :ulong_long, :pointer], :int
  attach_function :aez_encrypt, [:pointer, :pointer, :uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int
  attach_function :aez_decrypt, [:pointer, :pointer, :uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int

  module_function

  # Encrypt a message.
  # @param [String] key key with binary format.
  # @param [String] message message with binary format.
  # @param [String] ad ad with binary format.
  # @param [String] nonce nonce with binary format. The nonce length must be `1..=16`
  # @param [Integer] abyte authenticator length which determines how much longer a ciphertext is than its plaintext.
  # @return [String] cipher text with binary format. The ciphertext may be up to 16 bytes larger than the message,
  # these extra bytes add authentication.
  def encrypt(key, message, ad, nonce, abyte)
    raise Error, 'invalid nonce.' if nonce.empty? || nonce.bytesize > 16

    with_context(key) do |context|
      message_m = message.empty? ? nil : FFI::MemoryPointer.new(:uchar, message.bytesize).put_bytes(0, message)
      ad_m = ad.empty? ? nil : FFI::MemoryPointer.new(:char, ad.bytesize).put_bytes(0, ad)
      nonce_m = FFI::MemoryPointer.new(:char, nonce.bytesize).put_bytes(0, nonce)
      dest = FFI::MemoryPointer.new(:char, message.bytesize + abyte)

      aez_encrypt(context, nonce_m, nonce.bytesize, ad_m, ad.bytesize, abyte, message_m, message.bytesize, dest)
      dest.read_string(message.bytesize + abyte)
    end
  end

  # Decrypt a message.
  # @param [String] key key with binary format.
  # @param [String] ciphertxt cipher text with binary format. the ciphertext must not be larger than `2^32 - 1`.
  # @param [String] ad ad with binary format.
  # @param [String] nonce nonce with binary format. The nonce length must be `1..=16`.
  # @param [Integer] abyte authenticator length which determines how much longer a ciphertext is than its plaintext.
  # @return [String] plain text with binary format.
  def decrypt(key, ciphertxt, ad, nonce, abyte)
    raise Error, 'invalid nonce.' if nonce.empty? || nonce.bytesize > 16
    raise Error, 'ciphertxt length too long.' unless ciphertxt.bytesize < MAX_CIPHER_TXT_LENGTH

    with_context(key) do |context|
      ciphertxt_m = FFI::MemoryPointer.new(:uchar, ciphertxt.bytesize).put_bytes(0, ciphertxt)
      ad_m = ad.empty? ? nil : FFI::MemoryPointer.new(:char, ad.bytesize).put_bytes(0, ad)
      nonce_m = FFI::MemoryPointer.new(:char, nonce.bytesize).put_bytes(0, nonce)
      dest = FFI::MemoryPointer.new(:char, ciphertxt.bytesize - abyte)
      result = aez_decrypt(context, nonce_m, nonce.bytesize, ad_m, ad.bytesize, abyte, ciphertxt_m, ciphertxt.bytesize, dest)
      raise Error, 'decrypt failure.' unless result == 0

      dest.read_string(ciphertxt.bytesize - abyte)
    end
  end

  def with_context(key)
    context = FFI::MemoryPointer.new(144)
    key_m = FFI::MemoryPointer.new(:uchar, key.bytesize).put_bytes(0, key)
    aez_setup(key_m, key.bytesize, context)
    yield(context) if block_given?
  end

end
