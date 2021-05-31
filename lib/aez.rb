# frozen_string_literal: true

require 'aez/version'
require 'ffi'

# AEZv5 ruby binding.
# [AEZv5](https://web.cs.ucdavis.edu/~rogaway/aez)
module AEZ

  class Error; end

  extend FFI::Library

  ffi_lib 'lib/aez/aezv5.so'

  attach_function :crypto_aead_encrypt, [:pointer, :pointer, :pointer, :ulong_long, :pointer, :ulong_long, :pointer, :pointer, :pointer], :int
  attach_function :crypto_aead_decrypt, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
  attach_function :aez_setup, [:pointer, :ulong_long, :pointer], :int
  attach_function :aez_encrypt, [:pointer, :pointer, :uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int

  module_function

  # @param [String] key key with binary format.
  # @param [String] message message with binary format.
  # @param [String] ad ad with binary format.
  # @param [String] nonce nonce with binary format.
  def encrypt(key, message, ad, nonce, abyte)
    ctx = FFI::MemoryPointer.new(144)
    key_m = FFI::MemoryPointer.new(:uchar, key.bytesize).put_bytes(0, key)
    aez_setup(key_m, key.bytesize, ctx)

    message_m = message.empty? ? nil : FFI::MemoryPointer.new(:uchar, message.bytesize).put_bytes(0, message)
    ad_m = ad.empty? ? nil : FFI::MemoryPointer.new(:char, ad.bytesize).put_bytes(0, ad)
    nonce_m = FFI::MemoryPointer.new(:char, nonce.bytesize).put_bytes(0, nonce)
    dest = FFI::MemoryPointer.new(:char, message.bytesize + abyte)

    aez_encrypt(ctx, nonce_m, nonce.bytesize, ad_m, ad.bytesize, abyte, message_m, message.bytesize, dest)
    dest.read_string(message.bytesize + abyte)
  end

  def decrypt

  end

end
