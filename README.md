# AEZ for Ruby [![Build Status](https://github.com/azuchi/aez/actions/workflows/ruby.yml/badge.svg?branch=master)](https://github.com/azuchi/aez/actions/workflows/ruby.yml) [![Gem Version](https://badge.fury.io/rb/aez.svg)](https://badge.fury.io/rb/aez) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)

[AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/) binding for ruby.
This library calls AEZv5 implementation in C using AES-NI hardware optimizations via FFI.

## Requirements

There are the following limitations from Ted Krovetz's C implementation:

- Intel or ARM CPU supporting AES instructions
- Faster if all pointers are 16-byte aligned.
- Max 16 byte nonce, 16 byte authenticator
- Single AD (AEZ spec allows vector AD but this code doesn't)
- Max 2^32-1 byte buffers allowed (due to using unsigned int)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'aez'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install aez

## Usage

```ruby
require 'aez'

key = ['9adf7a023fbc4e663695f627a8d5b5c45f6752e375d19e11a669e6b949347d0cf5e0e2516ee285af365224976afa60be'].pack('H*')
nonce = ['799de3d90fbd6fed93b5f96cf9f4e852'].pack('H*')
ad = ['d6e278e0c6ede09d302d6fde09de77711a9a02fc8a049fb34a5e3f00c1cfc336d0'].pack('H*')
message = ['efea7ecfa45f51b52ce038cf6c0704392c2211bfca17a36284f63a902b37f0ab'].pack('H*')
abyte = 16

# Encryption
cipher_tex = AEZ.encrypt(key, message, ad, nonce, abyte)

# Decryption
plain_text = AEZ.decrypt(key, cipher_tex, ad, nonce, abyte)
```
