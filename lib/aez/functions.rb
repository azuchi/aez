module AEZ
  module Functions

    def extract_key(key)
      return key if key && key.size == AEZ::EXTRACTED_KEY_SIZE
      Blake2b.hex(key, Blake2b::Key.none, AEZ::EXTRACTED_KEY_SIZE).htb
    end

    def mk_block(size = AEZ::BLOCK_SIZE)
      ('00' * size).htb
    end

    def mult_block(x, src)
      r = mk_block
      t = src.dup
      until x == 0
        r = xor_bytes_1x16(r, t) unless (x & 1) == 0
        t = double_block(t)
        x >>= 1
      end
      r
    end

    def xor_bytes_1x16(a, b)
      a = a.each_byte.to_a
      b = b.each_byte.to_a
      BLOCK_SIZE.times.map do |i|
        (a[i] ^ b[i]).to_even_hex.htb
      end.join
    end

    def xor_bytes_4x16(a, b, c, d)
      a = a.each_byte.to_a
      b = b.each_byte.to_a
      c = c.each_byte.to_a
      d = d.each_byte.to_a
      BLOCK_SIZE.times.map do |i|
        (a[i] ^ b[i] ^ c[i] ^ d[i]).to_even_hex.htb
      end.join
    end

    def double_block(p)
      p = p.each_byte.to_a
      tmp = p[0]
      15.times do |i|
        p[i] = ((p[i] << 1) | (p[i+1] >> 7))
      end
      p[15] = (p[15] << 1) ^ ((tmp >> 7) == 0 ? 0 : 135)
      p.pack('C*')
    end

    def uint32(i)
      i >> 0
    end

    def uint8(i)
      0x000000ff & i
    end

  end
end