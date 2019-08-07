module AEZ

  class State

    include Functions

    attr_accessor :i
    attr_accessor :j
    attr_accessor :l
    attr_accessor :aes

    def initialize
      @i = [mk_block, mk_block]
      @j = [mk_block, mk_block, mk_block]
      @l = [mk_block, mk_block, mk_block, mk_block, mk_block, mk_block]
    end

    # @param [String] key a key with binary format.
    def init(key)
      extracted_key = extract_key(key)

      self.i[0] = extracted_key[0...16]
      self.i[1] = mult_block(2, i[0])

      self.j[0] = extracted_key[16...32]
      self.j[1] = mult_block(2, j[0])
      self.j[2] = mult_block(2, j[1])

      self.l[1] = extracted_key[32...48]
      self.l[2] = mult_block(2, l[1])
      self.l[3] = xor_bytes_1x16(l[2], l[1])
      self.l[4] = mult_block(2, l[2])
      self.l[5] = xor_bytes_1x16(l[4], l[1])
      self.l[6] = mult_block(2, l[3])
      self.l[7] = xor_bytes_1x16(l[6], l[1])

      self.aes = AESRound.new(extracted_key)
    end

    def aez_hash(nonce, ad, tau)
      buf, sum, ii, jj = [mk_block, mk_block, mk_block, mk_block]
      tau = [uint32(tau)].pack('I*').reverse
      buf[12, tau.bytesize] = tau
      jj[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(j[0], j[1])
      sum = aes.AES4(jj, i[1], l[1], buf)

      empty = !nonce || nonce.length == 0
      n = nonce
      n_bytes = empty ? 0 : nonce.length
      ii = i[1]
      index = 1
      while n_bytes >= AEZ::BLOCK_SIZE
        buf = aes.AES4(j[2], ii, l[index % 8], n[0..AEZ::BLOCK_SIZE])
        sum[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(sum, buf)
        n = n[AEZ::BLOCK_SIZE..-1]
        ii = double_block(ii) if index % 8 == 0
        n_bytes -= AEZ::BLOCK_SIZE
        index += 1
      end

      if n_bytes > 0 || empty
        buf = mk_block(buf.length)
        buf[0...n.length] = n unless empty
        buf[n_bytes] = '80'.htb
        buf = aes.AES4(j[2], i[0], l[0], buf)
        sum[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(sum, buf)
      end

      ad.each_with_index do |p, k|
        empty = !p || p.length == 0
        bytes = empty ? 0 : p.length
        ii[0..i[1].length] = i[1]
        jj = mult_block(5 + k, j[0])

        index = 1
        while bytes >= AEZ::BLOCK_SIZE
          buf = aes.AES4(jj, ii, l[index % 8], p[0..AEZ::BLOCK_SIZE])
          sum[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(sum, buf)
          p = p[AEZ::BLOCK_SIZE..-1]
          ii = double_block(ii) if index % 8 == 0
          bytes -= AEZ::BLOCK_SIZE
          index +=1
        end

        if bytes > 0 || empty
          buf = mk_block(buf.length)
          buf[0...p.length] = p unless empty
          buf[bytes] = '80'.htb
          buf = aes.AES4(jj, i[0], l[0], buf)
          sum[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(sum, buf)
        end
      end

      sum
    end

    def aez_prf(delta, tau, block)
      buf, ctr = [mk_block, mk_block]
      off = 0
      while tau >= AEZ::BLOCK_SIZE
        buf[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(delta, ctr)
        buf = aes.AES10(l[3], buf)
        block[off, buf.length] = buf
        i = 15
        loop do
          ctr[i] = (ctr[i].bti + 1).itb
          i -= 1
          break unless ctr[i+1].bti == 0
        end
        tau -= AEZ::BLOCK_SIZE
        off += AEZ::BLOCK_SIZE
      end

      if tau > 0
        buf[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(delta, ctr)
        buf = aes.AES10(l[3], buf)
        block[off..block.length] = buf[0...(block.length - off)]
      end
      block
    end

    def encipher(delta, input, dst)
      if input.length < 32
        aez_tiny(delta, input, 0, dst)
      else
        # aez_core(delta, input, 0, dst)
      end
    end

    def aez_tiny(delta, input, d, dst)
      in_bytes = input.bytesize
      buf = mk_block(2 * AEZ::BLOCK_SIZE)
      ll, r, tmp = [mk_block, mk_block, mk_block]
      mask = 0x00
      pad = 0x80
      ii = 7
      rounds = 8
      if in_bytes == 1
        rounds = 24
      elsif in_bytes == 2
        rounds = 16
      elsif in_bytes < 16
        rounds = 10
      else
        ii = 6
      end

      ll[0, ((in_bytes + 1)/2)] = input[0...((in_bytes + 1)/2)]
      r[0] = input[(in_bytes / 2)...((in_bytes / 2) + ((in_bytes + 1) / 2))]

      unless (in_bytes & 1) == 0
        (in_bytes / 2.0).ceil.times do |k|
          r[k] = ((r[k].bti << 4) | (r[k+1].bti >>4)).itb[-1]
        end
        r[(in_bytes/2.0).ceil] = (r[(in_bytes/2.0).ceil].bti << 4).itb[-1]
        pad = 0x08
        mask = 0xf0
      end

      step = 1
      jj = 0
      unless d == 0
        if in_bytes < 16
          buf[0, AEZ::BLOCK_SIZE] = input[0..AEZ::BLOCK_SIZE]
          buf[0] ||= '00'.htb
          buf[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(delta, buf)
          tmp = aes.AES4(mk_block, i[1], l[3], buf)
          self.l[0] = (l[0].bti ^ (tmp[0].bti & 0x80)).itb
        end
        step = -1
        jj = rounds -1
      end

      (rounds / 2).times do |k|
        buf = mk_block
        buf[0, ((in_bytes + 1)/2)] = r[0, ((in_bytes + 1)/2)]
        buf[(in_bytes/2.0).floor] = ((buf[(in_bytes/2.0).floor].bti & mask) | pad).itb
        buf = xor_bytes_1x16(delta, buf)
        buf[15] = (buf[15].bti ^ jj).itb
        tmp = aes.AES4(mk_block, i[1], l[ii], buf)
        ll[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(ll, tmp)

        buf = mk_block
        buf[0, ((in_bytes + 1)/2)] = ll[0, ((in_bytes + 1)/2)]
        buf[(in_bytes/2.0).floor] = ((buf[(in_bytes/2.0).floor].bti & mask) | pad).itb
        buf = xor_bytes_1x16(buf, delta)
        buf[15] = (buf[15].bti ^ (jj + step)).itb
        tmp = aes.AES4(mk_block, i[1], l[ii], buf)
        r[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(r, tmp)
        jj += step * 2
      end

      buf[0, (in_bytes / 2.0).floor] = r[0, (in_bytes / 2.0).floor]
      buf[(in_bytes / 2.0).floor, ((in_bytes + 1) / 2.0).floor] = ll[0, ((in_bytes + 1) / 2.0).floor]

      unless in_bytes & 1 == 0
        k = in_bytes - 1
        while k > (in_bytes / 2)
          buf[k] = (buf[k].bti >> 4 | buf[k-1].bti << 4).itb[-1]
          k -= 1
        end
        buf[(in_bytes / 2.0).floor] = ((ll[0].bti >> 4) | (r[(in_bytes / 2.0).floor].bti & 0xf0)).itb[0]
      end

      dst[0, in_bytes] = buf[0, in_bytes]
      if in_bytes < 16 && d == 0
        buf[in_bytes, AEZ::BLOCK_SIZE] = ('00' * (AEZ::BLOCK_SIZE - in_bytes)).htb
        buf[0] = (buf[0].bti | 0x80).itb
        buf[0, AEZ::BLOCK_SIZE] = xor_bytes_1x16(delta, buf)
        tmp = aes.AES4(mk_block, i[1], l[3], buf)
        dst[0] = (dst[0].bti ^ (tmp[0].bti & 0x80)).itb
      end
      dst
    end

  end

end