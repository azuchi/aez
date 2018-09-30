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
      jj = xor_bytes_1x16(j[0], j[1])
      sum = aes.AES4(jj, i[1], l[1], buf)

      empty = !nonce || nonce.length == 0
      n = nonce
      n_bytes = empty ? 0 : nonce.length
      ii = i[1]
      index = 1
      while n_bytes >= AEZ::BLOCK_SIZE
        buf = aes.AES4(j[2], ii, l[index % 8], n[0..AEZ::BLOCK_SIZE])
        sum = xor_bytes_1x16(sum, buf)
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
        sum = xor_bytes_1x16(sum, buf)
      end

      ad.each_with_index do |p, k|
        empty = !p || p.length == 0
        bytes = empty ? 0 : p.length
        ii[0..i[1].length] = i[1]
        jj = mult_block(5 + k, j[0])

        index = 1
        while bytes >= AEZ::BLOCK_SIZE
          buf = aes.AES4(jj, ii, l[index % 8], p[0..AEZ::BLOCK_SIZE])
          sum = xor_bytes_1x16(sum, buf)
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
          sum = xor_bytes_1x16(sum, buf)
        end
      end

      sum
    end

  end

end
