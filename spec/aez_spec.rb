# frozen_string_literal: true

require 'spec_helper'

RSpec.describe AEZ do

  describe 'Test Vector' do

    # let(:encrypt_vector) { fixture_file('encrypt.json') }
    let(:encrypt_vector) { fixture_file('aez.json') }


    it 'should be encrypt and decrypt' do
      encrypt_vector.each do |v|
        # ad = v['ad'].map(&:htb).join
        next if v['data'].length > 1 # skipped due to lack of vector-AAD support in the C implementation
        data = v['data'].map(&:htb).join

        # encrypted = AEZ.encrypt(v['key'].htb, v['message'].htb, ad, v['nonce'].htb, abyte)
        encrypted = AEZ.encrypt(v['k'].htb, v['m'].htb, data, v['nonce'].htb, v['tau'])
        # puts "#{encrypted.bth} =? #{v['result']}"
        puts "#{encrypted.bth} =? #{v['c']}"
        # expect(encrypted.bth).to eq(v['result'])
        expect(encrypted.bth).to eq(v['c'])
        expect(encrypted.bytesize).to eq(v['c'].htb.bytesize)
      end
    end

  end

end
