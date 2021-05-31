# frozen_string_literal: true

require 'spec_helper'

RSpec.describe AEZ do

  describe 'Test Vector' do

    # let(:encrypt_vector) { fixture_file('encrypt.json') }
    let(:encrypt_vector) { fixture_file('aez.json') }


    it 'should be encrypt and decrypt' do
      encrypt_vector.each do |v|
        next if v['data'].length > 1 # skipped due to lack of vector-AAD support in the C implementation

        key = v['k'].htb
        message = v['m'].htb
        ad = v['data'].map(&:htb).join
        nonce = v['nonce'].htb
        encrypted = AEZ.encrypt(key, message, ad, nonce, v['tau'])

        expect(encrypted.bth).to eq(v['c'])
        expect(encrypted.bytesize).to eq(v['c'].htb.bytesize)

        decrypted = AEZ.decrypt(key, encrypted, ad, nonce, v['tau'])
        expect(decrypted).to eq(message)
      end
    end

  end

end
