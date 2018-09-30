require 'spec_helper'

RSpec.describe AEZ do

  include AEZ::Functions

  describe 'Test Vector' do

    let(:hash_vector) {fixture_file('hash.json')}
    let(:prf_vector) {fixture_file('prf.json')}
    let(:extract_vector) {fixture_file('extract.json')}

    describe 'aezHash' do
      it 'should be calculate aezHash.' do
        hash_vector.each do |v|
          ad = v['ad'].map(&:htb)
          state = AEZ::State.new
          state.init(v['key'].htb)
          result = state.aez_hash(ad.shift, ad, v['tau'])
          expect(result.bth).to eq(v['result'])
        end
      end
    end

    describe 'aezPRF' do
      it 'should be calculate aezPRF' do
        prf_vector.each do |v|
          state = AEZ::State.new
          state.init(v['key'].htb)
          expect(state.aez_prf(v['delta'].htb, v['tau'], mk_block(v['tau'])).bth).to eq(v['result'])
        end
      end
    end

    describe 'extractKey' do
      it 'should be calculate extractKey' do
        extract_vector.each do |v|
          expect(extract_key(v['key'].htb).bth).to eq(v['result'])
        end
      end
    end
  end

end
