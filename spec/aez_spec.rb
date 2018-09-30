require 'spec_helper'

RSpec.describe AEZ do

  describe 'Test Vector' do

    let(:hash_vector) {fixture_file('hash.json')}

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

  end

end
