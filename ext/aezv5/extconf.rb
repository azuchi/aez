# frozen_string_literal: true

require 'mkmf'

$CFLAGS << ' -march=native'

# Create Makefile
create_makefile('aezv5')