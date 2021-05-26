# frozen_string_literal: true

require 'mkmf'

$CFLAGS << ' -march=native'
$CPPFLAGS << ' -march=native'

# Create Makefile
create_makefile('aezv5')