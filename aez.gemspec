
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'aez/version'

Gem::Specification.new do |spec|
  spec.name          = 'aez'
  spec.version       = AEZ::VERSION
  spec.authors       = ['Shigeyuki Azuchi']
  spec.email         = ['azuchi@chaintope.com']

  spec.summary       = 'AEZ binding for ruby.'
  spec.description   = 'AEZ binding for ruby.'
  spec.homepage      = 'https://github.com/azuchi/aez'
  spec.license       = 'MIT'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']
  spec.extensions = ['ext/aezv5/extconf.rb']
  spec.add_runtime_dependency 'ffi', '>= 1.15.1'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake', '>= 12.3.3'
  spec.add_development_dependency 'rake-compiler', '>= 1.1.1'
  spec.add_development_dependency 'rspec', '~> 3.0'

end
