require 'rubygems'

Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.name = 'guardtime'
  s.version = "0.0.4"
  s.summary = 'GuardTime service access extension for Ruby'
  s.description = <<-EOF
Keyless Signatures are a combination of hash function based server-side signatures and hash-linking based digital timestamping delivered using a distributed and hierarchical infrastructure.
This extension provides high-level API to access KSI.
  EOF
  s.author = 'GuardTime AS'
  s.email = 'info@guardtime.com'
  s.homepage = 'https://github.com/ristik/ruby-guardtime' 
  s.license = 'apache-2.0'
  s.has_rdoc = true
  s.rdoc_options = [ '--main', 'README.rdoc', 'README.rdoc', 'ext/guardtime.c' ]
  s.files = [ 'COPYING', 'INSTALL', 'README.rdoc', 'ChangeLog', 'ext/guardtime.c', 'ext/extconf.rb' ]
  s.files += Dir.glob('test/*')
  s.test_files = Dir.glob('test/tc_*.rb')
  s.extensions = ['ext/extconf.rb']
end
