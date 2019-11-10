#!/usr/bin/gem build
Gem::Specification.new do |s|
  s.name        = 'suid_sudo'
  s.version     = '0.1'
  s.licenses    = ['Apache-2.0']
  s.summary     = "Library for emulating setuid by sudo",
  s.description = open("README.md"){|f| f.read}
  s.authors     = ["Yutaka OIWA"]
  s.email       = 'yutaka@oiwa.jp'
  s.files       = ["suid_sudo.rb", "README.md", "doc/APIs.md"]
  s.require_paths = ['.']
  s.homepage    = 'https://rubygems.org/gems/example'
  s.metadata    = { "source_code_uri" => "https://github.com/example/example" }
end
