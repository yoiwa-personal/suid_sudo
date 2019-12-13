#!gem build

Gem::Specification.new do |s|
  s.name        = 'suid_sudo'
  s.version     = open("VERSION"){|f| f.readline.chomp}
  s.licenses    = ['Apache-2.0']
  s.summary     = "Library for emulating setuid by sudo",
  s.description = open("suid_sudo.rb") {|f| f.read =~ /=begin rdoc\n(.*)=end/m; $1 }
  s.authors     = ["Yutaka OIWA"]
  s.email       = 'yutaka@oiwa.jp'
  s.files       = ["suid_sudo.rb", "README.md", "doc/APIs.md"]
  s.require_paths = ['.']
  s.homepage    = 'https://github.com/yoiwa-persona/suid_sudo/'
  s.metadata    = { "source_code_uri" => "https://github.com/yoiwa-personal/suid_sudo/" }
end
