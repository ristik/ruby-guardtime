require 'mkmf'

dir_config("guardtime")
have_library("gtbase")
have_library("gthttp")
have_library("crypto")
have_library("curl")

$defs.push("-DRUBY_VERSION=" + RUBY_VERSION.delete('.'))

create_makefile("guardtime")
