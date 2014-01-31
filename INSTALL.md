= Dependencies:

- libcurl
- openssl 0.9.8+
- Guardtime C API

== installation on Debian:

   apt-get install ruby ruby-dev rubygems
   apt-get install libcurl-dev openssl-dev
   wget http://download.guardtime.com/libgt-0.3.12.tar.gz
   tar xfz libgt-0.3.12.tar.gz
   cd libgt-0.3.12
   ./configure --disable-shared
   make
   sudo make install
   cd ..
   sudo gem install guardtime-x.y.z.gem
or
   sudo gem install guardtime


== installation on OpenSolaris / OpenIndiana / Illumous / SmartOS

Please use 
   CPPFLAGS="-I/opt/local/include -fPIC" LDFLAGS="-L/opt/local/lib -R/opt/local/lib"  ./configure --prefix=/opt/local --disable-shared
for configuring the Guardtime C API. Adjust dependency install commands etc.
