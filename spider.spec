Summary: Cornell Spider Engine for UNIX
Name: spider-engine
Version: 1.1.1
Release: 1
License: GPL
Group: Applications/Security
Source: https://kielbasa.ccit.arizona.edu/spider/spider-engine-1.1.1.tar.gz
URL: http://security.arizona.edu/pistep4U
Vendor: University of Arizona
Packager: Shawn Nock <nock@email.arizona.edu>
Prefix: ${_prefix}
Requires: expat, bzip2, openssl, pcre, file, zlib, libzip

%description
Cornell Spider Engine for UNIX

%prep
%setup -q

%build
cd $RPM_BUILD_DIR/spider-engine-1.1.1
./configure --prefix=${_prefix}
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT
%files
%defattr(-,root,root)
%doc AUTHORS ChangeLog COPYING INSTALL NEWS README
/bin/spider
/etc/spider/spider.conf
/etc/spider/SSNlin.xml
