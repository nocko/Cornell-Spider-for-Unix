Summary: Cornell Spider Engine for UNIX
Name: spider
Version: 1.1.1
Release: 1
License: GPL
Group: Applications/Security
Source: https://kielbasa.ccit.arizona.edu/spider/spider-engine-1.1.1.tar.gz
URL: http://security.arizona.edu/pistep4U
Vendor: University of Arizona
Packager: Shawn Nock <nock@email.arizona.edu>

%description
Cornell Spider Engine for UNIX

%prep
rm -rf $RPM_BUILD_DIR/spider-engine-1.1.1
cd $RPM_BUILD_DIR
tar xf $RPM_SOURCE_DIR/spider-engine-1.1.1.tar.gz

%build
cd $RPM_BUILD_DIR/spider-engine-1.1.1
./configure --enable-static
make

%install
cd $RPM_BUILD_DIR/spider-engine-1.1.1
make install

%files
/usr/local/bin/spider
/usr/local/etc/spider/spider.conf
/usr/local/etc/spider/SSNlin.xml
