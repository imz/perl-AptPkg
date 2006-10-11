Name: perl-AptPkg
Version: 0.1.20
Release: alt1

Summary: Perl interface to libapt-pkg
License: GPL
Group: Development/Perl

URL: http://packages.debian.org/unstable/perl/libapt-pkg-perl
Source: libapt-pkg-perl-%version%release.tar

# Automatically added by buildreq on Wed Oct 11 2006
BuildRequires: apt gcc-c++ libapt-devel perl-devel

%description
A Perl interface to APT's libapt-pkg which provides modules
for configuration file/command line parsing, version comparison,
inspection of the binary package cache and source package details.

%prep
%setup -q -n libapt-pkg-perl-%version%release
cp -a /etc/apt/* t/cache/etc/

%build
%perl_vendor_build INC=-I%_includedir/rpm ||:

%install
%perl_vendor_install

%files
%doc README debian/changelog examples
%perl_vendor_archlib/AptPkg*
%perl_vendor_autolib/AptPkg*

%changelog
* Sat Jun 17 2006 Alexey Tourbin <at@altlinux.ru> 0.1.20-alt1
- 0.1.12 -> 0.1.20

* Tue Aug 10 2004 Alexey Tourbin <at@altlinux.ru> 0.1.12-alt1
- initial revision
- fc-rpm.patch: fix build
- license: GPL
