Name: perl-AptPkg
Version: 0.1.24
Release: alt1.1

Summary: Perl interface to libapt-pkg
License: GPL
Group: Development/Perl

URL: http://packages.debian.org/unstable/perl/libapt-pkg-perl
Source: libapt-pkg-perl-%version.tar
Patch: %name-%version-%release.patch

# Automatically added by buildreq on Fri Nov 27 2009
BuildRequires: apt gcc-c++ libapt-devel perl-devel

%description
A Perl interface to APT's libapt-pkg which provides modules
for configuration file/command line parsing, version comparison,
inspection of the binary package cache and source package details.

%prep
%setup -q -n libapt-pkg-perl-%version
%patch -p1
cp -a /etc/apt/* t/cache/etc/

%build
%perl_vendor_build INC=-I%_includedir/rpm ||:

%install
%perl_vendor_install

%files
%doc	README debian/changelog examples
	%perl_vendor_archlib/AptPkg.pm
%dir	%perl_vendor_archlib/AptPkg
	%perl_vendor_archlib/AptPkg/*.pm
%doc	%perl_vendor_archlib/AptPkg/*.pod
%dir	%perl_vendor_autolib/AptPkg
	%perl_vendor_autolib/AptPkg/AptPkg.so

%changelog
* Mon Dec 21 2009 Alexey I. Froloff <raorn@altlinux.org> 0.1.24-alt1.1
- NMU:
  + rebuilt with apt 0.5.15lorg2-alt31.1
  + AptPkg::PkgRecords::lookup(): also return raw changelog text

* Fri Nov 27 2009 Alexey Tourbin <at@altlinux.ru> 0.1.24-alt1
- 0.1.22 -> 0.1.24

* Sat Aug 30 2008 Alexey Tourbin <at@altlinux.ru> 0.1.22-alt1
- 0.1.20 -> 0.1.22

* Sat Jan 06 2007 Alexey Tourbin <at@altlinux.ru> 0.1.20-alt2
- rebuilt with new libapt-pkg/glibc

* Sat Jun 17 2006 Alexey Tourbin <at@altlinux.ru> 0.1.20-alt1
- 0.1.12 -> 0.1.20

* Tue Aug 10 2004 Alexey Tourbin <at@altlinux.ru> 0.1.12-alt1
- initial revision
- fc-rpm.patch: fix build
- license: GPL