%define module_name mod_libmemcached_deny
%define hash 7d894e2

Summary: A proftpd module:  IP based access control module with libmemcahced
Name: proftpd-%{module_name}
Version: 0.1
Release: 1
License: Perl
Group: System Environment/Daemons
URL: http://github.com/hiboma/proftpd-%{module_name}
Source0: hiboma-proftpd-%{module_name}-%{hash}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: proftpd libmemcached
BuildRequires: libmemcached-devel proftpd-devel
Requires: libmemcached proftpd

%description
A proftpd module:  IP based access control module with libmemcahced

%prep
%setup -q -n hiboma-proftpd-%{module_name}-%{hash}

%build
%{_bindir}/prxs -c %{module_name}.c -l=memcached 

%install
rm -rf   ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{_libexecdir}/proftpd
libtool --mode=install /usr/bin/install -c %{module_name}.la ${RPM_BUILD_ROOT}/%{_libexecdir}/proftpd

%clean
%{__rm} -rf %{buildroot}

%pre

%post

%preun

%postun

%files
%defattr(-,root,root,-)
%{_libexecdir}/proftpd/%{module_name}.a
%{_libexecdir}/proftpd/%{module_name}.la
%{_libexecdir}/proftpd/%{module_name}.so

%changelog
* Mon Feb 8 2010 Hiroya Ito <hiroyan@gmail.com> 0.1-1
 - wrote spec
