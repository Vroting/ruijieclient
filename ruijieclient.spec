Name:           ruijieclient
Version:        0.7.0
Release:        1%{?dist}
Summary:        powerfull ruijieclient based on mystar, but re-write form scratch. 

Group:          System Environment/Daemons
License:        LGPL
URL:            http://code.google.com/p/ruijieclient/
Source0:        ruijieclient-%{version}
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libpcap-devel glibc-devel
Requires:       libpcap glibc

%description


%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc



%changelog
