Name: drms_analysis
Version: %{DRMSVER}
Release: %{GITBRANCH}_%{GITCOMMIT}%{?dist}
Summary: DRMS Server for YamuDNS

Group: Yamu Tech Co Ltd.
License: GPLv3+
URL: http://www.yamu.com/
Source0: %{name}-%{version}.tar.gz

BuildRequires: info
Requires: info

%description
DRMS Server for YamuDNS

%define debug_package %{nil}

%prep
%setup -q


%build
exit 0
#%configure
#make %{?_smp_mflags}


%install
mkdir -p ${RPM_BUILD_ROOT}/%{_bindir}
install -m 0755 bin/%{name} ${RPM_BUILD_ROOT}/%{_bindir}/%{name}
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/init.d
install -m 0755 etc/init.d/%{name} ${RPM_BUILD_ROOT}/%{_sysconfdir}/init.d/%{name}
install -m 0644 etc/%{name}.ini ${RPM_BUILD_ROOT}/%{_sysconfdir}/%{name}.ini
exit 0

%make_install


%post
if [ "$1" = "1" ]
then
    chkconfig --add drms_analysis
fi


%files
%{_bindir}/%{name}
%{_sysconfdir}/init.d/%{name}
%config%{_sysconfdir}/%{name}.ini

%doc


%preun
if [ "$1" = "0" ]
then
    chkconfig --del drms_analysis
fi


%define __debug_install_post   \
%{_rpmconfigdir}/find-debuginfo.sh %{?_find_debuginfo_opts} "%{_builddir}/%{?buildsubdir}"\
%{nil}

%changelog


