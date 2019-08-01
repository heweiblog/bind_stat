
ifeq ($(origin PYENV_ROOT), undefined)
$(error `pyenv` is required for the Target.)
endif

PYVER := $(lastword $(shell python --version 2>&1))
APPVER := $(strip $(shell cat version))
GITBRANCH := $(strip $(shell git rev-parse --abbrev-ref HEAD))
GITCOMMIT := $(strip $(shell git rev-parse --short HEAD))

all: build

rpm: build
	mkdir -p drms_analysis-$(APPVER)/bin drms_analysis-$(APPVER)/etc drms_analysis-$(APPVER)/etc/init.d
	cp dist/drms_analysis drms_analysis-$(APPVER)/bin
	cp drms_analysis.py drms_analysis-$(APPVER)
	cp -r etc drms_analysis-$(APPVER)
	tar cvzf ~/rpmbuild/SOURCES/drms_analysis-$(APPVER).tar.gz drms_analysis-$(APPVER)
	rpmbuild -bb --define "DRMSVER $(APPVER)" --define "GITBRANCH $(GITBRANCH)" --define "GITCOMMIT $(GITCOMMIT)" drms.spec
	rm -rf drms_analysis-$(APPVER)

TGT=drms_analysis
rpmclean:	
	rm -rf build dist
	rm -rf drms_analysis-$(APPVER)
	rm -rf __pycache__
	cp -r ~/rpmbuild/RPMS/x86_64/$(TGT)*$(APPVER)* ./  
	rm -rf ~/rpmbuild/SOURCES/$(TGT)* \
	~/rpmbuild/BUILD/$(TGT)* \
	~/rpmbuild/RPMS/x86_64/$(TGT)* \
	~/rpmbuild/SPEC/$(TGT)* 

build: dist/drms_analysis

dist/drms_analysis: distclean
	env LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(PYENV_ROOT)/versions/$(PYVER)/lib/ pyinstaller --onefile pyinst-drms.spec

.PHONY: distclean clean

distclean:
	rm -rf build dist
	rm -rf drms_analysis-$(APPVER)
	rm -rf __pycache__

clean:
	rm -rf build dist
	rm -rf drms_analysis-$(APPVER)
	rm -rf __pycache__
