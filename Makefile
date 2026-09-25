export THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

# The root project has no control file of its own, so it cannot produce a .deb.
# Each subproject is a self-contained package; this target builds both.
.PHONY: all-packages
all-packages:
	$(MAKE) -C sb package
	$(MAKE) -C pref package
