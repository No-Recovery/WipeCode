export THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

# The root project has no control file of its own, so it cannot produce a .deb.
# The single subproject is a self-contained package.
.PHONY: all-packages
all-packages:
	$(MAKE) -C wipecode package
