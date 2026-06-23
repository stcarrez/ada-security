NAME=security
VERSION=1.6.0

DIST_DIR=ada-security-$(VERSION)
DIST_FILE=ada-security-$(VERSION).tar.gz

MAKE_ARGS += -XSECURITY_BUILD=$(BUILD)

-include Makefile.conf

UTIL_OS?=
UTIL_TIME_64?=yes

ifneq ($(UTIL_OS),)
MAKE_ARGS += -XUTIL_OS=$(UTIL_OS)
endif

ifneq ($(UTIL_TIME_64),yes)
MAKE_ARGS += -XUTIL_TIME_64=$(UTIL_TIME_64)
endif

STATIC_MAKE_ARGS = $(MAKE_ARGS) -XSECURITY_LIBRARY_TYPE=static
SHARED_MAKE_ARGS = $(MAKE_ARGS) -XSECURITY_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XUTILADA_BASE_BUILD=relocatable -XUTIL_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XXMLADA_BUILD=relocatable
SHARED_MAKE_ARGS += -XLIBRARY_TYPE=relocatable

include Makefile.defaults

build-test:: lib-setup
	cd regtests && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS) 

# Build and run the unit tests
test:	build
	bin/security_harness -l $(NAME): -xml security-aunit.xml

samples:
	cd samples && $(BUILD_COMMAND) $(GPRFLAGS) $(MAKE_ARGS)

SECURITY_DOC= \
  title.md \
  pagebreak.tex \
  index.md \
  pagebreak.tex \
  Installation.md \
  pagebreak.tex \
  Security.md \
  pagebreak.tex \
  Security_Auth.md \
  pagebreak.tex \
  Security_OAuth.md \
  pagebreak.tex \
  Security_Policies.md

DOC_OPTIONS=-f markdown --listings --number-sections --toc
HTML_OPTIONS=-f markdown --listings --number-sections --toc --css pandoc.css

$(eval $(call ada_library,$(NAME),.))
$(eval $(call pandoc_build,security-book,$(SECURITY_DOC)))
$(eval $(call alire_publish,.,se/security,security-$(VERSION).toml))

.PHONY: samples

setup::
	echo "UTIL_OS=$(UTIL_OS)" >> Makefile.conf
	echo "UTIL_TIME_64=$(UTIL_TIME_64)" >> Makefile.conf
