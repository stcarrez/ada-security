NAME=security
VERSION=1.5.1

DIST_DIR=ada-security-$(VERSION)
DIST_FILE=ada-security-$(VERSION).tar.gz

MAKE_ARGS += -XSECURITY_BUILD=$(BUILD)
PANDOC := $(shell which pandoc)
DYNAMO := $(shell which dynamo)

-include Makefile.conf

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
$(eval $(call alire_publish,alire.toml,se/security,security-$(VERSION).toml))

.PHONY: samples
