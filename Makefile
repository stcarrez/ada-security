NAME=security

GPRPATH=$(NAME).gpr

-include Makefile.conf

STATIC_MAKE_ARGS = $(MAKE_ARGS) -XSECURITY_LIBRARY_TYPE=static
SHARED_MAKE_ARGS = $(MAKE_ARGS) -XSECURITY_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XUTILADA_BASE_BUILD=relocatable -XUTIL_LIBRARY_TYPE=relocatable
SHARED_MAKE_ARGS += -XXMLADA_BUILD=relocatable
SHARED_MAKE_ARGS += -XLIBRARY_TYPE=relocatable

include Makefile.defaults

build-test:: setup
	$(GNATMAKE) $(GPRFLAGS) -p -Psecurity_tests $(MAKE_ARGS) 

# Build and run the unit tests
test:	build-test
	bin/security_harness -xml security-aunit.xml

ifeq (${HAVE_PANDOC},yes)
ifeq (${HAVE_DYNAMO},yes)
doc:  docs/security-book.pdf docs/security-book.html
	$(DYNAMO) build-doc -markdown wiki

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

DOC_OPTIONS=-f markdown -o security-book.pdf --listings --number-sections --toc
HTML_OPTIONS=-f markdown -o security-book.html --listings --number-sections --toc --css pandoc.css

docs/security-book.pdf:  force
	$(DYNAMO) build-doc -pandoc docs
	cd docs && pandoc $(DOC_OPTIONS) --template=./eisvogel.tex $(SECURITY_DOC)

docs/security-book.html: docs/security-book.pdf force
	cd docs && pandoc $(HTML_OPTIONS) $(SECURITY_DOC)
endif
endif


$(eval $(call ada_library,$(NAME)))
