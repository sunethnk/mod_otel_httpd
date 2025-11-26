# Makefile for mod_otel_http Apache module
#
# Usage:
#   make                 # build mod_otel_http.so
#   sudo make install    # install and load module into httpd
#   make clean           # clean build artifacts
#
# Override APXS if needed:
#   make APXS=apxs2
#
# Override CURL_LIBS if curl lives in a non-standard path:
#   make CURL_LIBS="-L/opt/curl/lib -lcurl"

APXS        ?= apxs
APACHECTL   ?= apachectl
MODULE_NAME  = mod_otel_http
SRC          = $(MODULE_NAME).c

# Linker flags for curl
CURL_LIBS   ?= -lcurl

all: $(MODULE_NAME).so

$(MODULE_NAME).so: $(SRC)
	$(APXS) -c \
	    -Wc,"-Wall -O2" \
	    -Wl,"$(CURL_LIBS)" \
	    $(SRC)

install: $(MODULE_NAME).so
	# Install the module and add a LoadModule line to httpd.conf
	$(APXS) -i -a $(MODULE_NAME).la

reload:
	$(APACHECTL) -k graceful || $(APACHECTL) -k restart

clean:
	rm -f *.o *.lo *.la *.slo *.so
	rm -rf .libs

.PHONY: all install clean reload
