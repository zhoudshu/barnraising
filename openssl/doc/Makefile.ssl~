VERSION =

#PODS = $(wildcard *.pod)
#MANS = $(addsuffix .man, $(basename $(PODS)))

MANS = openssl.1 ssl.3 crypto.3

P2M = pod2man --center='OpenSSL Documentation' --release="OpenSSL $(VERSION)"

all: manpages

.PHONY: manpages 

manpages: openssl.1 crypto.3 ssl.3

openssl.1:
	$(P2M) --section=1 openssl.pod > openssl.1

crypto.3:
	$(P2M) --section=3 crypto.pod > crypto.3

ssl.3:
	$(P2M) --section=3 ssl.pod > ssl.3

.PHONY: install
install:
	mkdir -p $(INSTALL_PREFIX)$(INSTALLTOP)/share/man/man1
	mkdir -p $(INSTALL_PREFIX)$(INSTALLTOP)/share/man/man3
	install -m 644 -p openssl.1 $(INSTALL_PREFIX)$(INSTALLTOP)/share/man/man1
	install -m 644 -p crypto.3 $(INSTALL_PREFIX)$(INSTALLTOP)/share/man/man3
	install -m 644 -p ssl.3 $(INSTALL_PREFIX)$(INSTALLTOP)/share/man/man3
	rm -f $(MANS)

.PHONY: clean
clean:
	rm -f $(MANS)

.PHONY: realclean
realclean:
	-$(MAKE) clean
