#
# Top-level makefile for Barnraising distribution.
#

GCP = gcp

DIST_FILES = COPYING NOTES TODO VERSION Makefile broker.pl expander.pl minion.pl
DIST_DIRS = Barnraising Mimic MyDNS TLS openssl


dist:
	rm -rf dist-dir
	mkdir dist-dir
	$(GCP) -a $(DIST_FILES) $(DIST_DIRS) dist-dir/
	( cd dist-dir/openssl/ ; tar xf ../../openssl-symlinks.tar )
	find dist-dir/ -name CVS -print | xargs rm -rf
	dest=barnraising-`cat VERSION` ; rm -rf ../$$dest ; mv dist-dir ../$$dest ; ( cd .. ; tar cvf - $$dest | gzip -c > $$dest.tar.gz ) ; rm -rf ../$$dest
