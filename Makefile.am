SUBDIRS = src packet
dist_doc_DATA = README
EXTRA_DIST = debian ruijieclient.spec

rpm: dist-bzip2
	mkdir -p ~/rpmbuild/SOURCES/
	mv ruijieclient-*.tar.bz2 ~/rpmbuild/SOURCES/
	if [ "" = "$(TARGET)" ] ;then \
	rpmbuild -bb $(top_srcdir)/ruijieclient.spec ; \
	else rpmbuild -bb $(top_srcdir)/ruijieclient.spec --target=$(TARGET) ; fi
	
	
	mv ~/rpmbuild/RPMS/*$(TARGET)/ruijieclient-*$(TARGET).rpm ./
	rm ~/rpmbuild/SOURCES/ruijieclient*
	