patchelf --set-rpath /usr/lib:/usr/local/lib smtp
patchelf --add-needed libglog.so.3 --add-needed libicudata.so.76 --add-needed libicui18n.so.76 --add-needed libicuuc.so.76 --add-needed libz.so.1 --add-needed libbz2.so.1.0 --add-needed liblzma.so.5 --add-needed libzstd.so.1 --add-needed libresolv.so.6662 --add-needed libboost_random.so.1.89.0 --add-needed libboost_atomic.so.1.89.0 --add-needed libboost_regex.so.1.89.0 smtp
DEPS=$(ldd smtp | awk '{ print $3 }' | grep --only-match --extended-regexp ".+/lib.*\\.so" )
TAR_ARGS="${DEPS//$'\n'/* }"
tar --xz --create --verbose --file smtp.tar.xz /etc/passwd /etc/group /etc/services /etc/pki/ /etc/ssl/ /usr/share/zoneinfo/ /lib smtp $TAR_ARGS
