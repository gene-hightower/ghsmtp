patchelf --set-rpath /usr/lib:/usr/local/lib smtp
patchelf --add-needed libboost_random.so.1.89.0 --add-needed libboost_atomic.so.1.89.0 --add-needed libboost_regex.so.1.89.0 smtp
DEPS=$(ldd smtp | awk '{ print $3 }' | grep --only-match --extended-regexp ".+/lib.*\\.so" )
TAR_ARGS="${DEPS//$'\n'/* }"
tar --xz --create --verbose --file smtp.tar.xz /etc/passwd /etc/group /etc/services /etc/pki/ /etc/ssl/ /usr/share/zoneinfo/ /lib smtp $TAR_ARGS
