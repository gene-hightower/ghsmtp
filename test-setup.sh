export MAILDIR=/tmp/Maildir

export GLOG_log_dir=/tmp/Maillogs
export GLOG_minloglevel=3

mkdir -p ${MAILDIR}/{tmp,new,cur}
mkdir -p ${GLOG_log_dir}
