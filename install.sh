#/bin/bash

#保证当前是root用户
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

#要求必要工具
grep -E -i "ubuntu|debian" /etc/issue >/dev/null && apt-get install gcc g++ make wget unzip
grep -i "centos" /etc/issue >/dev/null && yum -y install gcc gcc-c++ make wget unzip


#下载zlib:
cd /tmp
wget http://zlib.net/zlib-1.2.8.tar.gz
tar xzf zlib-1.2.8.tar.gz


#下载openssl:
cd /tmp
wget http://www.openssl.org/source/openssl-1.0.1e.tar.gz
tar xzf openssl-1.0.1e.tar.gz


#下载pcre:
cd /tmp
wget http://nchc.dl.sourceforge.net/project/pcre/pcre/8.32/pcre-8.32.zip
unzip pcre-8.32.zip


#安装openresty:
cd /tmp
wget http://openresty.org/download/ngx_openresty-1.2.8.3.tar.gz
tar xzf ngx_openresty-1.2.8.3.tar.gz
cd ngx_openresty-1.2.8.3
./configure --prefix=/usr/local --with-luajit  --with-pcre=/tmp/pcre-8.32 --with-openssl=/tmp/openssl-1.0.1e --with-zlib=/tmp/zlib-1.2.8
make install