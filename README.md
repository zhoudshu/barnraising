# barnraising

This Project is provided by Chris Lesniewski-Laas and M. Frans Kaashoek for reducing the bandwidth load on Web servers. the thesis is public and Demo Program is open source code. We can access [__thesis__](https://pdos.csail.mit.edu/papers/ssl-splitting-usenixsecurity03/) and download the [__Demo__](https://pdos.lcs.mit.edu/archive/barnraising/)

But both thesis and demo have not specific installed document. I had met a lot of problems, sometimes I had to modify the source code. After 3 weeks later, I finally install and run successfully. I wrote the process of installing to this file, and this git reposity is my modified and successful barnraising version.

## the demo component

* Cache Proxy
   * broker.pl: simple managed daemon
   * minion.pl: forward the user https request to webSite, get url content request from expander daemon and save content to local disk
   * Mysql database: record dns zone information
* WebSite
   * expander.pl: response minion request for url content request 
   * apache_1.3.23: the standard httpd program
   * OpenSSL0.9.6g: code at openssl directory in barnraising. In https handshake phase, It save url content to local disk 
   * domain and https certificate: I use my domain zhouds.cn to test

## the installed environment 

* Two physical Devices or VMs
* Cache Proxy: Linux OS is Centos5.8 + Kernel 2.6.18-308.el5 + Perl5.8.8 + Mysql 
* WebSite:     Linux OS is RHLr 8.0 + Kernel 2.4.18-14 + Perl5.8.0 + OpenSSL0.9.6 + Apache1.3.22

## Install Steps for Cache Proxy

### Step 1: Mysql Database
```bash
# yum install mysql-server.x86_64 mysql-devel
# service mysqld start
# mysql -uroot -p 
```
### Step 2: clone barnraising project 

```bash
# git clone https://github.com/zhoudshu/barnraising.git
# source barnraising/mydns.sql (at mysql command line)
# cpan install:
  Error
  Pod::Usage
  DBI
  DBD::mysql
  Digest::MD5
  Digest::SHA1
  Crypt::RC4
  Crypt::DES
  Crypt::DES_EDE3
  Crypt::CBC  ( whose tests depend on Crypt::Rijndael )
  Inline
  Inline::C
```

### Step 3: run perl script
```bash
# perl broker.pl 
# perl minion.pl https://zhouds.cn/manual/images/apache_pb.gif Cache ImpTLS (at another termination)
# 
```

## Install Steps for Website

### Step 1: cpan Error.pm
```bash
# cpan install Error
```
### Step 2: compile apache with OpenSSL0.9.6g
refer the article [__apache_ssl__](http://www.kozubik.com/docs/apache_ssl.txt)

```bash
# download apache_1.3.22 and mod_ssl-2.8.7-1.3.23
#./configure --with-ssl=../barnraising/openssl --with-apache=../apache_1.3.22 --prefix=/usr/local/apache-split
# make 
# make install
# cp ../barnraising/httpd.conf /usr/local/apache-split/conf/
# /usr/local/apache-split/bin/apachectl startssl
```

### Step 3: run perl script
```bash
# perl expander.pl 
# 
```

## Run and good luck
* configure A record of zhouds.cn to my Cache Proxy host
* https://zhouds.cn/index.html in chome or ie10+
