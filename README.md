#Zabbix Module - Xen Server Monitoring

***** THIS IS A POC *****

This is a module to monitoring with Zabbix a Xen Server.
Project started by Thiago Melo, Eduardo Stelmaszczyk and Alisson Oliveira from Unirede

For compile:
gcc zbx_xenserver.c -fPIC -shared -I [[ZABBIX_SOURCE]]/include -I /usr/include/libxml2 -I /usr/include/curl -lxml2 -lcurl -lxenserver -o zbx_xenserver.so
