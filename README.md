## Zabbix Module - Xen Server Monitoring

*Is a module to monitoring with Zabbix a Xen Server.*

This project was started by our collaborators, when had an initiative of the: 
- Thiago Melo
- Alisson Oliveira ***[@alisson276](https://github.com/alisson276)***
- Eduardo Stelmaszczyk

### For Compile
```bash
gcc zbx_xenserver.c -fPIC -shared -I [[ZABBIX_SOURCE]]/include -I /usr/include/libxml2 -I /usr/include/curl -lxml2 -lcurl -lxenserver -o zbx_xenserver.so
```