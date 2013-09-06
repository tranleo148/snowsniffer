@echo off
set CLASSPATH=.;dist/*;
java -Djava.library.path=lib/64bit -Dnet.sf.odinms.recvops=recvops.properties -Dnet.sf.odinms.sendops=sendops.properties org.snow.maplesnowsniffer.ListDevices
pause