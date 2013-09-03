@echo off
set CLASSPATH=.;dist/*;
java -Dnet.sf.odinms.recvops=recvops.properties -Dnet.sf.odinms.sendops=sendops.properties org.snow.maplesnowsniffer.Main sniffer
pause