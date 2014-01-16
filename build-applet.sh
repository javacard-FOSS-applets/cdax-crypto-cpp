#!/bin/bash

set -e

echo -n "> compiling applet class"
javac \
    -source 1.3 \
    -target 1.2  \
    -classpath JCKIT/lib/api.jar \
    applet/src/cdax/ClientApplet.java \
    -d applet/bin  \
    1> /dev/null
echo " ...done"

echo -n "> converted applet class to CAP file"
JCKIT/bin/converter \
    -out CAP \
    -exportpath JCKIT/api_export_files \
    -classdir applet/bin \
    -applet 0x00:0x00:0x00:0x00:0x00:0x42:0x01 \
    ClientApplet cdax 0x00:0x00:0x00:0x00:0x00:0x42 1.0 \
    1> /dev/null
echo " ...done"

echo -n "> deleted previous CAP file"
java \
    -d32 \
    -jar ../../apps/gpj/gpj.jar \
    -deletedeps -delete 000000000042  \
    1> /dev/null
echo " ...done"

echo -n "> uploadeding CAP file"
java \
    -d32 \
    -jar ../../apps/gpj/gpj.jar \
    -load applet/bin/cdax/javacard/cdax.cap \
    -install \
    1> /dev/null
echo " ...done"

if [ -f build/data/client-pub.key ]; then
    echo -n "> removing cached keys"
    rm build/data/client-pub.key
    echo " ...done"
fi

echo "> building and executing app"
cd build
make
./test
