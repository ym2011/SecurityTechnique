#!/bin/sh
[ $# -ne 1 ] && { 
 echo "Usage: sh check_server_linux.sh IP ";
 exit 1;
}

pathname=`pwd`


perl $pathname/check_server_linux.pl "${1}" 
