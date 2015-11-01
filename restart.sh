#!/bin/sh

CDIR=$(cd $(dirname $0) && pwd)
cd $CDIR
git pull origin master
sudo supervisorctl reload



