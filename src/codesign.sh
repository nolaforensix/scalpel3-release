#!/bin/bash
make clean
make
sudo codesign --sign "scalpel3" -f --timestamp --options=runtime --entitlements ent.plist scalpel3
