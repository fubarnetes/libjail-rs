#!/bin/sh

for target in $TARGET; do
	rustup target add $target
done
