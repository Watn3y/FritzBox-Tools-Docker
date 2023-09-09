 ###!/usr/bin/env bash

read -p 'Tag?: ' tag

docker buildx build --push --platform linux/amd64,linux/arm64 --tag watn3y/fritzbox-tools:$(git log -1 --pretty=%h) --tag watn3y/fritzbox-tools:$tag --build-arg=COMMIT=$(git log -1 --pretty=%h) .

