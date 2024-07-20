#!/bin/sh

# one time only:
# sudo groupadd docker
# sudo usermod -aG docker $USER
# sudo reboot
# docker build -t clang-format-lint github.com/DoozyX/clang-format-lint-action

# Run from the root of the project (./scripts/lint.sh)
docker run -it --rm --workdir /upnp -v $(pwd):/upnp clang-format-lint \
    --clang-format-executable /clang-format/clang-format17 -r --exclude .git .