# owasp-oshp-wasm
https://owasp.org/www-project-secure-headers/



```sh
sudo dnf install tinygo
sudo dnf groupinstall "Development Tools"
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
(echo; echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"') >> /home/tbox/.bashrc
    eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
brew install binaryen

sudo yum install yum-utils
sudo rpm --import 'https://rpm.dl.getenvoy.io/public/gpg.CF716AF503183491.key'
curl -sL 'https://rpm.dl.getenvoy.io/public/config.rpm.txt?distro=el&codename=7' > /tmp/tetrate-getenvoy-rpm-stable.repo
sudo yum-config-manager --add-repo '/tmp/tetrate-getenvoy-rpm-stable.repo'
sudo yum makecache --disablerepo='*' --enablerepo='tetrate-getenvoy-rpm-stable'
sudo yum install getenvoy-envoy


# curl https://func-e.io/install.sh | sudo bash -s -- -b /usr/local/bin
# func-e run -c ./examples/http_headers/envoy.yaml


make build.example name=http_headers
make run name=http_headers

curl -i localhost:18000

ref=quay.io/trevorbox/owasp-headers-wasm:latest
buildah bud -f examples/wasm-image.Dockerfile --build-arg WASM_BINARY_PATH=./examples/http_headers/main.wasm -t $ref .
buildah push $ref


```
