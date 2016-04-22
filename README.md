
# libssh to go

libssh is a mulitplatform C library implementing the SSHv2 and SSHv1 protocol on client and server side. With libssh, you can remotely execute programs, transfer files, use a secure and transparent tunnel, manage public keys and much more. [www.libssh.org](https://www.libssh.org)

ssh2go is Go bindings for libssh. The `master` branch follows the latest libssh [code](https://git.libssh.org/projects/libssh.git). 

# Installing

ssh2go depends on libssh, so make sure you've installed the **Lastest** git version of libssh

## For Mac OS (darwin)

### use homebrew

```
brew install --HEAD https://raw.githubusercontent.com/karfield/ssh2go/master/libssh.rb

go get github.com/karfield/ssh2go
```

## Build from scratch

If you want to build the libssh from scratch, use the './install-libs.sh' to install the prequisitements.

```
# download ssh2go, it will fails but okay.
go get github.com/karfield/ssh2go

cd $GOPATH/src/github.com/karfield/ssh2go

git submodule update --init --recursive

./install-libs.sh
```
