
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

If you have installed `libssh` but not the latest version in Mac OS, you should
reinstall it:

```
brew reinstall --HEAD https://raw.githubusercontent.com/karfield/ssh2go/master/libssh.rb
brew link --force libssh
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

# Examples

## simple-sshd

Custom a sshd, and run it locally, Try it:

```
go install github.com/karfield/ssh2go/examples/ssh2go-simple-sshd
```

see some options:

| option | shortcuts | default | description |
|---|---|---|---|
| port | p |2222|Set the port to bind.
| hostkey | k ||Set the hostkey file path.
| dsakey | d ||Set the dsa key.
| rsakey | r ||Set the rsa key.
| verbose |V ||Get verbose output.

run it:

```
ssh2go-simple-sshd --dsakey=/path/to/your/dsakey --rsakey=/path/to/your/rsakey --port 8888 -V
```

then open another terminal, run as a client:

```
ssh localhost -p 8888 -l test
```

Note:

granteed user and password: test / test

