package main

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"
	"github.com/karfield/ssh2go"
)

type ServerCallbacks struct{}
type ChannelCallbacks struct{}

var authenticated = false
var tryCount = 0
var channel *libssh.Channel

func (s *ServerCallbacks) OnAuthPassword(session libssh.Session, user, password string) int {
	fmt.Printf("auth user: %s, password: %s\n", user, password)
	if user == "test" && password == "test" {
		authenticated = true
		tryCount = 0
		return libssh.SSH_AUTH_SUCCESS
	}
	if tryCount >= 3 {
		session.Disconnect()
		return libssh.SSH_AUTH_DENIED
	}
	tryCount++
	return libssh.SSH_AUTH_DENIED
}

func (s *ServerCallbacks) OnSshAuthGssapiMic(session libssh.Session, user, principle string) int {
	fmt.Printf("auth GSSAPI with Mic, user: %s, principle %s\n", user, principle)
	_, err := session.GssapiGetCreds()
	if err == nil {
		return libssh.SSH_AUTH_SUCCESS
	}
	return libssh.SSH_AUTH_DENIED
}

func (s *ServerCallbacks) OnOpenChannel(session libssh.Session) libssh.Channel {
	fmt.Printf("on open channel\n")
	ch, _ := session.NewChannel()
	ch.SetCallbacks(&ChannelCallbacks{})
	channel = &ch
	return ch
}

func (c *ChannelCallbacks) OnChannelNewPty(session libssh.Session, channel libssh.Channel, term string, width, height, pxwidth, pwheight int) bool {
	fmt.Printf("client want to open a terminal: %s, %dx%d, pixel: %dx%d\n", term, width, height, pxwidth, pwheight)
	return true
}

func (c *ChannelCallbacks) OnChannelShellRequest(session libssh.Session, channel libssh.Channel) bool {
	fmt.Printf("shell has opended")
	return true
}

func fatal(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	cmdline := cli.NewApp()
	cmdline.Name = "ssh2go-sample-sshd"
	cmdline.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "port,p",
			Usage: "Set the port to bind.",
			Value: 2222,
		},
		cli.StringFlag{
			Name:  "hostkey,k",
			Usage: "Set the hostkey file path.",
		},
		cli.StringFlag{
			Name:  "dsakey,d",
			Usage: "Set the dsa key.",
		},
		cli.StringFlag{
			Name:  "rsakey,r",
			Usage: "Set the rsa key.",
		},
		cli.BoolFlag{
			Name:  "verbose,V",
			Usage: "Get verbose output.",
		},
	}
	cmdline.Action = func(ctx *cli.Context) {
		bind, err := libssh.NewBind()
		fatal(err)
		fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_DSAKEY, ctx.String("dsakey")))
		fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_RSAKEY, ctx.String("rsakey")))
		fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_BINDPORT, ctx.Int("port")))
		if hostkey := ctx.String("hostkey"); hostkey != "" {
			fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_HOSTKEY, hostkey))
		}
		if ctx.Bool("verbose") {
			fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_LOG_VERBOSITY, 3))
		}
		fatal(bind.Listen())
		session, err := libssh.NewSession()
		fatal(err)
		fatal(bind.Accept(session))
		callbacks := &ServerCallbacks{}
		session.SetServerCallbacks(callbacks)
		fatal(session.HandleKeyExchange())
		session.SetAuthMethods(libssh.SSH_AUTH_METHOD_PASSWORD | libssh.SSH_AUTH_METHOD_GSSAPI_MIC)
		mainLoop := libssh.NewEvent()
		mainLoop.AddSession(session)
		for {
			if authenticated {
				break
			}
			if err := mainLoop.Poll(-1); err != nil {
				fmt.Printf("session error: %s %d", session.GetErrorMsg(), session.GetErrorCode())
				session.Disconnect()
			}
		}
		for {
			ch := *channel
			data, err := ch.Read(2048, false)
			if err != nil {
				panic(err)
			}
			if len(data) > 0 {
				ch.Write(data)
			} else {
				break
			}
		}
		session.Disconnect()
		bind.Free()
	}
	cmdline.Run(os.Args)
}
