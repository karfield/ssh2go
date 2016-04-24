package main

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"
	"github.com/karfield/ssh2go"
)

func main() {
	cmdline := cli.NewApp()
	cmdline.Name = "ssh2go-multi-sshd"
	cmdline.Usage = "Example SSHD supports multiple connections"
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
		cli.StringFlag{
			Name:  "ecdsakey,e",
			Usage: "Set the ecdsa key.",
		},
		cli.BoolFlag{
			Name:  "verbose,V",
			Usage: "Get verbose output.",
		},
	}
	cmdline.Action = run_server
	cmdline.Run(os.Args)
}

func fatal(err error) {
	if err != nil {
		panic(err)
	}
}

func run_server(ctx *cli.Context) {
	fatal(libssh.Init())
	bind, err := libssh.NewBind()
	fatal(err)
	defer bind.Free()

	fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_DSAKEY, ctx.String("dsakey")))
	fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_RSAKEY, ctx.String("rsakey")))
	fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_BINDPORT, ctx.Int("port")))
	fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_ECDSAKEY, ctx.String("ecdsakey")))
	if hostkey := ctx.String("hostkey"); hostkey != "" {
		fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_HOSTKEY, hostkey))
	}
	if ctx.Bool("verbose") {
		fatal(bind.SetOption(libssh.SSH_BIND_OPTIONS_LOG_VERBOSITY, 3))
	}

	for {
		fatal(bind.Listen())
		session, err := libssh.NewSession()
		fatal(err)
		fatal(bind.Accept(session))
		go handleClientConnection(session)
	}
}

func handleClientConnection(session libssh.Session) {
	fmt.Println("new connection!")

	defer session.Disconnect()
	eventLoop, err := libssh.NewEvent()
	if err != nil {
		fmt.Println("unable to create event loop")
		return
	}
	defer eventLoop.Free()

	var (
		channel       libssh.Channel
		authenticated = false
		tryCount      = 0
	)

	channelCallbacks := libssh.ChannelCallbacks{
		OnChannelNewPty: func(session libssh.Session, channel libssh.Channel, term string, width, height, pxwidth, pwheight int) bool {
			fmt.Printf("client want to open a terminal: %s, %dx%d, pixel: %dx%d\n", term, width, height, pxwidth, pwheight)
			return true
		},
		OnChannelShellRequest: func(session libssh.Session, channel libssh.Channel) bool {
			fmt.Printf("shell has opended\n")
			return true
		},
		OnChannelExecRequest: func(session libssh.Session, channel libssh.Channel, cmdline string) bool {
			fmt.Printf("exec cmd: %s\n", cmdline)
			return true
		},
		OnChannelSubSystemRequest: func(session libssh.Session, channel libssh.Channel, subsystem string) bool {
			fmt.Printf("request sub system: %s\n", subsystem)
			return true
		},
	}

	serverCallbacks := libssh.ServerCallbacks{
		OnAuthPassword: func(session libssh.Session, user, password string) int {
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
		},
		OnOpenChannel: func(session libssh.Session) (libssh.Channel, error) {
			fmt.Printf("on open channel\n")
			ch, _ := session.NewChannel()
			if err := ch.SetCallbacks(&channelCallbacks); err != nil {
				return ch, err
			}
			channel = ch
			return ch, nil
		},
	}

	if err = session.SetServerCallbacks(&serverCallbacks); err != nil {
		fmt.Println("fails to set server callbacks")
		return
	}
	if err = session.HandleKeyExchange(); err != nil {
		fmt.Println("fails to set key exchange")
		return
	}
	session.SetAuthMethods(libssh.SSH_AUTH_METHOD_PASSWORD)

	if err = eventLoop.AddSession(session); err != nil {
		fmt.Println("unable to add session to event loop")
		return
	}
	defer eventLoop.RemoveSession(session)

	// authenticating phase
	for !authenticated || !channel.IsCreated() {
		if err := eventLoop.Poll(3 * 60 * 1000); err != nil {
			fmt.Println("authenticating timeout (3 min) or password error")
			return
		}
	}

	fmt.Println("start conversation")

	// conversation
	for {
		data, err := channel.Read(2048, false)
		if err != nil {
			return
		}
		if len(data) > 0 {
			channel.Write(data)
		}
	}
}
