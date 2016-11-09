package main

import (
	//"byte"
	//"crypto/x509"
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"golang.org/x/crypto/ssh"
)

//catapult [-keyfile=... [-passphrase=..] | -password=.. ] user@server:port

var client *ssh.Client
var password string
var passphrase string
var keyfile string

func usage() {
	fmt.Fprintf(os.Stderr,"catapult <flags> user@server:port\n")
	fmt.Fprintln(os.Stderr,"")
	fmt.Fprintln(os.Stderr,"Note: flags must come before connection string")
}

func init() {
	flag.StringVar(&password, "password", "", "password for sftp connection")
	flag.StringVar(&passphrase, "passphrase", "", "passphrase for keyfile")
	flag.StringVar(&keyfile, "keyfile", "", "keyfile path")
}

func main() {
	flag.Parse()

	if (flag.NArg() != 1) {
		usage()
		os.Exit(2)
	}

	connection := strings.SplitN(flag.Arg(0), "@", 2)
	if (len(connection) != 2) {
		usage()
		os.Exit(2)
	}
	username := connection[0]
	address := connection[1]

	config := &ssh.ClientConfig{
		User: username,
	}

	if keyfile != "" {
		config.Auth = []ssh.AuthMethod{ ssh.Password(password) }
	} else if password != "" {
		config.Auth = []ssh.AuthMethod{ ssh.Password(password) }
	} else {
		fmt.Fprintln(os.Stderr, "Need password or keyfile")
	}

	hasPort, err := regexp.MatchString(".+:\\d+", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !hasPort {
		address = address + ":22"
	}

	fmt.Println(username, address)

	client, err = ssh.Dial("tcp", address, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect to server")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	//split strings with escape of \ for spaces in arguments
	r := regexp.MustCompile("(\\\\.|[^\\s])+")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := scanner.Text()
		//TODO: read gets and puts commands here
		args := r.FindAllString(input, -1)
		switch cmd := args[0]; cmd {
		case "gets":
			//gets remotedir localdir otherdirs
			fmt.Println("Doing a gets command")
		case "puts":
			//puts localdir remotedir local_sent_dir
			fmt.Println("Doing a puts command")
		case "list":
			//list remotedir
			fmt.Println("Doing a list command")
		default:
			fmt.Println("Unknown command: %s", cmd)
		}
	}
}