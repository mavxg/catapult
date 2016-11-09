package main

import (
	//"byte"
	//"crypto/x509"
	"bufio"
	"fmt"
	"os"
	"regexp"
)

func main() {
	//TODO: read commands
	//catapult user@server:port --keyfile  --password --passphrase

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