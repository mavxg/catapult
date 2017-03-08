package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"net"
	"time"
	"strconv"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

//catapult [-keyfile=... [-passphrase=..] | -password=.. ] user@server:port

var password string
var passphrase string
var keyfile string
var fingerprint string
var daemon bool
var script string

var splitEscSpace *regexp.Regexp

func usage() {
	fmt.Fprintf(os.Stderr, "catapult <flags> user@server:port\n")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Note: flags must come before connection string")
}

func list(conn *ssh.Client, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "USAGE: list dir/[pattern]")
		return
	}

	p, m := path.Split(args[0])

	if m == "" {
		m = "*"
	}

	c, err := sftp.NewClient(conn)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	files, err := c.ReadDir(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for _, file := range files {
		name := file.Name()
		matched, _ := path.Match(m, name)
		if matched {
			fmt.Println(path.Join(p, name))
		}
	}
}

func get(client *sftp.Client, src string, dest string) error {
	srcFile, err := client.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest) //note, will truncate existing
	if err != nil {
		return err
	}
	defer destFile.Close()

	bytes, err := srcFile.WriteTo(destFile)
	if err != nil {
		return err
	}

	fmt.Printf("GET: %s %s %dbytes\n", src, dest, bytes)
	return nil
}

func exists(name string, alts []string) (bool, error) {
	for _, a := range alts {
		full := path.Join(a, name)
		_, err := os.Stat(full)
		if !(os.IsNotExist(err)) {
			return true, err
		}
	}
	return false, nil
}

func gets(conn *ssh.Client, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "USAGE: gets from/[pattern] to [alts]")
		fmt.Fprintln(os.Stderr, "       note that from must end in a / unless it has a match pattern")
		return
	}

	frm, m := path.Split(args[0])
	local := args[1]
	alts := args[1:] //include local in this to simplify logic

	ls, err := os.Stat(local)
	if err != nil || !(ls.IsDir()) {
		fmt.Fprintln(os.Stderr, "local (to) directory doesn't exist")
		return
	}

	if m == "" {
		m = "*"
	}

	c, err := sftp.NewClient(conn)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	files, err := c.ReadDir(frm)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for _, file := range files {
		name := file.Name()
		matched, _ := path.Match(m, name)
		if matched {
			done, err := exists(name, alts)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to check existence: ", name, err)
				continue //move on to next file
			}
			if done {
				//already have this file
				continue
			}
			src := path.Join(frm, name)
			dest := path.Join(local, name)
			err = get(c, src, dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed get the file: ", name)
			}
		}
	}
}

func put(client *sftp.Client, src string, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := client.Create(dest) //note, will truncate existing
	if err != nil {
		return err
	}
	defer destFile.Close()

	bytes, err := io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	fmt.Printf("PUT: %s %s %dbytes\n", src, dest, bytes)
	return nil
}

func puts(conn *ssh.Client, args []string) {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "USAGE: puts outbox/[pattern] to sentbox")
		fmt.Fprintln(os.Stderr, "       note that outbox must end in a / unless it has a match pattern")
		return
	}

	frm, m := path.Split(args[0])
	remote := args[1]
	sent := args[2]

	if m == "" {
		m = "*"
	}

	ls, err := os.Stat(sent)
	if err != nil || !(ls.IsDir()) {
		fmt.Fprintln(os.Stderr, "sentbox directory doesn't exist")
		return
	}

	c, err := sftp.NewClient(conn)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	files, err := ioutil.ReadDir(frm)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for _, file := range files {
		name := file.Name()
		matched, _ := path.Match(m, name)
		if matched {
			src := path.Join(frm, name)
			dest := path.Join(remote, name)
			archive := path.Join(sent, name)
			err = put(c, src, dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to send: ", name, err)
				continue //move on to next file
			}
			err = os.Rename(src, archive)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to move file to sent: ", name)
			}
		}
	}
}

func sleep(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "USAGE: sleep seconds")
		return
	}
	seconds, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "USAGE: sleep seconds -- seconds must be a number")
		return
	}
	time.Sleep(time.Duration(seconds) * time.Second)
}

//Remove files that exist 
func clean(conn *ssh.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "USAGE: clean remote_path/ local_processed_path/[pattern]")
		fmt.Fprintln(os.Stderr, "       processed path must end in a / or pattern")
		return
	}

	remote := args[0]
	local,m := path.Split(args[1])

	if m == "" {
		m = "*"
	}

	ls, err := os.Stat(local)
	if err != nil || !(ls.IsDir()) {
		fmt.Fprintln(os.Stderr, "processed directory doesn't exist")
		return
	}

	c, err := sftp.NewClient(conn)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	files, err := ioutil.ReadDir(local)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for _, file := range files {
		name := file.Name()
		matched, _ := path.Match(m, name)
		if matched {
			src := path.Join(local, name)
			dest := path.Join(remote, name)
			err = c.Remove(dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to remove remote file: ", dest, err)
				continue //move on to next file ??? Do we want to remove processed
			}
			err = os.Remove(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to remove local file: ", src, err)
			}
		}
	}
}

func init() {
	flag.StringVar(&password, "password", os.Getenv("CATAPULT_PASSWORD"), "password for sftp connection")
	flag.StringVar(&passphrase, "passphrase", os.Getenv("CATAPULT_PASSPHRASE"), "passphrase for keyfile")
	flag.StringVar(&keyfile, "keyfile", os.Getenv("CATAPULT_PASSPHRASE"), "keyfile path")
	flag.StringVar(&fingerprint, "fingerprint", os.Getenv("CATAPULT_FINGERPRINT"), "server fingerprint")
	flag.BoolVar(&daemon, "daemon", false, "daemon mode")
	flag.StringVar(&script, "script", os.Getenv("CATAPULT_SCRIPTFILE"), "command script")

	//split strings with escape of \ for spaces in arguments
	splitEscSpace = regexp.MustCompile("(\\\\.|[^\\s])+")
}

func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func ParsePrivateKey(file string, passphrase string) (interface{}, error) {
	pemBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found in keyfile")
	}

	if encryptedBlock(block) {
		bytes, err := x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil || bytes == nil {
			return nil, errors.New("ssh: could not decrypt keyfile")
		}

		key, err := x509.ParsePKCS8PrivateKey(bytes)
		if err == nil {
			return key, nil
		}

		key, err = x509.ParsePKCS1PrivateKey(bytes)
		if err == nil {
			return key, nil
		}

		return nil, errors.New("ssh: key decryption failed")

	}

	return ssh.ParseRawPrivateKey(pemBytes)
}

// CheckHostKey checks a host key certificate. This method can be
// plugged into ClientConfig.HostKeyCallback.
func CheckHostKey(addr string, remote net.Addr, key ssh.PublicKey) error {
	hostkey := fmt.Sprintf("%s %s", key.Type(), ssh.FingerprintSHA256(key))
	if fingerprint == "" {
		fmt.Fprintf(os.Stderr, "INFO: Server host key: %q\n", hostkey)
	} else if fingerprint != hostkey {
		fmt.Fprintf(os.Stderr, "ERROR: Server host key: %q doesn't match fingerprint\n       given:           %q\n", hostkey, fingerprint)
		return errors.New("Server key doesn't match")
	}
	return nil
}

func command(client *ssh.Client, input string) {
		args := splitEscSpace.FindAllString(input, -1)
		switch cmd := args[0]; cmd {
		case "gets":
			gets(client, args[1:])
		case "puts":
			puts(client, args[1:])
		case "list":
			list(client, args[1:])
		case "clean":
			clean(client, args[1:])
		case "sleep":
			sleep(args[1:])
		default:
			fmt.Println("Unknown command: %s", cmd)
		}
		return
}

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	connection := strings.SplitN(flag.Arg(0), "@", 2)
	if len(connection) != 2 {
		usage()
		os.Exit(2)
	}
	username := connection[0]
	address := connection[1]

	var auths []ssh.AuthMethod

	if keyfile != "" {
		key, err := ParsePrivateKey(keyfile, passphrase)
		if err != nil {
			panic(err)
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			panic(err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	if password != "" {
		auths = append(auths, ssh.Password(password))
	}

	if password == "" && keyfile == "" {
		fmt.Fprintln(os.Stderr, "Need password or keyfile")
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: auths,
		HostKeyCallback: CheckHostKey,
	}

	hasPort, err := regexp.MatchString(".+:\\d+", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !hasPort {
		address = address + ":22"
	}

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect to server")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer client.Close()

	var reader io.Reader
	reader = os.Stdin
	if script != "" {
		absPath, _ := filepath.Abs(script)
		src, err := os.Open(absPath)
		defer src.Close()
		reader = src
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to open script file")
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else if daemon {
		reader = strings.NewReader(os.Getenv("CATAPULT_DAEMON_SCRIPT"))
	}

	scanner := bufio.NewScanner(reader)
	if daemon {
		var commands []string
		for scanner.Scan() {
			commands = append(commands, scanner.Text())
		}
		if len(commands) < 1 {
			fmt.Fprintln(os.Stderr, "Command script empty")
			os.Exit(2)
		}
		for {
			for _, line := range commands {
				command(client, line)
			}
		}
	} else {
		for scanner.Scan() {
			input := scanner.Text()
			command(client, input)
		}
	}
}
