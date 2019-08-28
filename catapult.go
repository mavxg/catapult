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
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
)

//catapult [-keyfile=... [-passphrase=..] | -password=.. ] user@server:port

var password string
var passphrase string
var keyfile string
var fingerprint string
var daemon bool
var restart string
var script string
var localDir string
var client *ssh.Client
var nice int

var gpgPassphrase string

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
		var full string
		if (strings.Contains(a, "*")) {
			full = strings.Replace(a, "*", name, 1)
		} else {
			a, _ = filepath.Abs(a)
			full = path.Join(a, name)
		}
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

	local, _ = filepath.Abs(local)

	err := os.MkdirAll(local, 0777)
	if err != nil {
		fmt.Fprintf(os.Stderr, "local (to) directory cannot be created: %q\n", local)
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
	first := true

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
			if (!first && nice > 0) {
				//Sleep for {nice} seconds for a slow server
				time.Sleep(time.Duration(nice) * time.Second)
			}
			first = false
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

func keyring(passphrase string) (openpgp.EntityList, error) {
	gpg_home := os.Getenv("GPG_HOME")
	if gpg_home == "" {
		gpg_home = path.Join(os.Getenv("HOME"), ".gnupg")
	}
	secretKeyringFile := path.Join(gpg_home, "secring.gpg")
	secretKeyringBuffer, err := os.Open(secretKeyringFile)
	if err != nil {
		return nil, err
	}
	defer secretKeyringBuffer.Close()

	secretKeyring, err := openpgp.ReadKeyRing(secretKeyringBuffer)
	if err != nil {
		return nil, err
	}

	publicKeyringFile := path.Join(gpg_home, "pubring.gpg")
	publicKeyringBuffer, err := os.Open(publicKeyringFile)
	if err != nil {
		return nil, err
	}
	defer publicKeyringBuffer.Close()

	keyring, err := openpgp.ReadKeyRing(publicKeyringBuffer)
	if err != nil {
		return nil, err
	}

	//loop over secret keyring and add all keys not encrypted or that we can decrypt with
	passphraseByte := []byte(passphrase)
	for _, entity := range secretKeyring {
		if entity.PrivateKey == nil {
			continue
		}
		if entity.PrivateKey.Encrypted {
			err = entity.PrivateKey.Decrypt(passphraseByte)
			if err != nil {
				continue
			}
			for _, subkey := range entity.Subkeys {
				if subkey.PrivateKey == nil {
					continue
				}
				err = subkey.PrivateKey.Decrypt(passphraseByte)
				if err != nil {
					continue
				}
			}
		}
		keyring = append(keyring, entity)
	}
	return keyring, nil
}

func keys(args []string) {
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "USAGE: keys [passphrase]")
		return
	}
	passphrase := gpgPassphrase
	if len(args) == 1 {
		passphrase = args[0]
	}
	keys, err := keyring(passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed open keyring: ", err)
	}
	for _, key := range keys {
		if key.PrivateKey != nil {
			fmt.Fprintln(os.Stderr, "PRIVATE KEY: ", key.PrivateKey.KeyIdShortString())
		} else if key.PrimaryKey != nil {
			fmt.Fprintln(os.Stderr, "PUBLIC KEY:  ", key.PrimaryKey.KeyIdShortString())
		}
		for _, subkey := range key.Subkeys {
			if subkey.PrivateKey != nil {
				fmt.Fprintln(os.Stderr, "    PRIVATE SUB KEY: ", subkey.PrivateKey.KeyIdShortString())
			} else if subkey.PublicKey != nil {
				fmt.Fprintln(os.Stderr, "    PUBLIC SUB KEY:  ", subkey.PublicKey.KeyIdShortString())
			}
		}
	}
}

func moveFile(src, dest string) error {
	err := copyFile(src, dest)
	if err != nil {
		return err
	}
	return os.Remove(src)
}

func decrypt(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "USAGE: decrypt src/[pattern] dest/[pattern]")
		return
	}
	entityList, err := keyring(gpgPassphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed open keyring: ", err)
	}

	frm, m := path.Split(args[0])
	target, tm := path.Split(args[1])

	if m == "" {
		m = "*"
	}

	if tm == "" {
		tm = "*"
	}

	rsl := len(m) - len(tm)

	if !strings.HasPrefix(m, tm) {
		fmt.Fprintln(os.Stderr, "dest pattern must be initial substring of src pattern")
		return
	}

	err = os.MkdirAll(target, 0777)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dest directory could not be created")
		return
	}

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
			dest := path.Join(target, name[:len(name)-rsl])

			f, err := os.Open(src)
			defer func() {
				if f != nil {
					f.Close()
				}
			}()

			var reader io.Reader
			block, err := armor.Decode(f)

			if err != nil {
				//not armored
				f.Seek(0,0)
				reader = f
			} else {
				reader = block.Body
			}


			md, err := openpgp.ReadMessage(reader, entityList, nil, nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to read encrypted message: ", src, err)
				continue
			}

			out, err := os.Create(dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to create dest file: ", dest, err)
				continue
			}
			defer out.Close()

			//NOTE: if the file was compressed we do not decompress it
			_, err = io.Copy(out, md.UnverifiedBody)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to create dest file: ", dest, err)
				continue
			}
			err = out.Sync()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed sync dest file: ", dest, err)
			}

			f.Close() //must close before we remove

			err = os.Remove(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed delete encrypted source file: ", src, err)
			}

			fmt.Printf("DECRYPTED: %s %s\n", src, dest)
		}
	}
}

func encrypt(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "USAGE: encrypt src/[pattern] dest to [from...]")
		fmt.Fprintln(os.Stderr, "    where *to* is the key id of recipient")
		fmt.Fprintln(os.Stderr, "    and *from...* are the signing key ids")
		return
	}
	_, err := keyring(gpgPassphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed open keyring: ", err)
	}
	fmt.Fprintf(os.Stderr, "encrypt not implemented\n")
}

func copyFile(src, dst string) error {
	src_file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer src_file.Close()

	dst_file, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dst_file.Close()
	_, err = io.Copy(dst_file, src_file)
	return err
}

func copy_(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "USAGE: copy src/[pattern] dest")
		return
	}
	frm, m := path.Split(args[0])
	target := args[1]

	if m == "" {
		m = "*"
	}

	err := os.MkdirAll(target, 0777)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dest directory could not be created")
		return
	}

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
			dest := path.Join(target, name)

			err = copyFile(src, dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to copy: ", src, err)
				continue //move on to next file
			}
		}
	}
}

func move(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "USAGE: move src/[pattern] dest")
		return
	}
	frm, m := path.Split(args[0])
	target := args[1]

	if m == "" {
		m = "*"
	}

	ls, err := os.Stat(target)
	if err != nil || !(ls.IsDir()) {
		fmt.Fprintln(os.Stderr, "dest directory doesn't exist")
		return
	}

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
			dest := path.Join(target, name)

			err = copyFile(src, dest)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to copy (move): ", src, err)
				continue //move on to next file
			}
			err = os.Remove(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed delete moved file: ", src)
			}
		}
	}
}

func delete_(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "USAGE: delete src/[pattern]")
		return
	}
	frm, m := path.Split(args[0])

	if m == "" {
		m = "*"
	}

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
			err = os.Remove(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed delete file: ", src)
			}
		}
	}
}

//Remove files that exist
func clean(conn *ssh.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "USAGE: clean remote_path/ local_processed_path/[pattern]")
		fmt.Fprintln(os.Stderr, "       processed path must end in a / or pattern")
		return
	}

	remote := args[0]
	local, m := path.Split(args[1])

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
	flag.StringVar(&keyfile, "keyfile", os.Getenv("CATAPULT_KEYFILE"), "keyfile path")
	flag.StringVar(&fingerprint, "fingerprint", os.Getenv("CATAPULT_FINGERPRINT"), "server fingerprint")
	flag.BoolVar(&daemon, "daemon", false, "daemon mode")
	flag.StringVar(&restart, "restart", os.Getenv("CATAPULT_RESTART"), "restart time (todo pattern)")
	flag.StringVar(&script, "script", os.Getenv("CATAPULT_SCRIPTFILE"), "command script")
	flag.StringVar(&localDir, "local", os.Getenv("CATAPULT_LOCAL_DIRECTORY"), "local directory")
	flag.StringVar(&gpgPassphrase, "gpg", os.Getenv("CATAPULT_GPG_PASSPHRASE"), "gpg key passphrase")
	flag.IntVar(&nice, "nice", 0, "seconds delay between put files for slow servers")
	//split strings with escape of \ for spaces in arguments
	splitEscSpace = regexp.MustCompile("(\\\\.|[^\\s])+")
}

func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func ParsePrivateKey(pemBytes []byte, passphrase string) (interface{}, error) {
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

func command(client *ssh.Client, config *ssh.ClientConfig, input string) {
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
	case "decrypt":
		decrypt(args[1:])
	case "encrypt":
		encrypt(args[1:])
	case "copy":
		copy_(args[1:])
	case "move":
		move(args[1:])
	case "delete":
		delete_(args[1:])
	case "open":
		if client == nil {
			open(config, args[1:])
		}
	case "keys":
		keys(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ERROR: Unknown command: %s", cmd)
	}
	return
}

func open(config *ssh.ClientConfig, args []string) {
	var err error

	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "USAGE: open username@host")
		return
	}

	connection := strings.SplitN(args[0], "@", 2)
	if len(connection) != 2 {
		usage()
		os.Exit(2)
	}
	username := connection[0]
	address := connection[1]

	hasPort, err := regexp.MatchString(".+:\\d+", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !hasPort {
		address = address + ":22"
	}

	config.User = username

	client, err = ssh.Dial("tcp", address, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect to server")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return
}

func CloseIfOpen() {
	if client != nil {
		client.Close()
	}
}

func main() {
	flag.Parse()

	if script != "" {
		script, _ = filepath.Abs(script)
	}

	if localDir != "" {
		os.Chdir(localDir)
	} else if script != "" {
		os.Chdir(filepath.Dir(script))
	}

	var err error
	var auths []ssh.AuthMethod

	privateKey := []byte(os.Getenv("CATAPULT_PRIVATEKEY"))

	//keyfile overrides an environment variable key
	if keyfile != "" {
		privateKey, err = ioutil.ReadFile(keyfile)
		if err != nil {
			panic(err)
		}
	}

	if len(privateKey) > 0 {
		key, err := ParsePrivateKey(privateKey, passphrase)
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
		//User: username,
		Auth:            auths,
		HostKeyCallback: CheckHostKey,
	}

	if flag.NArg() > 1 {
		usage()
		os.Exit(2)
	}

	if flag.NArg() == 1 {
		open(config, flag.Args())
	}
	defer CloseIfOpen()

	var reader io.Reader
	reader = os.Stdin
	if script != "" {
		src, err := os.Open(script)
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
		var restartRegex *regexp.Regexp
		var commands []string
		var restartTime time.Time
		restartRegex = regexp.MustCompile(`^(every) (\d+) (hours|mins|minutes)$`) 
		if (restartRegex.MatchString(restart)) {
			restartMatches := restartRegex.FindStringSubmatch(restart)
			restartMultiple,_ := strconv.Atoi(restartMatches[2])
			var restartDuration time.Duration
			switch restartMatches[3] {
			case "hours":
				restartDuration = time.Hour
			case "mins", "minutes":
				restartDuration = time.Minute
			}
			restartTime = (time.Now()).Add(restartDuration * time.Duration(restartMultiple))
		} else {
			//restart once per week even if no time is given
			restartTime = (time.Now()).Add(time.Hour * time.Duration(24*7))
		}

		for scanner.Scan() {
			commands = append(commands, scanner.Text())
		}
		if len(commands) < 1 {
			fmt.Fprintln(os.Stderr, "Command script empty")
			os.Exit(2)
		}
		for {
			for _, line := range commands {
				command(client, config, line)
				if ((time.Now()).After(restartTime)) {
					fmt.Fprintln(os.Stderr, "Restart time passed")
					os.Exit(0)
				}
			}
		}
	} else {
		for scanner.Scan() {
			input := scanner.Text()
			command(client, config, input)
		}
	}
}
