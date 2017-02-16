# Catapult

Catapult lets you approximate messaging over sftp. Catapult has just three commands `list`, `puts`, `gets`. Of those, `gets` is the reason for catapult's existance.

## Usage

    catapult -keyfile ~/.ssh/id_rsa -passphrase ... user@server:port
    catapult -password ... user@server:port

## list

    list remotepath/[pattern]

`list` the files (or directories) in the remotepath that match the given pattern (default is all files)

## puts

    puts localpath/[pattern] remotepath donepath

`puts` uploads all the files in `localpath` (that match `pattern`) to the remote directory `remotepath`. After uploading each file is moved to `donepath`.

### Example puts useage

    puts ./outbox somedir ./sent

Messages you want to send are placed in `./outbox`. After `puts` has run `./sent` will contain all the uploaded messages. A follow up process then does what it needs (e.g. marks messages as sent in your database) and moves the messages to somewhere like `./archived/{todays date}`.

## gets

     gets remotepath localpath [, ...altpaths]

`gets` downloads all the files it finds at `remotepath` that are not in `localpath` or in any other local paths given as `altpaths`.


### Example gets useage

    gets results/*.asc ./inbox ./processed ./failed

Get will download files that match `results/*.asc` on the remote server into `./inbox` iff and only if they are not in any of `./inbox`, `./processed`, or `./failed`. A follow up job can then process all the matching files it finds in `./inbox` and move the files it has finished with into another directory (in this case `./processed` or `./failed`). This lets you decouple the dowload from the post processing without need a specific list of downloaded files or a mirror directory with fragile coupled (i.e. you get a list of newly downloaded files) postprocessing.


### Docker testing

    docker run -v host/share:/home/foo/share -v host/foo/_ssh/keys/id_rsa.pub:/home/foo/.ssh/keys/id_rsa.pub:ro -p 2222:22 -d atmoz/sftp foo:Paran01d:1001

Note, `host` folder needs to be in your home directory and is shared as `//c/Users/{username}/...` on Windows. Might also work if the path you are mounting is a windows share. Use a share /etc/sftp-users.conf to survive a restart (note must not have windows line endings)

    docker run -v //c/Users/bnorrington/Docker/foo/MRA01:/home/foo/MRA01 -v //c/Users/bnorrington/Docker/foo/outbound:/home/foo/outbound -v //c/Users/bnorrington/Docker/foo/_ssh/keys/id_rsa.pub:/home/foo/.ssh/keys/id_rsa.pub:ro v //c/Users/bnorrington/Docker/foo/users.conf:/etc/sftp-users.conf:ro -p 2222:22 -d atmoz/sftp