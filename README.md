# Catapult

Catapult lets you approximate messaging over sftp. Catapult has just three commands `open`, `puts`, `gets`. Of those, `gets` is the reason for catapult's existance.

## open

    open {connection details}

`open` creates a connection with the remote sftp server you want to send or receive messages to/from.

## puts

    puts localpath remotepath donepath

`puts` uploads all the files it finds in `localpath` to the remote directory `remotepath`. After uploading each file it move that file to `donepath`.

### Example puts useage

    puts ./outbox somedir ./sent

Messages you want to send are placed in `./outbox`. After puts has run `./sent` will contain all the uploaded messages. A follow up process then does what it needs (e.g. marks messages as sent in your database) and moves the messages to somewhere like `./archived/{todays date}`.

## gets

     gets remotepath localpath [, ...altpaths]

`gets` downloads all the files it finds at `remotepath` that are not in `localpath` or in any other local paths given as `altpaths`.


### Example gets useage

    gets results/*.asc ./inbox ./processed ./failed

Get will download files that match `results/*.asc` on the remote server into `./inbox` iff and only if they are not in any of `./inbox`, `./processed`, or `./failed`. A follow up job can then process all the matching files it finds in `./inbox` and move the files it has finished with into another directory (in this case `./processed` or `./failed`). This lets you decouple the dowload from the post processing without need a specific list of downloaded files or a mirror directory with fragile coupled (i.e. you get a list of newly downloaded files) postprocessing.


### Docker testing

    docker run -v host/share:/home/foo/share -v host/foo/_ssh/keys/id_rsa.pub:/home/foo/.ssh/keys/id_rsa.pub:ro -p 2222:22 -d atmoz/sftp foo:Paran01d:1001

Note, `host` folder needs to be in your home directory and is shared as `//c/Users/{username}/...` on Windows. Might also work if the path you are mounting is a windows share. Use a share /etc/sftp-users.conf to survive a restart (note must not have windows line endings)

