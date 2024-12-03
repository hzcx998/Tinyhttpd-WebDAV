#!/bin/bash

# WebDAV server URL
#WEBDAV_URL="http://192.168.36.129/webdav/"
WEBDAV_URL="http://192.168.36.129:8080"
# WebDAV credentials
USERNAME="x"
PASSWORD="x"
CURL=/snap/bin/curl

# Usage function to display help for the script
usage() {
    echo "Usage: $0 <command> [options]"
    echo "Commands:"
    echo "  list           List directory contents"
    echo "  upload <file>  Upload a file to WebDAV"
    echo "  mkcol <dir>    Create a new collection (directory)"
    echo "  delete <path>  Delete a file or directory"
    echo "  download <path> <localfile>  Download a file from WebDAV"
    echo "  props <path>   Get properties of a file or directory"
    echo "  lock <path>    Lock a file"
    echo "  unlock <path> <token> Unlock a file"
    echo "  move <source> <destination> Move a file or directory"
    echo "  copy <source> <destination> Copy a file or directory"
    exit 1
}

# Check if any command is provided
if [ $# -lt 1 ]; then
    usage
fi

COMMAND=$1
shift  # Remove the command from the arguments list

case "$COMMAND" in
    list)
        FILE=$1
        $CURL -u $USERNAME:$PASSWORD -X PROPFIND "$WEBDAV_URL/$(basename "$FILE")" -H "Depth: 1"
        ;;
    upload)
        if [ $# -lt 1 ]; then
            echo "Error: No file specified for upload"
            exit 1
        fi
        FILE=$1
        $CURL -u $USERNAME:$PASSWORD -X PUT -T "$FILE" "$WEBDAV_URL/$(basename "$FILE")"
        ;;
    mkcol)
        if [ $# -lt 1 ]; then
            echo "Error: No directory specified for creation"
            exit 1
        fi
        DIR=$1
        $CURL -u $USERNAME:$PASSWORD -X MKCOL "$WEBDAV_URL/$DIR"
        ;;
    delete)
        if [ $# -lt 1 ]; then
            echo "Error: No path specified for deletion"
            exit 1
        fi
        PATH=$1
        $CURL -u $USERNAME:$PASSWORD -X DELETE "$WEBDAV_URL/$PATH"
        ;;
    download)
        if [ $# -lt 2 ]; then
            echo "Error: No path and local file specified for download"
            exit 1
        fi
        PATH=$1
        LOCALFILE=$2
        $CURL -u $USERNAME:$PASSWORD -X GET "$WEBDAV_URL/$PATH" -o "$LOCALFILE"
        ;;
    props)
        if [ $# -lt 1 ]; then
            echo "Error: No path specified for properties"
            exit 1
        fi
        PATH=$1
        $CURL -u $USERNAME:$PASSWORD -X PROPFIND $WEBDAV_URL"/$PATH" -H "Depth: 0"
        ;;
    lock)
        if [ $# -lt 1 ]; then
            echo "Error: No path specified for locking"
            exit 1
        fi
        PATH=$1
        $CURL -u $USERNAME:$PASSWORD -X LOCK -H "Content-Type: application/xml" -d "<lockinfo xmlns='DAV:'><lockscope><exclusive/></lockscope><locktype><write/></locktype></lockinfo>" "$WEBDAV_URL/$PATH"
        ;;
    unlock)
        if [ $# -lt 2 ]; then
            echo "Error: No path and lock token specified for unlocking"
            exit 1
        fi
        PATH=$1
        TOKEN=$2
        $CURL -u $USERNAME:$PASSWORD -X UNLOCK -H "Lock-Token: <$TOKEN>" "$WEBDAV_URL/$PATH"
        ;;
    move)
        if [ $# -lt 2 ]; then
            echo "Error: No source and destination specified for move"
            exit 1
        fi
        SOURCE=$1
        DESTINATION=$2
        $CURL -u $USERNAME:$PASSWORD -X MOVE -H "Destination: $WEBDAV_URL/$DESTINATION" "$WEBDAV_URL/$SOURCE"
        ;;
    copy)
        if [ $# -lt 2 ]; then
            echo "Error: No source and destination specified for copy"
            exit 1
        fi
        SOURCE=$1
        DESTINATION=$2
        $CURL -u $USERNAME:$PASSWORD -X COPY -H "Destination: $WEBDAV_URL/$DESTINATION" "$WEBDAV_URL/$SOURCE"
        ;;
    *)
        usage
        ;;
esac