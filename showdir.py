#!/usr/bin/env python3

import cgi
import cgitb
import os
from datetime import datetime
from urllib.parse import quote
import socket

# Enable CGI error reporting
cgitb.enable()

# Define the directory to list
form = cgi.FieldStorage()
prefix = form.getvalue("prefix", "htdocs")
url = form.getvalue("url", "/")
directory = prefix + "/" + url

# Print the HTTP header
print("Content-Type: text/html; charset=UTF-8")
print()

# Start the HTML document
print("<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 3.2 Final//EN'>")
print("<html>")
print("    <head>")
print(f"        <title>Index of {url}</title>")
print("        <meta charset='UTF-8'>")
print("    </head>")
print("    <body>")
print(f"        <h1>Index of {url}</h1>")
print("        <table>")

# Print the table headers
print("            <tr>")
print("                <th valign='top'>")
print("                    <img src='/icons/blank.gif' alt='[ICO]'>")
print("                </th>")
print("                <th><a href='?C=N;O=D'>Name</a></th>")
print("                <th><a href='?C=M;O=A'>Last modified</a></th>")
print("                <th><a href='?C=S;O=A'>Size</a></th>")
print("                <th><a href='?C=D;O=A'>Description</a></th>")
print("            </tr>")
print("            <tr>")
print("                <th colspan='5'><hr></th>")
print("            </tr>")

if len(url) > 1:
    url = url.rstrip('/')

url_parent = os.path.dirname(url)
# Print the parent directory link
print("            <tr>")
print("                <td valign='top'>")
print("                    <img src='/icons/back.gif' alt='[PARENTDIR]'>")
print("                </td>")
print(f"                <td><a href='{url_parent}'>Parent Directory</a></td>")
print("                <td>&nbsp;</td>")
print("                <td align='right'>- </td>")
print("                <td>&nbsp;</td>")
print("            </tr>")

# Get the list of files and directories
files = os.listdir(directory)

# Function to get the icon based on file extension
def get_icon(filename):
    if os.path.isdir(filename):
        return '/icons/folder.gif'
    ext = os.path.splitext(filename)[1].lower()
    if ext in ['.txt', '.doc', '.docx']:
        return '/icons/text.gif'
    elif ext in ['.pdf']:
        return '/icons/pdf.gif'
    elif ext in ['.jpg', '.jpeg', '.png', '.gif']:
        return '/icons/image.gif'
    # Add more file types and their corresponding icons as needed
    return '/icons/unknown.gif'

# Print each file and directory in the listing
for filename in files:
    filepath = os.path.join(directory, filename)
    filestats = os.stat(filepath)
    last_modified = datetime.fromtimestamp(filestats.st_mtime).strftime('%Y-%m-%d %H:%M')
    size = filestats.st_size

    print("            <tr>")
    print("                <td valign='top'>")
    icon = get_icon(filepath)
    print(f"                    <img src='{icon}' alt='[FILE]'>")
    if os.path.isdir(filepath):
        # 使用绝对路径和URL编码，确保目录链接正确
        print(f"                <td><a href='{filename}/'>{filename}/</a></td>")
    else:
        print(f"                <td><a href='{filename}'>{filename}</a></td>")
    print(f"                <td align='right'>{last_modified}</td>")
    if os.path.isdir(filepath):
        print("                <td align='right'>- </td>")
    else:
        print(f"                <td align='right'>{size}</td>")
    print("                <td>&nbsp;</td>")
    print("            </tr>")

# Print the footer
print("            <tr>")
print("                <th colspan='5'><hr></th>")
print("            </tr>")
print("        </table>")
# Dynamically get server information
server_signature = os.environ.get('SERVER_SIGNATURE', 'tinyhttpd/0.1.0')
server_address = socket.gethostbyname(socket.gethostname())
server_port = os.environ.get('SERVER_PORT', '80')

print(f"        <address>{server_signature} at {server_address} Port {server_port}</address>")
print("    </body>")
print("</html>")
