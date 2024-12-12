# Tinyhttpd-WebDav

`Tinyhttpd-WebDav`是一个基于`tinyhttpd`的`WebDAV`扩展项目，支持`WebDAV`扩展：
`OPTIONS, GET, POST, DELETE, COPY, MOVE, PROPFIND, MKCOL`

可以通过webdav客户端连接（RaiDrive），也可以通过浏览器访问（默认使能了浏览器目录显示），比如：`127.0.0.1:8080`。

webdav访问目录为当前目录下面的webdav的文件。

```bash
# 1. 安装环境依赖
sudo apt install python3 make
# 2. 编译
make
# 3. 启动运行
./httpd # 启动，默认使用8080端口
./httpd -p 8888 # 启动，使用8888端口
./httpd & # 后台启动
```
