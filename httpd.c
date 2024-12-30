/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
 
 /*
     代码中除了用到 C 语言标准库的一些函数，也用到了一些与环境有关的函数(例如POSIX标准)
     具体可以参读《The Linux Programming Interface》，以下简称《TLPI》，页码指示均为英文版
     
     注释者： github: cbsheng
 */

// #ifndef __NXOS__
// #define __NXOS__
// #endif

#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#if defined(__UNIX__)
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/fcntl.h>

#define sock_close(sock) close(sock)
#define IS_DIR(mode) S_ISDIR(mode)
#define IS_EXEC(mode) (((mode) & S_IXUSR) || ((mode) & S_IXGRP) || ((mode) & S_IXOTH))


/* config */
// 使用多线程处理请求，当需要大量服务时可以考虑开启,0/1
#define USE_MULTI_THREAD_REQUEST 1
#define USE_CMD_PORT 1
#define USE_AUTO_PORT 1
#define USE_PIPE_SIGNAL 1

#elif defined(__NXOS__)
#include <nxos.h>
#include <netsocket.h>

// net api wrapper
#define socket(domain, type, protocol) NET_Socket(domain, type, protocol)
#define sock_close(sock) NET_Close(sock)
#define bind(sock, addr, addrlen) NET_Bind(sock, addr, addrlen)
#define listen(sock, backlog) NET_Listen(sock, backlog)
#define accept(sock, addr, addrlen) NET_Accept(sock, addr, addrlen)
#define send(sock, buf, len, flags) NET_Send(sock, (void *)(buf), len, flags)
#define recv(sock, buf, len, flags) NET_Recv(sock, (void *)(buf), len, flags)
#define shutdown(sock, how) NET_Shutdown(sock, how)

#define IS_DIR(mode) NX_FILE_IS_DIR(mode)
#define IS_EXEC(mode) ((mode) & NX_FILE_MODE_EXEC)

/* config */
// 使用多线程处理请求，当需要大量服务时可以考虑开启,0/1
#define USE_MULTI_THREAD_REQUEST 0
#define USE_CMD_PORT 0
#define USE_AUTO_PORT 0
#define USE_PIPE_SIGNAL 0
#else
#error unknown os!
#endif

#if USE_CMD_PORT == 1
#include <getopt.h>
#endif

// 默认端口号
#define DEFAULT_PORT 8080

#if USE_MULTI_THREAD_REQUEST == 1
#if defined(__NXOS__)
// nothing
#elif defined(__UNIX__)
#include <pthread.h>
#endif
#endif

#define ISspace(x) isspace((int)(x))

#define SERVER_NAME "tinyhttpd/0.1.0"
#define SERVER_STRING "Server: "SERVER_NAME"\r\n"

void accept_request(int);
void bad_request(int);
#if defined(__UNIX__)
void cat(int, FILE *);
#elif defined(__NXOS__)
void cat(int, NX_Solt);
#endif
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *, char *header);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(unsigned short *);
void unimplemented(int);

/**
 * 功能配置说明：
 * browser_root：在浏览器访问时显示的目录
 * webdav_root：在webdav客户端访问时显示的目录
 * index_file：在浏览器访问目录时访问的默认首页文件
 * enable_indexes：在浏览器访问目录时是否显示目录，如果配置1，则显示目录，不然则返回index_file对应的文件
 */

// 使能目录查看功能
int enable_indexes = 1;
#if defined(__UNIX__)
const char *showdir_cgi = "./cgi/showdir.cgi"; // showdir.py
#elif defined(__NXOS__)
const char *showdir_cgi = "/System/Applications/showdir.xapp";
#endif

// 浏览器服务目录，可修改为htdocs
char *browser_root = "webdav";
// webdav服务目录
char *webdav_root = "webdav";

char *icons_root = "icons";

// 默认浏览器索引文件
char *index_file = "index.html";

static unsigned short server_port = DEFAULT_PORT;

// 发送HTTP响应
void send_response(int client, const char *status, const char *content_type, const char *body) {
    char header[1024];
    sprintf(header,
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n",
        status, content_type, strlen(body));
    send(client, header, strlen(header), 0);
    send(client, body, strlen(body), 0);
}

// 检查请求头中是否有某个参数，并将结果保存到 buf 中
int get_header_value(const char *header, const char *param, char *buf, int buflen) {
    char *param_str = strstr(header, param);
    if (param_str) {
        // 找到参数，解析其值
        param_str += strlen(param);
        char *value_start = strchr(param_str, ':');
        if (value_start) {
            value_start++; // 跳过冒号
            while (*value_start == ' ') value_start++; // 跳过空格
            char *value_end = strchr(value_start, '\n');
            if (value_end) {
                int value_len = value_end - value_start;
                if (value_len < buflen) {
                    strncpy(buf, value_start, value_len);
                    buf[value_len] = '\0'; // 确保字符串结束符
                    return 0; // 成功
                } else {
                    return -2; // 缓冲区溢出
                }
            }
        }
    }
    return -1; // 未找到参数
}

#define BUFFER_SIZE 4096

int read_header(int client, char *buf, int len) {
    int numchars;
    char line[1024];
    int total_read = 0;

    // 读取请求头
    while ((numchars = get_line(client, line, sizeof(line))) > 0) {
        // 将读取的行累积到 buf 中
        if (total_read + numchars < len) {
            strcpy(buf + total_read, line);
            total_read += numchars;
        } else {
            // 缓冲区溢出
            return -1;
        }

        // 检查是否到达请求头结束（空行）
        if (strcmp(line, "\n") == 0 || strcmp(line, "") == 0) {
            break;
        }
    }

    // 返回读取的请求头长度
    return total_read;
}

int read_body(int client, char *buf, int len, int content_len) {
    int numchars;
    char line[1024];
    int total_read = 0;

    // 初始化缓冲区
    memset(buf, 0, len);

    // 读取请求头
    while (content_len > 0 && (numchars = get_line(client, line, sizeof(line))) > 0) {
        // 将读取的行累积到 buf 中
        if (total_read + numchars < len) {
            strcpy(buf + total_read, line);
            total_read += numchars;
        } else {
            // 缓冲区溢出
            return -1;
        }
        content_len -= total_read;
    }

    // 返回读取的请求头长度
    return total_read;
}


void handle_put(int client, const char *filepath, char *header) {
  printf("Method: PUT %s\n", filepath);

  int numchars;
  int content_length = -1;
  char buf[1024];

  // 获取header其他部分
    char content_buf[16];
    if (!get_header_value(header, "Content-Length", content_buf, sizeof(content_buf))) {
        //如果不存在，那把这次 http 的请求后续的内容(head 和 body)全部读完并忽略
        content_length = atoi(content_buf); //记录 body 的长度大小
    }
  //如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
  if (content_length == -1) {
   bad_request(client);
   return;
  }

  printf("Content-Length:%d\n", content_length);

  FILE *file = fopen(filepath, "wb");
  if (file == NULL) {
      send_response(client, "500 Internal Server Error", "text/plain", "Failed to open file");
      return;
  }

  while (content_length > 0 && (numchars = recv(client, buf, sizeof(buf) -1, 0)) > 0) {
      buf[numchars] = '\0';  // Ensure null-terminated string
      fwrite(buf, 1, numchars, file);
      content_length -= numchars;
  }
  fclose(file);
  send_response(client, "201 Created", "text/plain", "Success to creat file");
}

void format_time(time_t t, char *buf, size_t len) {
    struct tm *tm_info;

    // 使用 gmtime 或 localtime，这里我们使用 gmtime
    tm_info = gmtime(&t);

    if (tm_info == NULL) {
        // 处理错误情况
        snprintf(buf, len, "Invalid time");
        return;
    }

    // 使用 strftime 格式化时间
    if (strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", tm_info) == 0) {
        // 处理错误情况
        snprintf(buf, len, "Failed to format time");
    }

}

// 定义MIME类型映射表
typedef struct {
    const char *extension;
    const char *mime_type;
} MimeMap;

// 预定义一些常见的MIME类型
static const MimeMap mime_types[] = {
    {".html", "text/html"},
    {".txt", "text/plain"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
    {".gif", "image/gif"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    // 添加更多MIME类型映射...
    {NULL, NULL}  // 表结束标志
};

// 根据文件扩展名获取MIME类型
void get_mime_type_by_extension(const char *filename, char *buf, size_t buf_size) {
    int i;
    const char *ext = strrchr(filename, '.');
    if (!ext) {
        strncpy(buf, "application/octet-stream", buf_size);  // 未知类型默认值
        buf[buf_size - 1] = '\0';  // 确保字符串以 NULL 结尾
        return;
    }

    for (i = 0; mime_types[i].extension != NULL; ++i) {
        if (strcmp(ext, mime_types[i].extension) == 0) {
            strncpy(buf, mime_types[i].mime_type, buf_size);
            buf[buf_size - 1] = '\0';  // 确保字符串以 NULL 结尾
            return;
        }
    }

    strncpy(buf, "application/octet-stream", buf_size);  // 未找到匹配的扩展名
    buf[buf_size - 1] = '\0';  // 确保字符串以 NULL 结尾
}

// 根据目录路径获取MIME类型
void get_mime_type_for_directory(const char *path, char *buf, size_t buf_size) {
#if defined(__UNIX__)
    struct stat statbuf;
    if (stat(path, &statbuf) == 0 && IS_DIR(statbuf.st_mode)) {
#elif defined(__NXOS__)
    NX_FileStatInfo statbuf;
    if (NX_FileGetStatFromPath(path, &statbuf) == NX_EOK && NX_FILE_IS_DIR(statbuf.mode)) {
#endif
        strncpy(buf, "httpd/unix-directory", buf_size);  // 目录的MIME类型
        buf[buf_size - 1] = '\0';  // 确保字符串以 NULL 结尾
    }
}

// 根据文件路径获取MIME类型
void get_mime_type(const char *filepath, char *buf, size_t buf_size) {
    char mime_type[256];
    get_mime_type_for_directory(filepath, buf, buf_size);
    if (strcmp(buf, "httpd/unix-directory") == 0) {
        return;  // 返回目录的MIME类型
    }

    get_mime_type_by_extension(filepath, mime_type, sizeof(mime_type));
    strncpy(buf, mime_type, buf_size);
    buf[buf_size - 1] = '\0';  // 确保字符串以 NULL 结尾
}

#if defined(__UNIX__)
int generate_propfind_response_body(struct stat *statbuf, char *xml_response, int response_len, int offset, const char *path) {
    time_t st_mtim = statbuf->st_mtime;
    time_t st_ctim = statbuf->st_ctime;
    ino_t st_ino = statbuf->st_ino;
    mode_t st_mode = statbuf->st_mode;
    off_t st_size = statbuf->st_size;
#elif defined(__NXOS__)
int generate_propfind_response_body(NX_FileStatInfo *statbuf, char *xml_response, int response_len, int offset, const char *path) {
    time_t st_mtim = statbuf->mtime;
    time_t st_ctim = statbuf->ctime;
    NX_U32 st_ino = 0; // unsupport
    NX_U32 st_mode = statbuf->mode;
    NX_Size st_size = statbuf->size;
#endif

  // 添加资源类型、创建日期、最后修改日期、ETag等属性
  char time_buffer[256];
  format_time(st_mtim, time_buffer, sizeof(time_buffer));
  offset += snprintf(xml_response + offset, response_len - offset,
                      "<D:response>\n"
                      "<D:href>%s</D:href>\n"
                      "<D:propstat>\n"
                      "<D:prop>\n",
                      (path)); // 跳过路径的第一个字符，通常是 /

  // 检查是否是目录
  if (IS_DIR(st_mode)) {
      offset += snprintf(xml_response + offset, response_len - offset,
                          "<D:resourcetype><D:collection/></D:resourcetype>\n");
  } else {
      // 文件的resourcetype为空
      offset += snprintf(xml_response + offset, response_len - offset, "<D:resourcetype/>\n");
  }

  offset += snprintf(xml_response + offset, response_len - offset,
                      "<D:creationdate>%s</D:creationdate>\n"
                      "<D:getlastmodified>%s</D:getlastmodified>\n"
                      "<D:getetag>\"%lx-%lx\"</D:getetag>\n",
                      ctime(&st_ctim), // 创建时间
                      time_buffer, // 最后修改时间
                      st_ino, // ETag第一部分：inode
                      (unsigned long)st_size); // ETag第二部分：文件大小

  // 添加文件大小
  offset += snprintf(xml_response + offset, response_len - offset,
                   "<D:getcontentlength>%ld</D:getcontentlength>\n",
                   (long)st_size);

  // 添加锁支持
  offset += snprintf(xml_response + offset, response_len - offset,
                      "<D:supportedlock>\n"
                      "<D:lockentry>\n"
                      "<D:lockscope><D:exclusive/></D:lockscope>\n"
                      "<D:locktype><D:write/></D:locktype>\n"
                      "</D:lockentry>\n"
                      "<D:lockentry>\n"
                      "<D:lockscope><D:shared/></D:lockscope>\n"
                      "<D:locktype><D:write/></D:locktype>\n"
                      "</D:lockentry>\n"
                      "</D:supportedlock>\n"
                      "<D:lockdiscovery/>\n");

  // 添加内容类型
  char mime_type[256];
  get_mime_type(path, mime_type, sizeof(mime_type)); // 假设有一个函数来获取MIME类型
  offset += snprintf(xml_response + offset, response_len - offset,
                      "<D:getcontenttype>%s</D:getcontenttype>\n",
                      mime_type);

  // 结束prop和propstat元素
  offset += snprintf(xml_response + offset, response_len - offset,
                      "</D:prop>\n"
                      "<D:status>HTTP/1.1 200 OK</D:status>\n"
                      "</D:propstat>\n"
                      "</D:response>\n");

    return offset;
}

// 假设有一个函数来获取文件或目录的属性
int generate_propfind_response(char *xml_response, int response_len, const char *path, const char *url) {
  int offset = 0;
#if defined(__UNIX__)
  struct stat statbuf;
  if (stat(path, &statbuf) == -1) {
    return -1;
  }
#elif defined(__NXOS__)
    NX_FileStatInfo statbuf;
    if (NX_FileGetStatFromPath(path, &statbuf) != NX_EOK) {
        return -1;
    }
#endif

  // 添加响应头
  offset += snprintf(xml_response, response_len,
                      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                      "<D:multistatus xmlns:D=\"DAV:\">\n");

  offset = generate_propfind_response_body(&statbuf, xml_response, response_len, offset, url);

  // 结束multistatus元素
  offset += snprintf(xml_response + offset, response_len,
                      "</D:multistatus>\n");

  return offset;
}

#define PROP_CHUNK 2048
#define EXPAND_SIZE (PROP_CHUNK * 4)

#if defined(__UNIX__)
static int propfind_dir(int client, const char *filepath, const char *url)
{
  DIR *dir;
  struct dirent *entry;
  char entry_path[1024];
  char entry_url[1024];
  char *response;
  int response_len = EXPAND_SIZE;
  int offset = 0;
  struct stat statbuf;

  dir = opendir(filepath);
  if (dir == NULL) {
      send_response(client, "500 Internal Server Error", "text/plain", "Failed to open directory");
      return -1;
  }

  response = malloc(response_len);
  if (!response) {
    closedir(dir);
    send_response(client, "500 Internal Server Error", "text/plain", "Failed to open directory");
    return -1;
  }

  // 其他XML部分...
  offset += sprintf(response, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:multistatus xmlns:D=\"DAV:\">\n");

  while ((entry = readdir(dir)) != NULL) {
      // 跳过 "." 和 ".."
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
          continue;
      }

      // 构建完整的文件路径
      memset(entry_path, 0, sizeof(entry_path));
      if (filepath[strlen(filepath) - 1] == '/') {
        snprintf(entry_path, sizeof(entry_path), "%s%s", filepath, entry->d_name);
      } else {
        snprintf(entry_path, sizeof(entry_path), "%s/%s", filepath, entry->d_name);
      }
      
      memset(entry_url, 0, sizeof(entry_url));
      if (url[strlen(url) - 1] == '/') {
        snprintf(entry_url, sizeof(entry_url), "%s%s", url, entry->d_name);
      } else {
        snprintf(entry_url, sizeof(entry_url), "%s/%s", url, entry->d_name);
      }

      if (stat(entry_path, &statbuf) == -1) {
        closedir(dir);
        free(response);
        send_response(client, "500 Internal Server Error", "text/plain", "File not exist");
        return -1; 
      }

      // 获取文件状态
      offset = generate_propfind_response_body(&statbuf, response, response_len, offset, entry_url);
      // 扩展响应内存
      if (offset + PROP_CHUNK > response_len) {
        // printf("expand , response len %d, off %d\n", response_len, offset);
        response = realloc(response, response_len + EXPAND_SIZE);
        if (!response) {
            closedir(dir);
            free(response);
            send_response(client, "500 Internal Server Error", "text/plain", "No enough memory");
            return -1;
        }
        response_len += EXPAND_SIZE;
      }
  }
  
  offset += sprintf(response + offset, "</D:multistatus>");
  send_response(client, "207 Multi-Status", "application/xml", response);
  free(response);
  closedir(dir);

  return offset;
}
#elif defined(__NXOS__)
static int propfind_dir(int client, const char *filepath, const char *url)
{
  NX_Solt dir;
  NX_Dirent entry;
  char entry_path[1024];
  char entry_url[1024];
  char *response;
  int response_len = EXPAND_SIZE;
  int offset = 0;
  NX_FileStatInfo statbuf;

  dir = NX_DirOpen(filepath);
  if (dir == NX_SOLT_INVALID_VALUE) {
      send_response(client, "500 Internal Server Error", "text/plain", "Failed to open directory");
      return -1;
  }

  response = malloc(response_len);
  if (!response) {
    NX_DirClose(dir);
    send_response(client, "500 Internal Server Error", "text/plain", "Failed to open directory");
    return -1;
  }

  // 其他XML部分...
  offset += sprintf(response, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:multistatus xmlns:D=\"DAV:\">\n");

  while ((NX_DirRead(dir, &entry)) == NX_EOK) {
      // 跳过 "." 和 ".."
      if (strcmp(entry.name, ".") == 0 || strcmp(entry.name, "..") == 0) {
          continue;
      }

      // 构建完整的文件路径
      memset(entry_path, 0, sizeof(entry_path));
      if (filepath[strlen(filepath) - 1] == '/') {
        snprintf(entry_path, sizeof(entry_path), "%s%s", filepath, entry.name);
      } else {
        snprintf(entry_path, sizeof(entry_path), "%s/%s", filepath, entry.name);
      }
      
      memset(entry_url, 0, sizeof(entry_url));
      if (url[strlen(url) - 1] == '/') {
        snprintf(entry_url, sizeof(entry_url), "%s%s", url, entry.name);
      } else {
        snprintf(entry_url, sizeof(entry_url), "%s/%s", url, entry.name);
      }

      if (NX_FileGetStatFromPath(entry_path, &statbuf) != NX_EOK) {
        NX_DirClose(dir);
        free(response);
        send_response(client, "500 Internal Server Error", "text/plain", "File not exist");
        return -1; 
      }

      // 获取文件状态
      offset = generate_propfind_response_body(&statbuf, response, response_len, offset, entry_url);
      // 扩展响应内存
      if (offset + PROP_CHUNK > response_len) {
        // printf("expand , response len %d, off %d\n", response_len, offset);
        response = realloc(response, response_len + EXPAND_SIZE);
        if (!response) {
            NX_DirClose(dir);
            free(response);
            send_response(client, "500 Internal Server Error", "text/plain", "No enough memory");
            return -1;
        }
        response_len += EXPAND_SIZE;
      }
  }
  
  offset += sprintf(response + offset, "</D:multistatus>");
  send_response(client, "207 Multi-Status", "application/xml", response);
  free(response);
  NX_DirClose(dir);

  return offset;
}
#endif

void handle_propfind(int client, const char *filepath, const char *url, char *header) {
#if defined(__UNIX__)
    struct stat file_stat;
    mode_t st_mode;
#elif defined(__NXOS__)
    NX_FileStatInfo file_stat;
    NX_U32 st_mode;
#endif
    char response[PROP_CHUNK];
    memset(response, 0, sizeof(response));

    printf("Method: PROPFIND %s\n", filepath);

    // 检查是否有长度参数，如果有就读取剩余的，没有就不读取。
    char depth[16];
    if (get_header_value(header, "Depth", depth, sizeof(depth))) {
        strcpy(depth, "infinity"); // 默认"infinity"
    }

    //如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
    if (strcmp(depth, "infinity") == 0) {
        printf("Depth:%s not support\n", depth);

        snprintf(response, 1024, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                    "<D:multistatus xmlns:D=\"DAV:\">\n"
                    "  <D:response>\n"
                    "    <D:href>%s</D:href>\n"
                    "    <D:propstat>\n"
                    "      <D:prop>\n"
                    "        <D:resourcetype><D:collection/></D:resourcetype>\n"
                    "      </D:prop>\n"
                    "      <D:status>HTTP/1.1 403 Forbidden</D:status>\n"
                    "    </D:propstat>\n"
                    "  </D:response>\n"
                    "  <D:error>\n"
                    "    <D:cannot-modify-property />\n"
                    "  </D:error>\n"
                    "</D:multistatus>\n", url);

        send_response(client, "403 Forbidden", "application/xml; charset=\"utf-8\"", response);
        return;
    }

#if defined(__UNIX__)
    if (stat(filepath, &file_stat) == -1) {
        send_response(client, "404 Not Found", "text/plain", "File not found");
        return;
    }
    st_mode = file_stat.st_mode;
#elif defined(__NXOS__)
    if (NX_FileGetStatFromPath(filepath, &file_stat) != NX_EOK) {
        send_response(client, "404 Not Found", "text/plain", "File not found");
        return;
    }
    st_mode = file_stat.mode;
#endif
    // 只有depth为1才返回目录，不然依然返回文件信息
    if (IS_DIR(st_mode) && strcmp(depth, "1") == 0) {
      if (propfind_dir(client, filepath, url) == -1)
        return;
    } else {
      generate_propfind_response(response, sizeof(response), filepath, url);
      send_response(client, "207 Multi-Status", "application/xml", response);
    }
}

#if defined(__UNIX__)
// 递归删除目录及其所有内容
int remove_directory(const char *path) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char full_path[1024];

    if ((dir = opendir(path)) == NULL) {
        return -1; // 打开目录失败
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue; // 跳过 "." 和 ".."
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (stat(full_path, &statbuf) == -1) {
            closedir(dir);
            return -1; // 获取状态失败
        }

        if (IS_DIR(statbuf.st_mode)) {
            // 递归删除子目录
            if (remove_directory(full_path) == -1) {
                closedir(dir);
                return -1; // 子目录删除失败
            }
        } else {
            // 删除文件
            if (remove(full_path) == -1) {
                closedir(dir);
                return -1; // 文件删除失败
            }
        }
    }

    closedir(dir);

    // 删除空目录
    return rmdir(path);
}

void handle_delete(int client, const char *path) {
    struct stat statbuf;

    printf("Method: DELETE %s\n", path);

    if (stat(path, &statbuf) == -1) {
        // 文件或目录不存在
        send_response(client, "404 Not Found", "text/plain", "File not found");
        return;
    }

    if (IS_DIR(statbuf.st_mode)) {
        // 删除目录
        if (remove_directory(path) == -1) {
            send_response(client, "500 Internal Server Error", "text/plain", "Remove directory failed");
            return;
        }
    } else {
        // 删除文件
        if (remove(path) == -1) {
            send_response(client, "500 Internal Server Error", "text/plain", "Remove file failed");
            return;
        }
    }

    // 删除成功
    send_response(client, "204 No Content", "text/plain", "Success to delete resource");
}

#elif defined(__NXOS__)
// 递归删除目录及其所有内容
int remove_directory(const char *path) {
    NX_Solt dir;
    NX_Dirent entry;
    NX_FileStatInfo statbuf;
    char full_path[1024];

    if ((dir = NX_DirOpen(path)) == NX_SOLT_INVALID_VALUE) {
        return -1; // 打开目录失败
    }

    while ((NX_DirRead(dir, &entry)) == NX_EOK) {
        if (strcmp(entry.name, ".") == 0 || strcmp(entry.name, "..") == 0) {
            continue; // 跳过 "." 和 ".."
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry.name);

        if (NX_FileGetStatFromPath(path, &statbuf) != NX_EOK) {
            NX_DirClose(dir);
            return -1; // 获取状态失败
        }

        if (IS_DIR(statbuf.mode)) {
            // 递归删除子目录
            if (remove_directory(full_path) == -1) {
                NX_DirClose(dir);
                return -1; // 子目录删除失败
            }
        } else {
            // 删除文件
            if (NX_FileDelete(full_path) == -1) {
                NX_DirClose(dir);
                return -1; // 文件删除失败
            }
        }
    }

    NX_DirClose(dir);

    // 删除空目录
    return NX_DirDelete(path);
}

void handle_delete(int client, const char *path) {
    NX_FileStatInfo statbuf;

    printf("Method: DELETE %s\n", path);

    if (NX_FileGetStatFromPath(path, &statbuf) != NX_EOK) {
        // 文件或目录不存在
        send_response(client, "404 Not Found", "text/plain", "File not found");
        return;
    }

    if (IS_DIR(statbuf.mode)) {
        // 删除目录
        if (remove_directory(path) == -1) {
            send_response(client, "500 Internal Server Error", "text/plain", "Remove directory failed");
            return;
        }
    } else {
        // 删除文件
        if (NX_FileDelete(path) == -1) {
            send_response(client, "500 Internal Server Error", "text/plain", "Remove file failed");
            return;
        }
    }

    // 删除成功
    send_response(client, "204 No Content", "text/plain", "Success to delete resource");
}
#endif

int handle_mkcol(int client, const char *path) {
    
    printf("Method: MKCOL %s\n", path);
#if defined(__UNIX__)
    // 尝试创建目录
    if (mkdir(path, 0755) == -1) {
        // 目录创建失败
        if (errno == EEXIST) {
            send_response(client, "405 Method Not Allowed", "text/plain", "The resource already exists.");
        } else if (errno == EACCES || errno == EPERM) {
            send_response(client, "403 Forbidden", "text/plain", "Permission denied.");
        } else {
            char *err_msg = strerror(errno);
            send_response(client, "500 Internal Server Error", "text/plain", err_msg);
        }
        return -1;
    }
#elif defined(__NXOS__)
    NX_Error err = NX_DirCreate(path, 0755);
    // 尝试创建目录
    if (err != NX_EOK) {
        // 目录创建失败
        if (err == NX_ENORES) {
            send_response(client, "405 Method Not Allowed", "text/plain", "The resource already exists.");
        } else if (err == NX_EPERM || err == NX_EFAULT) {
            send_response(client, "403 Forbidden", "text/plain", "Permission denied.");
        } else {
            char *err_msg = strerror(errno);
            send_response(client, "500 Internal Server Error", "text/plain", err_msg);
        }
        return -1;
    }
#endif
    // 目录创建成功
    send_response(client, "201 Created", "text/plain", "Collection created successfully.");
    return 0;
}

#define PARM_MOVE_DEST "Destination:"

int is_remote_url(const char *dest) {
    // Simple check to see if the destination starts with "http://" or "https://"
    return strncmp(dest, "http://", 7) == 0 || strncmp(dest, "https://", 8) == 0;
}

char* extract_path_from_url(const char *url) {
    // 找到主机名后的第一个 '/' 字符的位置
    const char *start = strstr(url, "://");
    if (start) {
        start += 3; // 跳过 "://"
        const char *host_end = strchr(start, '/');
        if (host_end) {
            // 返回主机名后的第一个 '/' 之后的部分，即路径
            return (char *)host_end + 1;
        }
    }
    return NULL; // 如果没有找到路径，返回 NULL
}

int parse_dest_path(const char *header, char *buf, int buflen) {
    char dest[256] = {0};
    if (get_header_value(header, "Destination", dest, sizeof(dest))) {
        return -1;
    }

    char *path = is_remote_url(dest) ? extract_path_from_url(dest): dest;
    if (!path)
        return -1;

    snprintf(buf, buflen, "%s/%s", webdav_root, path);
    return 0;
}

int handle_move(int client, const char *path, char *header) {
    
    printf("Method: MOVE %s\n", path);

    /* 获取参数 */
    char dest[256] = {0};
    if (parse_dest_path(header, dest, sizeof(dest))) {
        send_response(client, "400 Bad Request", "text/plain", "No file destination");
        return -1;
    }

    // 检查目标文件是否已经存在
#if defined(__UNIX__)
    if (access(dest, F_OK) == 0) {
#elif defined(__NXOS__)
    if (NX_FileAccess(dest, NX_FILE_READ_OK) == NX_EOK) {
#endif
        send_response(client, "409 Conflict", "text/plain", "File conflict");
        return -1;
    }

#if defined(__UNIX__)
    if (rename(path, dest) == 0) {
#elif defined(__NXOS__)
    if (NX_FileRename(path, dest) == NX_EOK) {
#endif
        send_response(client, "200 OK", "text/plain", "Move file sucess");
    } else {
        send_response(client, "500 Internal Server Error", "text/plain", "Move file failed");
        return -1;
    }

    return 0;
}

#if defined(__UNIX__)
static int copy_file(const char *src, const char *dest, mode_t mode) {
    int src_fd = open(src, O_RDONLY);
    if (src_fd == -1) {
        return -1;
    }

    int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (dest_fd == -1) {
        close(src_fd);
        return -1;
    }

    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        if (write(dest_fd, buffer, bytes_read) != bytes_read) {
            close(src_fd);
            close(dest_fd);
            return -1;
        }
    }

    if (bytes_read == -1) {
        close(src_fd);
        close(dest_fd);
        return -1;
    }

    close(src_fd);
    close(dest_fd);
    return 0;
}

// 递归复制目录
int copy_directory(const char *src, const char *dest) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char src_path[512];
    char dest_path[512];
    int ret = 0;

    // 打开源目录
    dir = opendir(src);
    if (!dir) {
        return -1;
    }

    // 创建目标目录
    if (mkdir(dest, 0755) == -1 && errno != EEXIST) {
        closedir(dir);
        return -1;
    }

    // 遍历目录中的所有文件和子目录
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue; // 跳过当前目录和上级目录
        }

        snprintf(src_path, sizeof(src_path), "%s/%s", src, entry->d_name);
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest, entry->d_name);

        if (lstat(src_path, &file_stat) == -1) {
            ret = -1;
            break;
        }

        if (IS_DIR(file_stat.st_mode)) {
            // 递归复制子目录
            if (copy_directory(src_path, dest_path) == -1) {
                ret = -1;
                break;
            }
        } else {
            // 复制文件
            if (copy_file(src_path, dest_path, file_stat.st_mode) == -1) {
                ret = -1;
                break;
            }
        }
    }

    closedir(dir);
    return ret;
}

int handle_copy(int client, const char *path, char *header) {
    
    printf("Method: COPY %s\n", path);

    char dest[256] = {0};
    if (parse_dest_path(header, dest, sizeof(dest))) {
        send_response(client, "400 Bad Request", "text/plain", "No file destination");
        return -1;
    }

    // 检查目标文件是否已经存在
    if (access(dest, F_OK) == 0) {
        send_response(client, "409 Conflict", "text/plain", "File conflict");
        return -1;
    }

    struct stat file_stat;
    if (stat(path, &file_stat) == -1) {
        send_response(client, "500 Internal Server Error", "text/plain", "Failed to stat source file");
        return -1;
    }

    if (IS_DIR(file_stat.st_mode)) {
        // 如果是目录，递归复制目录
        if (copy_directory(path, dest) == 0) {
            // 设置目标目录的权限
            if (chmod(dest, file_stat.st_mode) == -1) {
                send_response(client, "500 Internal Server Error", "text/plain", "Failed to set directory permissions");
                return -1;
            }
            send_response(client, "200 OK", "text/plain", "Directory copied successfully");
        } else {
            send_response(client, "500 Internal Server Error", "text/plain", "Failed to copy directory");
        }
    } else {
        // 如果是文件，复制文件
        if (copy_file(path, dest, file_stat.st_mode) == 0) {
            send_response(client, "200 OK", "text/plain", "File copied successfully");
        } else {
            send_response(client, "500 Internal Server Error", "text/plain", "Failed to copy file");
        }
    }
    return 0;
}
#elif defined(__NXOS__)
static int copy_file(const char *src, const char *dest, NX_U32 mode) {
    int src_fd = NX_FileOpen(src, NX_FILE_RDONLY, mode);
    if (src_fd == -1) {
        return -1;
    }

    int dest_fd = NX_FileOpen(dest, NX_FILE_WRONLY | NX_FILE_CREAT | NX_FILE_TRUNC, mode);
    if (dest_fd == -1) {
        NX_FileClose(src_fd);
        return -1;
    }

    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = NX_FileRead(src_fd, buffer, sizeof(buffer))) > 0) {
        if (NX_FileWrite(dest_fd, buffer, bytes_read) != bytes_read) {
            NX_FileClose(src_fd);
            NX_FileClose(dest_fd);
            return -1;
        }
    }

    if (bytes_read == -1) {
        NX_FileClose(src_fd);
        NX_FileClose(dest_fd);
        return -1;
    }

    NX_FileClose(src_fd);
    NX_FileClose(dest_fd);
    return 0;
}

// 递归复制目录
int copy_directory(const char *src, const char *dest) {
    NX_Solt dir;
    NX_Dirent entry;
    NX_FileStatInfo file_stat;
    char src_path[512];
    char dest_path[512];
    int ret = 0;

    // 打开源目录
    dir = NX_DirOpen(src);
    if (dir == NX_SOLT_INVALID_VALUE) {
        return -1;
    }

    // 创建目标目录
    if (NX_DirCreate(dest, 0755) != NX_EOK) {
        NX_DirClose(dir);
        return -1;
    }

    // 遍历目录中的所有文件和子目录
    while ((NX_DirRead(dir, &entry)) == NX_EOK) {
        if (strcmp(entry.name, ".") == 0 || strcmp(entry.name, "..") == 0) {
            continue; // 跳过当前目录和上级目录
        }

        snprintf(src_path, sizeof(src_path), "%s/%s", src, entry.name);
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest, entry.name);

        if (NX_FileGetStatFromPath(src_path, &file_stat) != NX_EOK) {
            ret = -1;
            break;
        }

        if (IS_DIR(file_stat.mode)) {
            // 递归复制子目录
            if (copy_directory(src_path, dest_path) == -1) {
                ret = -1;
                break;
            }
        } else {
            // 复制文件
            if (copy_file(src_path, dest_path, file_stat.mode) == -1) {
                ret = -1;
                break;
            }
        }
    }

    NX_DirClose(dir);
    return ret;
}

int handle_copy(int client, const char *path, char *header) {
    
    printf("Method: COPY %s\n", path);

    char dest[256] = {0};
    if (parse_dest_path(header, dest, sizeof(dest))) {
        send_response(client, "400 Bad Request", "text/plain", "No file destination");
        return -1;
    }

    // 检查目标文件是否已经存在
    if (NX_FileAccess(dest, NX_FILE_READ_OK) == NX_EOK) {
        send_response(client, "409 Conflict", "text/plain", "File conflict");
        return -1;
    }

    NX_FileStatInfo file_stat;
    if (NX_FileGetStatFromPath(path, &file_stat) != NX_EOK) {
        send_response(client, "500 Internal Server Error", "text/plain", "Failed to stat source file");
        return -1;
    }

    if (IS_DIR(file_stat.mode)) {
        // 如果是目录，递归复制目录
        if (copy_directory(path, dest) == 0) {
            // 设置目标目录的权限
            if (NX_FileSetModeToPath(dest, file_stat.mode) != NX_EOK) {
                send_response(client, "500 Internal Server Error", "text/plain", "Failed to set directory permissions");
                return -1;
            }
            send_response(client, "200 OK", "text/plain", "Directory copied successfully");
        } else {
            send_response(client, "500 Internal Server Error", "text/plain", "Failed to copy directory");
        }
    } else {
        // 如果是文件，复制文件
        if (copy_file(path, dest, file_stat.mode) == 0) {
            send_response(client, "200 OK", "text/plain", "File copied successfully");
        } else {
            send_response(client, "500 Internal Server Error", "text/plain", "Failed to copy file");
        }
    }
    return 0;
}
#endif

int check_webdav(char *buf)
{
    char *mozila;
    char useragent[256];
    if (get_header_value(buf, "User-Agent", useragent, sizeof(useragent))) {
        return 0; // 没有agent
    }
    // 基本上浏览器都有Mozilla，所以简单判断就行
    mozila = strstr(useragent, "Mozilla");
    if (mozila != NULL) {
        return 0;
    }
    // 其他客户端就认定为webdav
    return 1;
}

void handle_options(int client) {
    char buf[1024];

    printf("Method: OPTIONS\n");

    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);

    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);

    // 设置Allow头，列出支持的方法
    // 全部功能：OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
    // 不过目前只支持部分功能
    sprintf(buf, "Allow: OPTIONS, GET, POST, DELETE, COPY, MOVE, PROPFIND, MKCOL\r\n");
    send(client, buf, strlen(buf), 0);

    // 设置Content-Length头
    sprintf(buf, "Content-Length: 0\r\n");
    send(client, buf, strlen(buf), 0);

    // 添加空行表示头部结束
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(int client)
{
 char buf[1024] = {0};
 char method[255];
 char url[255];
 char path[512];
 size_t i, j;
#if defined(__UNIX__)
 struct stat st;
 mode_t mode;
#elif defined(__NXOS__)
 NX_FileStatInfo st;
 NX_U32 mode;
#endif

 int cgi = 0;      /* becomes true if server decides this is a CGI
                    * program */
 char *query_string = NULL;
 int check_exist = 0;
 char *param; // param start from second line
 int is_webdav = 0;
 char *prefix_dir;
 int show_dir = 0;

 int len = read_header(client, buf, sizeof(buf));
//  printf("header: %d, %s\n", len, buf);
 if (len <= 0) {
    bad_request(client);
    return;
 }

 // skip newline
 param = strstr(buf, "\n");
 while (*param == '\n' || *param == '\r')
 {
    param++;
 }

 /* 获取用户代理，如果是浏览器，就使用浏览器方式，不然就是webdav文件传输。 */
 is_webdav = check_webdav(param);
 prefix_dir = is_webdav ? webdav_root : browser_root;
//  printf("is webdav: %d\n", is_webdav);

 //读http 请求的第一行数据（request line），把请求方法存进 method 中
 i = 0; j = 0;
 while (!ISspace(buf[j]) && (i < sizeof(method) - 1))
 {
  method[i] = buf[j];
  i++; j++;
 }
 method[i] = '\0';

 //如果请求的方法不是 GET 或 POST 任意一个的话就直接发送 response 告诉客户端没实现该方法
 if (strcasecmp(method, "GET") && strcasecmp(method, "POST") && strcasecmp(method, "PUT") && 
    strcasecmp(method, "PROPFIND") && strcasecmp(method, "DELETE") && strcasecmp(method, "MKCOL") &&
    strcasecmp(method, "MOVE") && strcasecmp(method, "COPY") && strcasecmp(method, "OPTIONS"))
 {
  unimplemented(client);
  return;
 }

 //如果是 POST 方法就将 cgi 标志变量置一(true)
 if (strcasecmp(method, "POST") == 0) {
  check_exist = 1;
  cgi = 1;
 }

 i = 0;
 //跳过所有的空白字符(空格)
 while (ISspace(buf[j]) && (j < sizeof(buf))) 
  j++;
 
 //然后把 URL 读出来放到 url 数组中
 while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)))
 {
  url[i] = buf[j];
  i++; j++;
 }
 url[i] = '\0';

 //如果这个请求是一个 GET 方法的话
 if (strcasecmp(method, "GET") == 0)
 {
  check_exist = 1;
  if (!is_webdav) {
    //用一个指针指向 url
    query_string = url;
    
    //去遍历这个 url，跳过字符 ？前面的所有字符，如果遍历完毕也没找到字符 ？则退出循环
    while ((*query_string != '?') && (*query_string != '\0'))
    query_string++;
    
    //退出循环后检查当前的字符是 ？还是字符串(url)的结尾
    if (*query_string == '?')
    {
    //如果是 ？ 的话，证明这个请求需要调用 cgi，将 cgi 标志变量置一(true)
    cgi = 1;
    //从字符 ？ 处把字符串 url 给分隔会两份
    *query_string = '\0';
    //使指针指向字符 ？后面的那个字符
    query_string++;
    }
  }
 }

 if (strcasecmp(method, "DELETE") == 0 || strcasecmp(method, "MOVE") == 0 ||
    strcasecmp(method, "COPY") == 0)
 {
    check_exist = 1;
 }
 
    // 拦截icons目录
    if (enable_indexes && strncmp(url, "/icons/", 7) == 0) {
        sprintf(path, "%s", (url + 1)); // skip '/'
    } else {
        //将前面分隔两份的前面那份字符串，拼接在字符串htdocs的后面之后就输出存储到数组 path 中。相当于现在 path 中存储着一个字符串
        sprintf(path, "%s%s", prefix_dir, url);
    }
 
    //如果 path 数组中的这个字符串的最后一个字符是以字符 / 结尾的话，就拼接上一个"index.html"的字符串。首页的意思
    if (!is_webdav && path[strlen(path) - 1] == '/') {
        if (!enable_indexes) {
            strcat(path, index_file);
        } else {
            // 如果使能索引了，就是浏览目录
            show_dir = 1;
            cgi = 1;
        }
    }

 //在系统上去查询该文件是否存在
#if defined(__UNIX__)
 if ((stat(path, &st) == -1) && check_exist) {
#elif defined(__NXOS__)
 if (NX_FileGetStatFromPath(path, &st) != NX_EOK && check_exist) {
#endif
    // 检查是否有长度参数，如果有就读取剩余的，没有就不读取。
    char content_buf[16];
    if (!get_header_value(param, "Content-Length", content_buf, sizeof(content_buf))) {
        //如果不存在，那把这次 http 的请求后续的内容(head 和 body)全部读完并忽略
        int content_length = atoi(content_buf); //记录 body 的长度大小
        if (content_length > 0)
            read_body(client, buf, sizeof(buf), content_length);
    }
  //然后返回一个找不到文件的 response 给客户端
  not_found(client);
 }
 else
 {
#if defined(__UNIX__)
    mode = st.st_mode;
#elif defined(__NXOS__)
    mode = st.mode;
#endif
    /* 不是webdav的情况下，检查是否为CGI */
    if (!is_webdav) {
        //文件存在，那去跟常量S_IFMT相与，相与之后的值可以用来判断该文件是什么类型的
        //S_IFMT参读《TLPI》P281，与下面的三个常量一样是包含在<sys/stat.h>
        if (IS_DIR(mode)) {
            if (!enable_indexes) {
                //如果这个文件是个目录，那就需要再在 path 后面拼接一个"/index.html"的字符串
                if (path[strlen(path) - 1] != '/')
                    strcat(path, "/");
                strcat(path, index_file);
            } else {
                // 如果使能索引了，就是浏览目录
                show_dir = 1;
                cgi = 1;
            }
        } else if (IS_EXEC(mode)) {
            //S_IXUSR, S_IXGRP, S_IXOTH三者可以参读《TLPI》P295
            //如果这个文件是一个可执行文件，不论是属于用户/组/其他这三者类型的，就将 cgi 标志变量置一
            // TODO: cgi = 1;
        }
    }

  if (strcasecmp(method, "GET") == 0 || strcasecmp(method, "POST") == 0) {
    // GET方法可能有参数，就是CGI，没有就是普通的文件返回。POST一定是有CGI的。
    if (!cgi || is_webdav) { //如果不需要 cgi 机制的
        serve_file(client, path);
    } else {
        if (!show_dir) {
            //如果需要则调用
            execute_cgi(client, path, method, query_string, param);
        } else {
            //显示目录
            char query_param[256+64];
            snprintf(query_param, sizeof(query_param), "port=%d&prefix=%s&url=%s",
                server_port, prefix_dir, url);
            execute_cgi(client, showdir_cgi, method, query_param, param);
        }
    }
  } else if (strcasecmp(method, "PUT") == 0) {
    handle_put(client, path, param);
  } else if (strcasecmp(method, "PROPFIND") == 0) {
    handle_propfind(client, path, url, param);
  } else if (strcasecmp(method, "DELETE") == 0) {
    handle_delete(client, path);
  } else if (strcasecmp(method, "MKCOL") == 0) {
    handle_mkcol(client, path);
  } else if (strcasecmp(method, "MOVE") == 0) {
    handle_move(client, path, param);
  } else if (strcasecmp(method, "COPY") == 0) {
    handle_copy(client, path, param);
  } else if (strcasecmp(method, "OPTIONS") == 0) {
    handle_options(client);
  }
 }
 // disconnect first, make sure response send done
  shutdown(client, SHUT_WR);
 sock_close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "Content-type: text/html\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "<P>Your browser sent a bad request, ");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "such as a POST without a Content-Length.\r\n");
 send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
#if defined(__UNIX__)
void cat(int client, FILE *resource)
{
    char buf[1024];
    size_t bytes_read;

    // 从文件中读取指定内容
    while ((bytes_read = fread(buf, 1, sizeof(buf), resource)) > 0) {
        send(client, buf, bytes_read, 0);
    }
}
#elif defined(__NXOS__)
void cat(int client, NX_Solt resource)
{
    char buf[2048];
    size_t bytes_read;

    // 从文件中读取指定内容
    while ((bytes_read = NX_FileRead(resource, buf, sizeof(buf))) > 0) {
        send(client, buf, bytes_read, 0);
    }
}
#endif
/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
 //包含于<stdio.h>,基于当前的 errno 值，在标准错误上产生一条错误消息。参考《TLPI》P49
 perror(sc); 
 exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path,
                 const char *method, const char *query_string, char *header)
{
 char buf[32];
 int i;
 char c;
 int content_length = -1;

    printf("CGI: path: %s, method: %s, query: %s\n", path, method, query_string);

    if (strcasecmp(method, "POST") == 0) {
        // 检查是否有长度参数，如果有就读取剩余的，没有就不读取。
        char content_buf[16];
        if (!get_header_value(header, "Content-Length", content_buf, sizeof(content_buf))) {
            //如果不存在，那把这次 http 的请求后续的内容(head 和 body)全部读完并忽略
            content_length = atoi(content_buf); //记录 body 的长度大小
        }

        //如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }

#if defined(__UNIX__)
 int cgi_output[2];
 int cgi_input[2];
 pid_t pid;
 int status;
 
 sprintf(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);

 //下面这里创建两个管道，用于两个进程间通信
 if (pipe(cgi_output) < 0) {
  cannot_execute(client);
  return;
 }
 if (pipe(cgi_input) < 0) {
  cannot_execute(client);
  return;
 }

 //创建一个子进程
 if ( (pid = fork()) < 0 ) {
  cannot_execute(client);
  return;
 }
 
 //子进程用来执行 cgi 脚本
 if (pid == 0)  /* child: CGI script */
 {
  char meth_env[255];
  char query_env[255];
  char length_env[255];

  //dup2()包含<unistd.h>中，参读《TLPI》P97
  //将子进程的输出由标准输出重定向到 cgi_ouput 的管道写端上
  dup2(cgi_output[1], 1);
  //将子进程的输出由标准输入重定向到 cgi_ouput 的管道读端上
  dup2(cgi_input[0], 0);
  //关闭 cgi_ouput 管道的读端与cgi_input 管道的写端
  close(cgi_output[0]);
  close(cgi_input[1]);
  
  //构造一个环境变量
  sprintf(meth_env, "REQUEST_METHOD=%s", method);
  //putenv()包含于<stdlib.h>中，参读《TLPI》P128
  //将这个环境变量加进子进程的运行环境中
  putenv(meth_env);
  
  //根据http 请求的不同方法，构造并存储不同的环境变量
  if (strcasecmp(method, "GET") == 0) {
   if (query_string[0] != '\0') {
     sprintf(query_env, "QUERY_STRING=%s", query_string);
   } else {
     sprintf(query_env, "QUERY_STRING=");
   }
   putenv(query_env);
  }
  else if (strcasecmp(method, "POST") == 0) {   /* POST */
   sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
   putenv(length_env);
  }
  
  // 在执行程序前先关闭client sock连接
  close(client);

  //execl()包含于<unistd.h>中，参读《TLPI》P567
  //最后将子进程替换成另一个进程并执行 cgi 脚本
  execl(path, path, NULL);
  exit(0);
  
 } else {    /* parent */
  //父进程则关闭了 cgi_output管道的写端和 cgi_input 管道的读端
  close(cgi_output[1]);
  close(cgi_input[0]);
  
  //如果是 POST 方法的话就继续读 body 的内容，并写到 cgi_input 管道里让子进程去读
  if (strcasecmp(method, "POST") == 0)
   for (i = 0; i < content_length; i++) {
    recv(client, &c, 1, 0);
    write(cgi_input[1], &c, 1);
   }
   
    char pipebuf[2048];
    //然后从 cgi_output 管道中读子进程的输出，并发送到客户端去
    ssize_t bytes_read;
    while ((bytes_read = read(cgi_output[0], pipebuf, sizeof(pipebuf) - 1)) > 0) {
        if (send(client, pipebuf, bytes_read, 0) <= 0) {
            printf("err: send pipe buf failed on client %d!\n", client);
            break;
        }
    }

  //关闭管道
  close(cgi_output[0]);
  close(cgi_input[1]);
  //等待子进程的退出
  waitpid(pid, &status, 0);
 }
#elif defined(__NXOS__)
  /* 创建一个双向管道 */
  NX_Solt pipe, child;
  char env[256];
  char *env_array[16];
  char meth_env[32];
  char length_env[32];
  int env_idx = 0;
  char query_env[255];

  /* 给子进程传入环境变量 */
  sprintf(meth_env, "REQUEST_METHOD=%s", method);
  env_array[env_idx++] = meth_env;

  if (strcasecmp(method, "GET") == 0) {
   if (query_string[0] != '\0') {
     sprintf(query_env, "QUERY_STRING=%s", query_string);
   } else {
     sprintf(query_env, "QUERY_STRING=");
   }
   env_array[env_idx++] = query_env;
  }
  else if (strcasecmp(method, "POST") == 0) {   /* POST */
   sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
   env_array[env_idx++] = length_env;
  }
  env_array[env_idx] = NX_NULL; // endof env

  NX_EnvToBuf(env, sizeof(env), env_array);

  pipe = NX_PipeCreate(NX_NULL, 4096, NX_PIPE_SEND | NX_PIPE_RECV);

  if (pipe == NX_SOLT_INVALID_VALUE)
  {
      NX_Printf("pipe create failed!\n");
      send_response(client, "500 Internal Server Error", "text/plain", "Create pipe failed");
      return;
  }

  /* 创建一个子进程，并重定向管道到标准输入输出 */
  child = NX_ProcessLaunch((char *)path, NX_THREAD_CREATE_SUSPEND, NX_NULL, (char *)path, env);
  if (child == NX_SOLT_INVALID_VALUE)
  {
      NX_SoltClose(pipe);
      send_response(client, "500 Internal Server Error", "text/plain", "Invalid CGI file");
      return;
  }

 sprintf(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);

  /* 重定向管道 */
  NX_Solt newPipeSolt = NX_SoltCopyTo(child, pipe, 0);
  if (newPipeSolt != 0)
    abort();
  newPipeSolt = NX_SoltCopyTo(child, pipe, 1);
  if (newPipeSolt != 1)
    abort();
  
  NX_ThreadResume(child);

  /* 如果是父进程，把数据写入管道 */
  if (strcasecmp(method, "POST") == 0)
   for (i = 0; i < content_length; i++) {
    NET_Recv(client, &c, 1, 0);
    NX_FileWrite(pipe, &c, 1);
  }

    char pipebuf[2048];
    //然后从 cgi_output 管道中读子进程的输出，并发送到客户端去
    ssize_t bytes_read;
    while ((bytes_read = NX_FileRead(pipe, pipebuf, sizeof(pipebuf) - 1)) > 0) {
        if (send(client, pipebuf, bytes_read, 0) <= 0) {
            printf("err: send pipe buf failed on client %d!\n", client);
            break;
        }
    }
  
  /* 关闭管道 */
  NX_SoltClose(pipe);

  /* 等待子进程退出 */
  NX_ThreadWait(child, NX_NULL);
#endif
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
 int i = 0;
 char c = '\0';
 int n;

 while ((i < size - 1) && (c != '\n'))
 {
  //recv()包含于<sys/socket.h>,参读《TLPI》P1259, 
  //读一个字节的数据存放在 c 中
  n = recv(sock, &c, 1, 0);
  /* DEBUG printf("%02X\n", c); */
  if (n > 0)
  {
   if (c == '\r')
   {
    //
    n = recv(sock, &c, 1, MSG_PEEK);
    /* DEBUG printf("%02X\n", c); */
    if ((n > 0) && (c == '\n'))
     recv(sock, &c, 1, 0);
    else
     c = '\n';
   }
   buf[i] = c;
   i++;
  }
  else
   c = '\n';
 }
 buf[i] = '\0';

 return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
 char buf[1024];

 char mime_type[128];
 get_mime_type(filename, mime_type, sizeof(mime_type)); // 假设有一个函数来获取MIME类型

 strcpy(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);
 strcpy(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: %s\r\n", mime_type);
 send(client, buf, strlen(buf), 0);
 strcpy(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "your request because the resource specified\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "is unavailable or nonexistent.\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</BODY></HTML>\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
#if defined(__UNIX__)
 FILE *resource = NULL;

  printf("Method: GET %s\n", filename);

 //打开这个传进来的这个路径所指的文件
 resource = fopen(filename, "r");
 if (resource == NULL)
  not_found(client);
 else
 {
  //打开成功后，将这个文件的基本信息封装成 response 的头部(header)并返回
  headers(client, filename);
  //接着把这个文件的内容读出来作为 response 的 body 发送到客户端
  cat(client, resource);
 }
 
 fclose(resource);
#elif defined(__NXOS__)
 NX_Solt resource;

  printf("Method: GET %s\n", filename);

 //打开这个传进来的这个路径所指的文件
 resource = NX_FileOpen(filename, NX_FILE_RDONLY, 0);
 if (resource == NX_SOLT_INVALID_VALUE)
  not_found(client);
 else
 {
  //打开成功后，将这个文件的基本信息封装成 response 的头部(header)并返回
  headers(client, filename);
  //接着把这个文件的内容读出来作为 response 的 body 发送到客户端
  cat(client, resource);
 }
 
 NX_FileClose(resource);
#endif
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(unsigned short *port)
{
 int httpd = 0;
 //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
 struct sockaddr_in name;
 
 //socket()用于创建一个用于 socket 的描述符，函数包含于<sys/socket.h>。参读《TLPI》P1153
 //这里的PF_INET其实是与 AF_INET同义，具体可以参读《TLPI》P946
 httpd = socket(PF_INET, SOCK_STREAM, 0);
 if (httpd == -1)
  error_die("socket");
  
 memset(&name, 0, sizeof(name));
 name.sin_family = AF_INET;
 //htons()，ntohs() 和 htonl()包含于<arpa/inet.h>, 参读《TLPI》P1199
 //将*port 转换成以网络字节序表示的16位整数
 name.sin_port = htons(*port);
 //INADDR_ANY是一个 IPV4通配地址的常量，包含于<netinet/in.h>
 //大多实现都将其定义成了0.0.0.0 参读《TLPI》P1187
 name.sin_addr.s_addr = htonl(INADDR_ANY);
 
 //bind()用于绑定地址与 socket。参读《TLPI》P1153
 //如果传进去的sockaddr结构中的 sin_port 指定为0，这时系统会选择一个临时的端口号
 if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
  error_die("bind");

#if USE_AUTO_PORT == 1
 //如果调用 bind 后端口号仍然是0，则手动调用getsockname()获取端口号
 if (*port == 0)  /* if dynamically allocating a port */
 {
  socklen_t namelen = sizeof(name);
  //getsockname()包含于<sys/socker.h>中，参读《TLPI》P1263
  //调用getsockname()获取系统给 httpd 这个 socket 随机分配的端口号
  if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
   error_die("getsockname");
  *port = ntohs(name.sin_port);
 }
#endif

 //最初的 BSD socket 实现中，backlog 的上限是5.参读《TLPI》P1156
 if (listen(httpd, 5) < 0) 
  error_die("listen");
 return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</TITLE></HEAD>\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</BODY></HTML>\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

static int server_sock = -1;

void handle_term(int signo)
{
  printf("term signo %d httpd sock %d\n", signo, server_sock);

  // close sock before exit
  shutdown(server_sock, SHUT_RDWR);
  sock_close(server_sock);
  exit(0);
}

#if USE_PIPE_SIGNAL == 1
void handle_sigpipe(int signo)
{
  printf("err: sigpipe %d happend!\n", signo);
}
#endif

#if USE_MULTI_THREAD_REQUEST == 1
#if defined(__UNIX__)
void *accept_request_thread(void *arg)
{
    accept_request((long)arg);
    return NULL;
}
#elif defined(__NXOS__)
NX_U32 accept_request_thread(void *arg)
{
    accept_request((long)arg);
    return 0;
}
#endif
#endif

int main(int argc, char *argv[])
{
#if USE_CMD_PORT == 1
 int opt;
#endif

 long client_sock = -1;
 //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
 struct sockaddr_in client_name;
 socklen_t client_name_len = sizeof(client_name);
#if USE_MULTI_THREAD_REQUEST == 1
 #if defined(__UNIX__)
 pthread_t newthread;
 #elif defined(__NXOS__)
 NX_Solt newthread;
 #endif
#endif

#if USE_CMD_PORT == 1
    // 解析命令行参数
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                server_port = atoi(optarg);
                if (server_port <= 0) {
                    fprintf(stderr, "Invalid port number\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
#endif

 server_sock = startup(&server_port);
 printf("httpd running on port %d\n", server_port);

  signal(SIGTERM, handle_term);
  signal(SIGINT, handle_term);

#if USE_PIPE_SIGNAL == 1
  signal(SIGPIPE, handle_sigpipe);
#endif

 while (1)
 {
  //阻塞等待客户端的连接，参读《TLPI》P1157
  client_sock = accept(server_sock,
                       (struct sockaddr *)&client_name,
                       &client_name_len);
  if (client_sock <= 0)
   error_die("accept");
#if USE_MULTI_THREAD_REQUEST == 1
 #if defined(__UNIX__)
  if (pthread_create(&newthread , NULL, accept_request_thread, (void *)client_sock) != 0)
   perror("pthread_create");
 #elif defined(__NXOS__)
  NX_ThreadAttr attr;
  NX_ThreadAttrInit(&attr, 16 * 1024, NX_THREAD_PRIORITY_NORMAL);
  newthread = NX_ThreadCreate(&attr, accept_request_thread, (void *)client_sock, 0);
  if (newthread == NX_SOLT_INVALID_VALUE)
   perror("pthread_create");
 #endif
//   printf("info: create thread %ld to handle request client %ld\n", newthread, client_sock);
#else
  accept_request(client_sock);
#endif
 }

 sock_close(server_sock);

 return(0);
}
