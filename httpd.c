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
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
//#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"

void accept_request(int);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

char *prefix_dir = "htdocs";

// append index.html
int append_index = 0;

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

void handle_put(int client, const char *filepath) {
  printf("Method: PUT %s\n", filepath);

  int numchars;
  int content_length;
  char buf[1024];

  // 获取header其他部分
  numchars = get_line(client, buf, sizeof(buf));
  //这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
  //注意这里只读完 header 的内容，body 的内容没有读
  while ((numchars > 0) && strcmp("\n", buf))
  {
   buf[15] = '\0';
   if (strcasecmp(buf, "Content-Length:") == 0)
    content_length = atoi(&(buf[16])); //记录 body 的长度大小
   numchars = get_line(client, buf, sizeof(buf));
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
    const char *ext = strrchr(filename, '.');
    if (!ext) {
        strncpy(buf, "application/octet-stream", buf_size);  // 未知类型默认值
        buf[buf_size - 1] = '\0';  // 确保字符串以 NULL 结尾
        return;
    }

    for (int i = 0; mime_types[i].extension != NULL; ++i) {
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
    struct stat statbuf;
    if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
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

int generate_propfind_response_body(struct stat *statbuf, char *xml_response, int response_len, int offset, const char *path) {

  // 添加资源类型、创建日期、最后修改日期、ETag等属性
  char time_buffer[256];
  format_time(statbuf->st_mtime, time_buffer, sizeof(time_buffer));
  offset += snprintf(xml_response + offset, response_len - offset,
                      "<D:response>\n"
                      "<D:href>%s</D:href>\n"
                      "<D:propstat>\n"
                      "<D:prop>\n",
                      (path)); // 跳过路径的第一个字符，通常是 /

  // 检查是否是目录
  if (S_ISDIR(statbuf->st_mode)) {
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
                      ctime(&statbuf->st_ctime), // 创建时间
                      time_buffer, // 最后修改时间
                      statbuf->st_ino, // ETag第一部分：inode
                      (unsigned long)statbuf->st_size); // ETag第二部分：文件大小

  // 添加文件大小
  offset += snprintf(xml_response + offset, response_len - offset,
                   "<D:getcontentlength>%ld</D:getcontentlength>\n",
                   (long)statbuf->st_size);

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
int generate_propfind_response(char *xml_response, int response_len, const char *path) {
  struct stat statbuf;
  int offset = 0;

  if (stat(path, &statbuf) == -1) {
    return -1; 
  }

  // 添加响应头
  offset += snprintf(xml_response, response_len,
                      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                      "<D:multistatus xmlns:D=\"DAV:\">\n");

  offset = generate_propfind_response_body(&statbuf, xml_response, response_len, offset, path);

  // 结束multistatus元素
  offset += snprintf(xml_response + offset, response_len,
                      "</D:multistatus>\n");

  return offset;
}

static int propfind_dir(int client, char *response, int response_len, const char *filepath)
{
  DIR *dir;
  struct dirent *entry;
  char entry_path[1024];
  char mtime[64];
  int offset = 0;
  struct stat statbuf;

  dir = opendir(filepath);
  if (dir == NULL) {
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
      snprintf(entry_path, sizeof(entry_path), "%s/%s", filepath, entry->d_name);

      if (stat(entry_path, &statbuf) == -1) {
        closedir(dir);
        return -1; 
      }

      // 获取文件状态
      offset = generate_propfind_response_body(&statbuf, response, response_len, offset, entry_path);
  }

  offset += sprintf(response + offset, "</D:multistatus>");

  closedir(dir);

  return offset;
}

const char *parse_depth_header(const char *header) {
    if (header && strstr(header, "Depth:")) {
        // Depth: 0/1/infinity
        const char *depth = strstr(header, "Depth:") + 7;
        if (strncmp(depth, "0", 1) == 0) {
            return "0";
        } else if (strncmp(depth, "1", 1) == 0) {
            return "1";
        } else if (strncmp(depth, "infinity", 8) == 0) {
            return "infinity";
        }
    }
    return "infinity";  // 默认值
}

void handle_propfind(int client, const char *filepath) {
    struct stat file_stat;
    // TODO: 需要一个大缓冲区来保存响应报文。后续使用malloc分配
    static char response[1024 * 32];
    memset(response, 0, 1024 * 32);

    printf("Method: PROPFIND %s\n", filepath);

    /* 获取参数 */
    int numchars;
    const char *depth = "infinity";
    char buf[1024];

    // 获取header其他部分
    numchars = get_line(client, buf, sizeof(buf));
    //这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
    //注意这里只读完 header 的内容，body 的内容没有读
    while ((numchars > 0) && strcmp("\n", buf))
    {
        if (strncasecmp(buf, "Depth:", 6) == 0) {
            depth = parse_depth_header(buf); //记录 depth长度
        }
        numchars = get_line(client, buf, sizeof(buf));
    }
    
    //如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
    if (strcmp(depth, "infinity") == 0) {
        printf("Depth:%s not support\n", depth);

        snprintf(buf, 1024, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
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
                    "</D:multistatus>\n", filepath);

        send_response(client, "403 Forbidden", "application/xml; charset=\"utf-8\"", buf);
        return;
    }

    if (stat(filepath, &file_stat) == -1) {
        send_response(client, "404 Not Found", "text/plain", "File not found");
        return;
    }

    // 只有depth为1才返回目录，不然依然返回文件信息
    if (S_ISDIR(file_stat.st_mode) && strcmp(depth, "1") == 0) {
      if (propfind_dir(client, response, sizeof(response), filepath) == -1)
        return;
    } else {
      generate_propfind_response(response, sizeof(response), filepath);
    }

    send_response(client, "207 Multi-Status", "application/xml", response);
}

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

        if (S_ISDIR(statbuf.st_mode)) {
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

    if (S_ISDIR(statbuf.st_mode)) {
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


int handle_mkcol(int client, const char *path) {
    
    printf("Method: MKCOL %s\n", path);

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

const int parse_dest_path(const char *header, char *buf, int buflen) {
    if (header && strstr(header, PARM_MOVE_DEST)) {
        char *dest = strstr(header, PARM_MOVE_DEST) + sizeof(PARM_MOVE_DEST);
        char *path = is_remote_url(dest) ? extract_path_from_url(dest): dest;
        if (!path)
            return -1;

        snprintf(buf, buflen, "%s/%s", prefix_dir, path);
        return 0;
    }
    return -1;
}

int handle_move(int client, const char *path) {
    
    printf("Method: MOVE %s\n", path);

    /* 获取参数 */
    int numchars;
    char buf[1024];
    char dest[256] = {0};

    // 获取header其他部分
    numchars = get_line(client, buf, sizeof(buf));
    //这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
    //注意这里只读完 header 的内容，body 的内容没有读
    while ((numchars > 0) && strcmp("\n", buf))
    {
        if (strncasecmp(buf, PARM_MOVE_DEST, sizeof(PARM_MOVE_DEST)-1) == 0) {
            // buf 最后一个字符是'\n'，需要剔除
            buf[strlen(buf) - 1] = '\0';
            if (parse_dest_path(buf, dest, sizeof(dest))) {
                printf("MOVE: parse dest path %s faied\n", buf);
                send_response(client, "400 Bad Request", "text/plain", "Bad destination");
                return -1;
            }
        }
        memset(buf, 0, sizeof(buf));
        numchars = get_line(client, buf, sizeof(buf));
    }

    // 没有目标参数
    if (dest[0] == '\0') {
        send_response(client, "400 Bad Request", "text/plain", "No file destination");
        return -1;
    }

    // 检查目标文件是否已经存在
    if (access(dest, F_OK) == 0) {
        send_response(client, "409 Conflict", "text/plain", "File conflict");
        return -1;
    }

    if (rename(path, dest) == 0) {
        send_response(client, "200 OK", "text/plain", "Move file sucess");
    } else {
        send_response(client, "500 Internal Server Error", "text/plain", "Move file failed");
        return -1;
    }

    return 0;
}

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(int client)
{
 char buf[1024];
 int numchars;
 char method[255];
 char url[255];
 char path[512];
 size_t i, j;
 struct stat st;
 int cgi = 0;      /* becomes true if server decides this is a CGI
                    * program */
 char *query_string = NULL;
 int check_exist = 0;

 //读http 请求的第一行数据（request line），把请求方法存进 method 中
 numchars = get_line(client, buf, sizeof(buf));
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
    strcasecmp(method, "MOVE") && strcasecmp(method, "COPY"))
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

 if (strcasecmp(method, "DELETE") == 0 || strcasecmp(method, "MOVE") == 0 ||
    strcasecmp(method, "COPY") == 0)
 {
    check_exist = 1;
 }

 //将前面分隔两份的前面那份字符串，拼接在字符串htdocs的后面之后就输出存储到数组 path 中。相当于现在 path 中存储着一个字符串
 sprintf(path, "%s%s", prefix_dir, url);
 
 //如果 path 数组中的这个字符串的最后一个字符是以字符 / 结尾的话，就拼接上一个"index.html"的字符串。首页的意思
 if (append_index && path[strlen(path) - 1] == '/')
  strcat(path, "index.html");
 
 //在系统上去查询该文件是否存在
 if (stat(path, &st) == -1 && check_exist) {
  //如果不存在，那把这次 http 的请求后续的内容(head 和 body)全部读完并忽略
  while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
   numchars = get_line(client, buf, sizeof(buf));
  //然后返回一个找不到文件的 response 给客户端
  not_found(client);
 }
 else
 {
  //文件存在，那去跟常量S_IFMT相与，相与之后的值可以用来判断该文件是什么类型的
  //S_IFMT参读《TLPI》P281，与下面的三个常量一样是包含在<sys/stat.h>
  if (append_index && (st.st_mode & S_IFMT) == S_IFDIR)  
   //如果这个文件是个目录，那就需要再在 path 后面拼接一个"/index.html"的字符串
   strcat(path, "/index.html");
   
   //S_IXUSR, S_IXGRP, S_IXOTH三者可以参读《TLPI》P295
  if ((st.st_mode & S_IXUSR) ||       
      (st.st_mode & S_IXGRP) ||
      (st.st_mode & S_IXOTH)    ) {
        cgi = 1;
    //如果这个文件是一个可执行文件，不论是属于用户/组/其他这三者类型的，就将 cgi 标志变量置一
  }

  if (strcasecmp(method, "GET") == 0) { //如果不需要 cgi 机制的
    serve_file(client, path);
  } else if (strcasecmp(method, "PUT") == 0) {
    handle_put(client, path);
  } else if (strcasecmp(method, "PROPFIND") == 0) {
    handle_propfind(client, path);
  } else if (strcasecmp(method, "DELETE") == 0) {
    handle_delete(client, path);
  } else if (strcasecmp(method, "MKCOL") == 0) {
    handle_mkcol(client, path);
  } else if (strcasecmp(method, "MOVE") == 0) {
    handle_move(client, path);
  } else if (cgi) {
    //如果需要则调用
    execute_cgi(client, path, method, query_string);
  }

 }
 // disconnect first
  shutdown(client, SHUT_RDWR);
 close(client);
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
void cat(int client, FILE *resource)
{
 char buf[1024];

 //从文件文件描述符中读取指定内容
 fgets(buf, sizeof(buf), resource);
 while (!feof(resource))
 {
  send(client, buf, strlen(buf), 0);
  fgets(buf, sizeof(buf), resource);
 }
}

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
                 const char *method, const char *query_string)
{
 char buf[1024];
 int cgi_output[2];
 int cgi_input[2];
 pid_t pid;
 int status;
 int i;
 char c;
 int numchars = 1;
 int content_length = -1;
 
 //往 buf 中填东西以保证能进入下面的 while
 buf[0] = 'A'; buf[1] = '\0';
 //如果是 http 请求是 GET 方法的话读取并忽略请求剩下的内容
 if (strcasecmp(method, "GET") == 0)
  while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
   numchars = get_line(client, buf, sizeof(buf));
 else    /* POST */
 {
  //只有 POST 方法才继续读内容
  numchars = get_line(client, buf, sizeof(buf));
  //这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
  //注意这里只读完 header 的内容，body 的内容没有读
  while ((numchars > 0) && strcmp("\n", buf))
  {
   buf[15] = '\0';
   if (strcasecmp(buf, "Content-Length:") == 0)
    content_length = atoi(&(buf[16])); //记录 body 的长度大小
   numchars = get_line(client, buf, sizeof(buf));
  }
  
  //如果 http 请求的 header 没有指示 body 长度大小的参数，则报错返回
  if (content_length == -1) {
   bad_request(client);
   return;
  }
 }

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
   sprintf(query_env, "QUERY_STRING=%s", query_string);
   putenv(query_env);
  }
  else {   /* POST */
   sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
   putenv(length_env);
  }
  
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
   
  //然后从 cgi_output 管道中读子进程的输出，并发送到客户端去
  while (read(cgi_output[0], &c, 1) > 0)
   send(client, &c, 1, 0);

  //关闭管道
  close(cgi_output[0]);
  close(cgi_input[1]);
  //等待子进程的退出
  waitpid(pid, &status, 0);
 }
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
 (void)filename;  /* could use filename to determine file type */

 strcpy(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);
 strcpy(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
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
 FILE *resource = NULL;
 int numchars = 1;
 char buf[1024];

  printf("Method: GET %s\n", filename);

 //确保 buf 里面有东西，能进入下面的 while 循环
 buf[0] = 'A'; buf[1] = '\0';
 //循环作用是读取并忽略掉这个 http 请求后面的所有内容
 while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
  numchars = get_line(client, buf, sizeof(buf));

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
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(u_short *port)
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
  
 //如果调用 bind 后端口号仍然是0，则手动调用getsockname()获取端口号
 if (*port == 0)  /* if dynamically allocating a port */
 {
  int namelen = sizeof(name);
  //getsockname()包含于<sys/socker.h>中，参读《TLPI》P1263
  //调用getsockname()获取系统给 httpd 这个 socket 随机分配的端口号
  if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
   error_die("getsockname");
  *port = ntohs(name.sin_port);
 }
 
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
  printf("term httpd sock %d\n", server_sock);

  // close sock before exit
  shutdown(server_sock, SHUT_RDWR);
  close(server_sock);
  exit(0);
}

int main(void)
{
 u_short port = 8080;
 int client_sock = -1;
 //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
 struct sockaddr_in client_name;
 int client_name_len = sizeof(client_name);
 //pthread_t newthread;

 server_sock = startup(&port);
 printf("httpd running on port %d\n", port);

  signal(SIGTERM, handle_term);
  signal(SIGINT, handle_term);

 while (1)
 {
  //阻塞等待客户端的连接，参读《TLPI》P1157
  client_sock = accept(server_sock,
                       (struct sockaddr *)&client_name,
                       &client_name_len);
  if (client_sock == -1)
   error_die("accept");
  accept_request(client_sock);
 /*if (pthread_create(&newthread , NULL, accept_request, client_sock) != 0)
   perror("pthread_create");*/
 }

 close(server_sock);

 return(0);
}
