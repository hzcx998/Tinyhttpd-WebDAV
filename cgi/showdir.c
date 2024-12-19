#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <cgic.h>
#include <time.h>
#if defined(__UNIX__)
#include <dirent.h>
#include <sys/stat.h>
#elif defined(__NXOS__)
#include <nxos.h>
#else
#error unknown os!
#endif

// Function to get the icon based on file extension
const char* get_icon(const char* filename) {
#if defined(__UNIX__)
    struct stat statbuf;
    if (stat(filename, &statbuf) == -1) {
        return "/icons/unknown.gif";
    }

    if (S_ISDIR(statbuf.st_mode)) {
        return "/icons/folder.gif";
    }
#elif defined(__NXOS__)
    NX_FileStatInfo statbuf;
    if (NX_FileGetStatFromPath(filename, &statbuf) != NX_EOK) {
        return "/icons/unknown.gif";
    }
    if (NX_FILE_IS_DIR(statbuf.mode)) {
        return "/icons/folder.gif";
    }
#endif
    const char* ext = strrchr(filename, '.');
    if (!ext) {
        return "/icons/unknown.gif";
    }

    ext++; // Skip the dot
    if (strcmp(ext, "txt") == 0 || strcmp(ext, "doc") == 0 || strcmp(ext, "docx") == 0) {
        return "/icons/text.gif";
    } else if (strcmp(ext, "pdf") == 0) {
        return "/icons/pdf.gif";
    } else if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0 || strcmp(ext, "png") == 0 || strcmp(ext, "gif") == 0) {
        return "/icons/image.gif";
    }
    return "/icons/unknown.gif";
}

void urlDecode(const char *src, char *dst) {
    while (*src) {
        if (*src == '+') {
            *dst = ' ';
        } else if (*src == '%') {
            src++;
            if (*src && *(src + 1)) {
                int a = tolower((unsigned char)*src);
                int b = tolower((unsigned char)*(src + 1));
                *dst = (a >= 'a' ? a - 'a' + 10 : a - '0') * 16 + (b >= 'a' ? b - 'a' + 10 : b - '0');
                src++;
            }
        } else {
            *dst = *src;
        }
        src++;
        dst++;
    }
    *dst = '\0';
}

char* cgiUrlDecode(const char *src) {
    if (!src) return NULL;

    size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1); // +1 for null terminator
    if (!dst) return NULL;

    urlDecode(src, dst);
    return dst;
}

const char* cgiGetParam(const char* name, const char* defaultValue) {
    static char paramValue[255]; // 静态缓冲区以存储参数值
    memset(paramValue, 0 , sizeof(paramValue));
    cgiFormResultType result = cgiFormStringNoNewlines((char *)name, paramValue, sizeof(paramValue));
    if (result != cgiFormSuccess) {
        return defaultValue; // 如果参数不存在或获取失败，返回默认值
    }
    return paramValue; // 返回参数值
}

int cgiMain() {
    char rootdir[256];
    char prefix[128];

    cgiHeaderContentType("text/html; charset=UTF-8"); // Set the HTTP header

    printf("<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 3.2 Final//EN'>\n");
    printf("<html>\n");
    printf("    <head>\n");
    const char* url = cgiGetParam("url", "/");
    printf("        <title>Index of %s</title>\n", url);
    printf("        <meta charset='UTF-8'>\n");
    printf("    </head>\n");
    printf("    <body>\n");
    printf("        <h1>Index of %s</h1>\n", url);
    printf("        <table>\n");

    // Print the table headers
    printf("            <tr>\n");
    printf("                <th valign='top'><img src='/icons/blank.gif' alt='[ICO]'></th>\n");
    printf("                <th><a href='?C=N;O=D'>Name</a></th>\n");
    printf("                <th><a href='?C=M;O=A'>Last modified</a></th>\n");
    printf("                <th><a href='?C=S;O=A'>Size</a></th>\n");
    printf("                <th><a href='?C=D;O=A'>Description</a></th>\n");
    printf("            </tr>\n");
    printf("            <tr>\n");
    printf("                <th colspan='5'><hr></th>\n");
    printf("            </tr>\n");

    // Print the parent directory link
    printf("            <tr>\n");
    printf("                <td valign='top'><img src='/icons/back.gif' alt='[PARENTDIR]'></td>\n");
    printf("                <td><a href='../'>Parent Directory</a></td>\n");
    printf("                <td>&nbsp;</td>\n");
    printf("                <td align='right'>- </td>\n");
    printf("                <td>&nbsp;</td>\n");
    printf("            </tr>\n");

    strcpy(prefix, cgiGetParam("prefix", "htdocs"));
    snprintf(rootdir, sizeof(rootdir), "%s%s", prefix, cgiGetParam("url", "/"));

#if defined(__UNIX__)
    // Get the list of files and directories
    DIR* dir;
    struct dirent* entry;
    if ((dir = opendir(rootdir)) == NULL) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s%s", rootdir, entry->d_name);
        struct stat statbuf;
        stat(filepath, &statbuf);
        char last_modified[256];
        strftime(last_modified, sizeof(last_modified), "%Y-%m-%d %H:%M", localtime(&statbuf.st_mtime));
        const char* icon = get_icon(filepath);
        printf("            <tr>\n");
        printf("                <td valign='top'><img src='%s' alt='[FILE]'></td>\n", icon);
        if (S_ISDIR(statbuf.st_mode)) {
            printf("                <td><a href='%s/'>%s/</a></td>\n", entry->d_name, entry->d_name);
        } else {
            printf("                <td><a href='%s'>%s</a></td>\n", entry->d_name, entry->d_name);
        }
        printf("                <td align='right'>%s</td>\n", last_modified);
        if (S_ISDIR(statbuf.st_mode)) {
            printf("                <td align='right'>- </td>\n");
        } else {
            printf("                <td align='right'>%ld</td>\n", statbuf.st_size);
        }
        printf("                <td>&nbsp;</td>\n");
        printf("            </tr>\n");
    }
    closedir(dir);
#elif defined(__NXOS__)
    // Get the list of files and directories
    NX_Solt dir;
    NX_Dirent entry;
    
    if ((dir = NX_DirOpen(rootdir)) == NX_SOLT_INVALID_VALUE) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    while ((NX_DirRead(dir, &entry)) == NX_EOK) {
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s%s", rootdir, entry.name);
        NX_FileStatInfo statbuf;
        if (NX_FileGetStatFromPath(filepath, &statbuf) != NX_EOK) {
            NX_DirClose(dir);
            return -1; 
        }
        
        char last_modified[256];
        strftime(last_modified, sizeof(last_modified), "%Y-%m-%d %H:%M", localtime((const time_t *)&statbuf.mtime));
        const char* icon = get_icon(filepath);
        printf("            <tr>\n");
        printf("                <td valign='top'><img src='%s' alt='[FILE]'></td>\n", icon);
        if (NX_FILE_IS_DIR(statbuf.mode)) {
            printf("                <td><a href='%s/'>%s/</a></td>\n", entry.name, entry.name);
        } else {
            printf("                <td><a href='%s'>%s</a></td>\n", entry.name, entry.name);
        }
        printf("                <td align='right'>%s</td>\n", last_modified);
        if (NX_FILE_IS_DIR(statbuf.mode)) {
            printf("                <td align='right'>- </td>\n");
        } else {
            printf("                <td align='right'>%ld</td>\n", statbuf.size);
        }
        printf("                <td>&nbsp;</td>\n");
        printf("            </tr>\n");
    }
    NX_DirClose(dir);
#endif
    // Print the footer
    printf("            <tr>\n");
    printf("                <th colspan='5'><hr></th>\n");
    printf("            </tr>\n");
    printf("        </table>\n");
    printf("        <address>%s at %s Port %s</address>\n", "tinyhttpd/0.1.0", "127.0.0.1", cgiGetParam("port", "80"));
    printf("    </body>\n");
    printf("</html>\n");

    return 0;
}