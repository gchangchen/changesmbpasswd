#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>


//#include <systemd/sd-daemon.h>
#include <dlfcn.h>

#include "qs_parse.h"
#include "picohttpparser.h"

const char * const html_template =
{
	"<!DOCTYPE html>\n"
		"<html>\n"
		"	<head>\n"
		"		<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n"
		"		<title>Change Samba password</title>\n"
		"		<script language=\"javascript\">\n"
		"			function validate() {\n"
		"				var pwd1 = document.getElementById(\"newpassword\").value;\n"
		"				var pwd2 = document.getElementById(\"newpassword2\").value;\n"
		"				if (pwd1 != pwd2){\n"
		"					alert(\"Two input password must be consistent!\");\n"
		"					return false;\n"
		"				}\n"
		"				return true;\n"
		"			}\n"
		"		</script>\n"
		"	</head>\n"
		"	<body>\n"
		"		<h1>Change Samba password</h1><hr/>\n"
		"		<!--                                                                                            -->\n"
		"			<form name=\"changesmbpassword\" action=\"\" method=\"POST\" onSubmit=\"return validate();\">\n"
		"			<table>\n"
		"				<tr>\n"
		"					<td> username: </td>\n"
		"					<td> <input type=\"text\" name=\"username\" required=\"required\" value=\"\"> </td>\n"
		"				</tr>\n"
		"				<tr>\n"
		"					<td> old password: </td>\n"
		"					<td> <input type=\"password\" name=\"oldpassword\" required=\"required\" value=\"\"> </td>\n"
		"				</tr>\n"
		"				<tr>\n"
		"					<td> new password: </td>\n"
		"					<td> <input type=\"password\" id=\"newpassword\" name=\"newpassword\" required=\"required\" value=\"\"> </td>\n"
		"				</tr>\n"
		"				<tr>\n"
		"					<td> retype new  password: </td>\n"
		"					<td> <input type=\"password\" id=\"newpassword2\" required=\"required\" value=\"\"> </td>\n"
		"				</tr>\n"
		"				<tr>\n"
		"				</tr>\n"
		"				<tr>\n"
		"					<td colspan=\"2\">\n"
		"						<hr>\n"
		"						<input type=\"submit\" value=\"change password\">\n"
		"						<input type=\"reset\" value=\"reset form\">\n"
		"						<input type=\"button\" value=\"reload page\" onClick=\"window.location.href=window.location.href\">\n"
		"					</td>\n"
		"				</tr>\n"
		"		</form>\n"
		"		</p>\n"
		"	<body>\n"
		"</html>"
};

static int run_mode = 3; // cgi=0, scgi=1, nginx_scgi=2, http_response=3, 
static int client_fd = STDOUT_FILENO; 

static int response(const char*msg)
{
	char buf[8192];
	switch(run_mode){
		case 0:
			strcpy(buf, "Content-type:text/html\r\n\r\n");
			break;
		case 1:
			strcpy(buf, "Status: 200 OK\r\nContent-Type: text/html\r\n\r\n");
			break;
		case 2:
			strcpy(buf, "HTTP/1.1 200 OK\r\n\r\n");
			break;
		default:
			sprintf(buf, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n", strlen(html_template));
	}
	strcat(buf, html_template);
	if(msg != NULL && strlen(msg) > 0){
		char *p = strstr(buf, "<!--");
		int len = strstr(p, "-->") - p + 3;
		memset(p, ' ', len);
		memcpy(p, msg, strlen(msg));
	}
	return write(client_fd, buf, strlen(buf));
}

static int parse_scgi(const char *buf, size_t buf_len, int *content_length)
{
	*content_length = 0;
	if(buf == NULL)return -1;
	if(buf_len < 16)return -2;
	char *header_start = strchr(buf, ':');
	if(header_start == NULL)return -1;
	char temp[16] = {0};
	memcpy(temp, buf, header_start - buf);
	int headers_len = atoi(buf) + (header_start - buf) + 1;
	if(headers_len < 16 || headers_len > 4096)return -1;

	if(strcmp(header_start, ":CONTENT_LENGTH") != 0)return -1; 
	char *value = header_start + strlen(header_start) +1;
	*content_length = atoi(value);
	header_start = value + strlen(value) + 1;

	run_mode = 1; //scgi

	while(header_start < buf + headers_len){
		value = header_start + strlen(header_start) +1;
		if(strcmp(header_start, "SCGI") == 0){
			if(strcmp(value, "1") != 0)return -1; 
		}else if(strcmp(header_start, "REQUEST_METHOD") == 0){
			if(strcmp(value, "POST") != 0) *content_length = 0;
		}else if(strcmp(header_start, "NGINX_SCGI") == 0){
			run_mode = 2; //nginx_scgi
		}
		header_start = value + strlen(value) + 1;
	}
	return headers_len + 1;
}

static int client_handle(int client_sock)
{
	char buf[8192];
	const char *method, *path;
	int pret = -2, minor_version;
	struct phr_header headers[64];
	size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
	ssize_t rret;

	int content_length = 0;
	if(run_mode == 0){//cgi
		char *value = getenv("REQUEST_METHOD");
		if(value && strcmp(value, "POST") == 0){
			value = getenv("CONTENT_LENGTH");
			if(value)content_length = atoi(value);
		}
		pret = 0;
	}

	while(pret == -2){
		while ((rret = read(client_sock, buf + buflen, sizeof(buf) - buflen)) == -1 && errno == EINTR);
		if (rret <= 0) return -1;
		prevbuflen = buflen;
		buflen += rret;

		num_headers = sizeof(headers) / sizeof(headers[0]);
		pret = phr_parse_request(buf, buflen, &method, &method_len, &path, &path_len,
				&minor_version, headers, &num_headers, prevbuflen);
		if (pret > 0){
			run_mode = 3; //http
			if(method_len == 4 && strncmp(method, "POST", method_len) == 0){
				for (int i = 0; i != num_headers; ++i) {
					if(headers[i].name_len == strlen("Content-Length") &&
							strncmp(headers[i].name, "Content-Length", headers[i].name_len) == 0){
						content_length = atoi(headers[i].value);
						break;
					}
				}
			}
			break;
		}
		if (pret == -1){
			pret = parse_scgi(buf, buflen, &content_length);
			if(pret > 0){
				break;
			}
		}

		if(buflen == sizeof(buf))return -1;
	}

	if(content_length <= 0) return response("");
	while(content_length > buflen - pret){
		while ((rret = read(client_sock, buf + buflen, sizeof(buf) - buflen)) == -1 && errno == EINTR);
		if (rret <= 0) return -1;
		buflen += rret;
	}

	if(pret > 0)memmove(buf, buf+pret, content_length);
	buf[content_length] = '\0';
	//* @query_string = "username=xxx&oldpassword=xxx&newpassword=xxx"

	char username[256];
	char oldpassword[256];
	char newpassword[256];
	if ( qs_scanvalue("username", buf, username, sizeof(username)) == NULL
			|| qs_scanvalue("oldpassword", buf, oldpassword, sizeof(oldpassword)) == NULL
			|| qs_scanvalue("newpassword", buf, newpassword, sizeof(newpassword)) == NULL ){
		return response("Query string error!");
	}
	memset(buf, 0, sizeof(buf));

	struct passwd *pw = getpwnam(username);
	if(pw == NULL || pw->pw_uid < 100) return response("Username error!");
	int fildes[2][2];
	if(-1 == setuid(pw->pw_uid) /*|| -1 == setgid(pw->pw_gid)*/
			|| -1 == pipe(fildes[0]) || -1 == pipe(fildes[1])
	  )return response("Server internal error!");

	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	if (fork() == 0) { // i'm the child
		close(fildes[0][1]);
		close(fildes[1][0]);
		int fd = open("/dev/null", O_WRONLY);
		if(-1 == dup2(fildes[0][0], 0) || -1 == dup2(fildes[1][1], 2) || -1 == dup2(fd, 1)
				|| -1 == execlp( "smbpasswd", "smbpasswd", NULL)){
			perror("Server internal error!");
		}
		exit(0);
	}
	close(fildes[0][0]);
	close(fildes[1][1]);
	dprintf(fildes[0][1],"%s\n%s\n%s\n",oldpassword, newpassword, newpassword);
	while (rret = read(fildes[1][0], buf, sizeof(buf)) == -1 && errno == EINTR);
	if (rret < 0)return response("Server internal error!");
	close(fildes[0][1]);
	close(fildes[1][0]);
	return response(buf);
}

/*
 * Create net socket or unix socket server
 * @addr hostname or ip or NULL for net socket
 * 		or absolute path start with '/' for unix socket 
 * @port network port for net socket
 * 		or mode_t for unix socket file, see chmod for details.
 * 		if mode_t == 0, use 0666 instead.
 * @type SOCK_STREAM or SOCK_DGRAM
 * 		see getaddrinfo ai_socktype for details.
 * @return a listening socket.
 */
static int create_server(const char *addr, unsigned short port, int type)
{
	int listen_sock;
	if (addr == NULL || *addr != '/'){
		struct addrinfo hints;
		struct addrinfo *result, *rp;

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = type;
		hints.ai_flags = AI_PASSIVE;
		char buf[8];
		sprintf(buf, "%d", port);
		int s = getaddrinfo(addr, buf, &hints, &result);
		if (s != 0) {
			return -1;
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (listen_sock == -1) {
				continue;
			}

			int opt = 1;
			setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

			s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
			if (s == 0) {
				break;
			} else {
				close(listen_sock);
				listen_sock = -1;
			}
		}

		if (rp == NULL) {
			return -1;
		}

		freeaddrinfo(result);
	} else {
		//UNIX SOCKET
		listen_sock = socket(AF_UNIX, type, 0);
		if(listen_sock < 0) {
			return -1;
		}

		struct sockaddr_un sa;
		memset(&sa, 0, sizeof(sa));
		sa.sun_family = AF_UNIX;
		strncpy(sa.sun_path, addr, sizeof(sa.sun_path));

		unlink(addr);
		if (bind(listen_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			return -1;
		}
		if(port == 0)port = 0666;
		chmod(addr, port);
	}

	if(type == SOCK_STREAM && listen_sock >= 0){
		if(-1 == listen(listen_sock, SOMAXCONN)){
			close(listen_sock);
			listen_sock = -1;
		}
	}
	return listen_sock;
}

int main(int argc, char *argv[])
{

	int opt;
	int not_daemon = 0;
	int from_inetd = 0;
	const char *addr = NULL;
	int port = 0;
	while ((opt = getopt(argc, argv, "Dil:p:")) != -1) {
		switch (opt) {
			case 'D':
				not_daemon = 1;
				break;
			case 'i':
				from_inetd = 1;
				break;
			case 'l':
				addr = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			default: /* '?' */
				//-D      Not detach and does not become a daemon.
				//-i      Specifies that sshd is being run from inetd(8).
				//-l      listening host, like 0.0.0.0 or /var/run/unix.sock.
				//-p   	:port
				fprintf(stderr, "Usage: %s [-l addr] [-p port] [-i] [-D]\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if(from_inetd){
		run_mode = 3;
		client_fd = STDIN_FILENO;
		client_handle(client_fd);
		return 0;
	}

	void *handle = dlopen("libsystemd.so", RTLD_LAZY);
	int (*sd_listen_fds)(int) = NULL;
	if (handle) {
		sd_listen_fds = (int (*)(int)) dlsym(handle, "sd_listen_fds");
	}

	int listen_sock = 3; //SD_LISTEN_FDS_START;
	if (sd_listen_fds == NULL || (1 != sd_listen_fds(0))){
		if(addr == NULL && port == 0){
			run_mode = 0;
			client_fd = STDOUT_FILENO; 
			client_handle(STDIN_FILENO);
			return 0;
		}
		listen_sock = create_server(addr, port, SOCK_STREAM);
		if (listen_sock < 0)return -1;
	}

	if(not_daemon == 0) daemon(0, 0);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	while(1){
		int client_sock = accept(listen_sock, NULL, NULL);
		if(client_sock < 0)return -1;

		if (fork() == 0) { // i'm the child
			run_mode = 3;
			client_fd = client_sock;
			client_handle(client_sock);
			close(client_sock);
			exit(0);
		}
		close(client_sock);
	}

	return 0;
}

