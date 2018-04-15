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

//#include <systemd/sd-daemon.h>
#include <dlfcn.h>

#include "qs_parse.h"

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
	"		<h1>Change Samba password</h1>\n"
	"		<hr/><form name=\"changesmbpassword\" action=\"\" method=\"POST\" onSubmit=\"return validate();\">\n"
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

/*
 * use stdin to get query_string
 * use stdout to resqonse
 * @content_length = strlen(query_string)
 * @type cgi=0, scgi=1, nginx_scgi=2
 * @is_post 0=get 1=post
*/
static void do_smbpasswd(size_t content_length, int type, int is_post)
{
	char response[8192];
	if(type == 1){//scgi
		strcpy(response, "Status: 200 OK\r\nContent-Type: text/html\r\n\r\n");
	}else if(type == 2){//nginx scgi
		strcpy(response, "HTTP/1.1 200 OK\r\n\r\n");
	}else{//CGI reqponse
		strcpy(response, "Content-type:text/html\r\n\r\n");
	}
	strcat(response, html_template);

	if(is_post == 0 || content_length == 0){
		write(STDOUT_FILENO, response, strlen(response));
		return;
	}

 //* @query_string = "username=xxx&oldpassword=xxx&newpassword=xxx"
	char buf[4096];
	if(content_length > sizeof(buf)-1)return;
	int readed = 0;
	while(readed < content_length){
		ssize_t ret = read(STDIN_FILENO, buf + readed, content_length - readed);
		if(ret <=0 )break;
		readed += ret;
	}
	if(readed < content_length)return;
	buf[content_length] = '\0';

	char *f = strstr(response, "<form ");
	*f = '\0';

	char username[256];
	char oldpassword[256];
	char newpassword[256];
	if ( qs_scanvalue("username", buf, username, sizeof(username)) == NULL
			|| qs_scanvalue("oldpassword", buf, oldpassword, sizeof(oldpassword)) == NULL
			|| qs_scanvalue("newpassword", buf, newpassword, sizeof(newpassword)) == NULL ){
		strcat(response, "Query string error!");
	}else{
		struct passwd *pw = getpwnam(username);
		if(pw == NULL || pw->pw_uid < 100){
			strcat(response, "Username error!");
		}else if(-1 == setuid(pw->pw_uid) /*|| -1 == setgid(pw->pw_gid)*/
				|| -1 == dup2(STDOUT_FILENO, STDERR_FILENO)){
			strcat(response, "Server internal error!");
		}
	}
	if(strlen(response) != write(STDOUT_FILENO, response, strlen(response))){
		return;
	}
	if(*f == '\0'){
		FILE *smbpipe = popen("smbpasswd","w");
		if(smbpipe){
			fprintf(smbpipe,"%s\n%s\n%s\n",oldpassword, newpassword, newpassword);
			pclose(smbpipe);
		}
	}
	f = strstr(html_template, "<hr/><form ");
end:
	write(STDOUT_FILENO, f, strlen(f));
	return;
}

static void cgi_handle(void)
{
	char *value = getenv("REQUEST_METHOD");
	if(!value)return;
	int is_post = (strcmp(value, "POST") == 0);
	size_t content_length = 0;
	if(is_post){
		value = getenv("CONTENT_LENGTH");
		if(!value)return;
		content_length = atoi(value);
	}
	signal(SIGCHLD, SIG_IGN);
	do_smbpasswd(content_length, 0, is_post);
	return;
}

static void scgi_handle(int client_sock)
{
	unsigned char buf[4096];
	ssize_t readed = 0;
	ssize_t headers_len = 16;
	unsigned char *header_start = NULL;
	do{
		ssize_t ret = read(client_sock, buf + readed, headers_len - readed);
		if(ret <=0 )break;
		readed += ret;
		if(!header_start){
			header_start = strchr(buf, ':');
			if(!header_start)break;
			*header_start = '\0';
			header_start++;
			headers_len = atoi(buf) + (header_start - buf) + 1;
			if(headers_len < 16 || headers_len > sizeof(buf))break;
		}
	} while(readed < headers_len);
	if(readed < headers_len)return;
	buf[headers_len -1] = '\0';

	if(strcmp(header_start, "CONTENT_LENGTH") != 0)return; 
	unsigned char *value = header_start + strlen(header_start) +1;
	size_t content_length = atoi(value);
	header_start = value + strlen(value) + 1;

	int is_post = 0;
	int is_nginx = 0;
	while(header_start < buf + headers_len){
		value = header_start + strlen(header_start) +1;
		if(strcmp(header_start, "SCGI") == 0){
		   	if(strcmp(value, "1") != 0)return; 
		}else if(strcmp(header_start, "REQUEST_METHOD") == 0){
		   	if(strcmp(value, "POST") == 0)is_post = 1;
		}else if(strcmp(header_start, "NGINX_SCGI") == 0){
			is_nginx = 1;
		}
		header_start = value + strlen(value) + 1;
	}

	dup2(client_sock, STDIN_FILENO);
	dup2(client_sock, STDOUT_FILENO);
	do_smbpasswd(content_length, is_nginx ? 2 : 1, is_post);
	return;
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
	void *handle = dlopen("libsystemd.so", RTLD_LAZY);
	int (*sd_listen_fds)(int) = NULL;
	if (handle) {
		sd_listen_fds = (int (*)(int)) dlsym(handle, "sd_listen_fds");
	}

	int listen_sock = 3; //SD_LISTEN_FDS_START;
	if (sd_listen_fds == NULL || (1 != sd_listen_fds(0))){
		if(argc < 2){
			cgi_handle();
			return 0;
		}
		int port = atoi(argv[ argc -1 ]);
		if(argc > 2 || port == 0){
			listen_sock = create_server(argv[1], port, SOCK_STREAM);
		}else{
			listen_sock = create_server(NULL, port, SOCK_STREAM);
		}
		if (listen_sock < 0)return -1;
	}

	daemon(0, 0);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	while(1){
		int client_sock = accept(listen_sock, NULL, NULL);
		if(client_sock < 0)return -1;

		if (fork() == 0) { /* i'm the child */
			scgi_handle(client_sock);
			close(client_sock);
			exit(0);
		}
		close(client_sock);
	}

	return 0;
}

