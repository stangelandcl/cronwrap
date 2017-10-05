/* @(#) cronwrap.c 1.24@(#)
 *
 * Author: Scott Hamilton <sah@uow.edu.au>
 * Copyright 2001 University of Wollongong
 *
 * This file is part of Cronwrap.
 *
 * Cronwrap is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Cronwrap is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Foobar; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>


static char** process_arguments(int, char**);
static void usage();
static void run_command(char**, char**, char**, char**);
static void feedback(char*, char*, char*);
static void send_mail(char*, char*, char*);
static void write_log(char*, char*, char*);
static void alarm_handler(int);
static void default_handler(int);
static void my_fclose(FILE*);
static void my_close(int);
static void my_waitpid(pid_t, int*, int);
static void debug(char*, char*);
static void install_signal_handlers();
static void kill_process_group();
static void my_sigsend(idtype_t, id_t, int);
static void exit_after_signal(int);
static FILE* my_tmpfile();
static char* read_file(FILE *);
static FILE* my_fdopen(int, const char*);
static void my_fstat(int, struct stat*);
static void my_dup2(int, int);
static void* my_malloc(size_t);
static void* my_realloc(void *, size_t);
static FILE* my_fopen(const char*, const char*);
static void clear_logfiles();
static size_t nullp_strlen(const char *);

#ifndef DEBUG
#define DEBUG 0
#endif

static const char* version = "1.24";
static char* email_recipients = NULL;
static char* email_subject = NULL;
static char* logfile_name = NULL;
static char* clear_logs[64];
static int num_clear_logs = 0;
static int timeout = 0;
static int kill_after_timeout = 0;
static int ignore_stdout = 0;
static int ignore_stderr = 0;
static int ignore_exit_status[256];
static int num_ignore_exit_status = 0;
static FILE* child_stderr_fh;
static FILE* child_stdout_fh;
static pid_t pid = 0;


int main(int argc, char** argv)
{
	char** cmd;
	char* info_buf = NULL;
	char* stdout_buf = NULL;
	char* stderr_buf = NULL;

	debug("main", "entered");
	cmd = process_arguments(argc, argv);
	if (cmd != NULL) {
		run_command(cmd, &info_buf, &stdout_buf, &stderr_buf);
	}

	if ((info_buf != NULL && strlen(info_buf) != 0) ||
		(stdout_buf != NULL && strlen(stdout_buf) != 0) ||
		(stderr_buf != NULL && strlen(stderr_buf) != 0))
	{
		feedback(info_buf, stdout_buf, stderr_buf);
	}

	if (num_clear_logs != 0) {
		clear_logfiles();
	}
	return 0;
}


char** process_arguments(int argc, char** argv)
{
	char** cmd = NULL;
	int opt;
	int cmd_args_num = 0;
	int subject_len = 0;
	int i = 0;
	int es = 0;
	struct utsname uname_st;

	debug("process_arguments", "entered");

	/* exit status 0 is always ignored */
	ignore_exit_status[num_ignore_exit_status] = 0;
	num_ignore_exit_status++;

	/* get nodename for use in setting subject */
	if (uname(&uname_st) == -1) {
		perror("cronwrap: uname(2) failed");
		exit(1);
	}


	while ((opt = getopt(argc, argv, "r:t:s:l:L:x:oekVh")) != EOF) {

		switch(opt) {

			/* A comma seperated list of email addresses passed to mailx */
			case 'r':

				email_recipients = optarg;
				debug("process_arguments", "email_recipients:");
				debug("process_arguments", email_recipients);
				break;

			/* A timeout value in seconds */
			case 't':

				if (sscanf(optarg, "%d", &timeout) != 1) {

					(void)fprintf(stderr, "cronwrap: invalid value for option -t\n");
					usage();
					exit(1);
				}
				break;

			case 's':

				subject_len = strlen(argv[optind]) + SYS_NMLN
					+ 32;
				email_subject = (char*)my_malloc(sizeof(char) *
					subject_len);
				(void)snprintf(email_subject, subject_len,
					"%s cron output: %s",
					uname_st.nodename, optarg);
				break;

			case 'l':
				logfile_name = optarg;
				break;

			case 'L':
				clear_logs[num_clear_logs] = optarg;
				num_clear_logs++;
				break;

			case 'o':
				ignore_stdout = 1;
				break;

			case 'e':

				ignore_stderr = 1;
				break;

			case 'k':

				kill_after_timeout = 1;
				break;

			case 'V':

				(void)printf("Cronwrap version %s\n", version);
				exit(0);
				break;

			case 'x':	
				(void)sscanf(optarg, "%d", &es);
				ignore_exit_status[num_ignore_exit_status]
					= es;
				num_ignore_exit_status++;
				break;

			case 'h':
				usage();
				exit(0);
				break;
		}
	}

	if (email_recipients == NULL && logfile_name == NULL) {
		email_recipients = "root";
	}

	if (email_recipients == NULL && num_clear_logs != 0) {
		email_recipients = "root";
	}

	cmd_args_num = argc - optind;

	if (cmd_args_num == 0 && num_clear_logs == 0) {
		(void)fprintf(stderr, "cronwrap: no command specified\n");
		usage();
		exit(1);
	}

	if (email_subject == NULL && num_clear_logs == 0) {
		subject_len = strlen(argv[optind]) + SYS_NMLN + 32;
		email_subject = (char*)my_malloc(sizeof(char) * subject_len);
		(void)snprintf(email_subject, subject_len,
			"%s cron output: %s", uname_st.nodename, argv[optind]);
	}

	if (email_subject == NULL) {
		subject_len = strlen("cronwrap problem") + 1;
		email_subject = (char *)my_malloc(sizeof(char) * subject_len);
		(void)snprintf(email_subject, subject_len, "cronwrap problem");
	}

	if (cmd_args_num != 0) {
		cmd = calloc(cmd_args_num + 1, sizeof(char*));

		if (cmd == NULL) {
			perror("cronwrap: failed to allocated memory");
			exit(1);
		}

		for (i = 0; i < cmd_args_num; i++) {

			int length = strlen(argv[optind + i]) + 1;
			cmd[i] = calloc(length, sizeof(char));

			if (cmd[i] == NULL) {
				perror("cronwrap: failed to allocated memory");
				exit(1);
			}
			(void)strncpy(cmd[i], argv[optind + i], length);
		}
	}
	return cmd;
}


void usage()
{
	debug("usage", "entered");

	(void)fprintf(stderr, "usage: cronwrap [-s <subject>] [-r <recipient> ");
	(void)fprintf(stderr, "[,<recipient>  ...] ]\n       [-t <timeout secs>] ");
	(void)fprintf(stderr, "[-l <logfile path>] [-x <n> [-x <n>] ...]\n       ");
	(void)fprintf(stderr, "[-k] [-o] [-e] <cmd> [<cmd args> ...]\n\n");
	(void)fprintf(stderr, "usage: cronwrap [-s <subject] [-r <recipient> [,<recipient> ...] ]\n");
	(void)fprintf(stderr, "       -L <log file> [-L <log file> -L ...]\n\n");
	(void)fprintf(stderr, "-s <subject>: the subject line of any email sent\n");
	(void)fprintf(stderr, "-r <recipient>[,<recipient> ...]: email addresses.\n");
	(void)fprintf(stderr, "-t <timeout secs>: time within which ");
	(void)fprintf(stderr, "job should be complete. (default 900)\n");
	(void)fprintf(stderr, "-l <logfile path>: path and file name\n");
	(void)fprintf(stderr, "-k: terminate job if time out is reached.\n");
	(void)fprintf(stderr, "-x <n>: ignore exit status <n>.\n");
	(void)fprintf(stderr, "-o: ignore stdout.\n");
	(void)fprintf(stderr, "-e: ignore stderr.\n");
}


void run_command(char** cmd, char** info_buf, char** out_buf, char** err_buf)
{
	int wait_res = NULL;
	int exit_status = 0;
	int new_len = 0;
	int exit_sig_num = 0;
	int core_dumped = 0;
	int child_stderr_fd = -1;
	int child_stdout_fd = -1;
	int i = 0;
	int ignore = 0;

	char* information_buf = NULL;
	char* stdout_buf = NULL;
	char* stderr_buf = NULL;
	char exit_msg[48];
	char sig_msg[48];

	debug("run_command", "entered");

	child_stderr_fh = my_tmpfile();
	child_stdout_fh = my_tmpfile();
	child_stderr_fd = fileno(child_stderr_fh);
	child_stdout_fd = fileno(child_stdout_fh);

	pid = fork();

	if (pid == -1) {
		perror("cronwrap: failed to fork");
		exit(1);
	}

	/* child */
	if (pid == 0) {

		my_dup2(child_stdout_fd, STDOUT_FILENO);
		my_dup2(child_stderr_fd, STDERR_FILENO);
		(void)setpgrp(); /* give child its own process group */

		if (execvp(cmd[0], cmd) == -1) {
			perror("cronwrap: failed to execute command");
			exit(1);
		}
	}

	/* parent */
	else {
		install_signal_handlers();
		(void)alarm(timeout);
		my_waitpid(pid, &wait_res, NULL);

		if (WIFEXITED(wait_res)) {
			exit_status = WEXITSTATUS(wait_res);
		}

		if (WIFSIGNALED(wait_res)) {
			exit_sig_num = WTERMSIG(wait_res);
		}

		if (WCOREDUMP(wait_res)) {
			core_dumped = 1;
		}

		for (i = 0; i < num_ignore_exit_status && ignore == 0; i++) {
			if (exit_status == ignore_exit_status[i]) {
				debug("run command", "exit status ignored");
				ignore = 1;
			}
		}

		if (ignore != 1) {
			debug("run command", "exit status not ignored");
			(void)snprintf(exit_msg, 48, "Exit status = %d\n",
				exit_status);
			new_len = nullp_strlen(information_buf)
				+ strlen(exit_msg) + 1;
			information_buf = my_realloc(information_buf,
				new_len * sizeof(char));
			information_buf = strncat(information_buf, exit_msg,
				new_len);
		}

		if (exit_sig_num != 0) {
			(void)snprintf(sig_msg, 48,
				"Exited due to receipt of signal %d\n",
				exit_sig_num);
			new_len = nullp_strlen(information_buf)
				+ strlen(sig_msg) + 1;
			information_buf = my_realloc(information_buf,
				new_len * sizeof(char));
			information_buf = strncat(information_buf, sig_msg,
				new_len);
		}

		if (core_dumped != 0) {

			new_len = nullp_strlen(information_buf) + 13;
			information_buf = my_realloc(information_buf,
				new_len * sizeof(char));
			information_buf = strncat(information_buf, 
				"Core dumped\n", new_len);
		}

		if (ignore_stderr == 0) {
			stderr_buf = read_file(child_stderr_fh);
		}

		if (ignore_stdout == 0) {
			stdout_buf = read_file(child_stdout_fh);
		}

	}

	*info_buf = information_buf;
	*out_buf = stdout_buf;
	*err_buf = stderr_buf;
}


void feedback(char* info_buf, char* stdout_buf, char* stderr_buf)
{
	debug("feedback", "entered");

	if (logfile_name != NULL) {
		debug("send_mail", "calling write_log");
		write_log(info_buf, stdout_buf, stderr_buf);
	}

	if (email_recipients != NULL) {
		debug("send_mail", "calling send_mail");
		send_mail(info_buf, stdout_buf, stderr_buf);
	}
}


void send_mail(char* info_buf, char* stdout_buf, char* stderr_buf)
{
	char* mailer_cmd_line[] = { "/usr/bin/mailx", "-s", "", "", NULL };
	int fds[2];
	int exit_status = 0;
	int exit_sig_num = 0;
	int wait_res = NULL;
	pid_t pid;
	FILE* fh = NULL;

	debug("send_mail", "entered");

	mailer_cmd_line[2] = email_subject;
	mailer_cmd_line[3] = email_recipients;

	if (pipe(fds) != 0) {
		perror("cronwrap: failed to create pipe");
		exit(1);
	}

	pid = fork();

	if (pid == -1) {
		perror("cronwrap: failed to fork");
		exit(1);
	}

	/* child */
	if (pid == 0) {

		my_dup2(fds[0], STDIN_FILENO);
		my_close(fds[1]);

		if (execv(mailer_cmd_line[0], mailer_cmd_line) == -1) {
			perror("cronwrap: failed to execute /usr/bin/mailx");
			exit(1);
		}
	}

	/* parent */
	else {

		my_close(fds[0]);
		fh = my_fdopen(fds[1], "w");

		if (info_buf != NULL && strlen(info_buf) != 0) {

			if (fprintf(fh, "%s\n", info_buf) < 0) {
				perror("cronwrap: failed to write to mailx");
				exit(1);
			}
			debug("send_mail", "sending info_buf:");
			debug("send_mail", info_buf);
		}

		if (stdout_buf != NULL && strlen(stdout_buf) != 0) {

			if (fprintf(fh, "\nSTANDARD OUT:\n\n") < 0) {
				perror("cronwrap: failed to write to mailx");
				exit(1);
			}
			if (fprintf(fh, "%s\n", stdout_buf) < 0) {
				perror("cronwrap: failed to write to mailx");
				exit(1);
			}
			debug("send_mail", "sending stdout_buf");
			debug("send_mail", stdout_buf);
		}

		if (stderr_buf != NULL && strlen(stderr_buf) != 0) {

			if (fprintf(fh, "\nSTANDARD ERROR:\n\n") < 0) {
				perror("cronwrap: failed to write to mailx");
				exit(1);
			}
			if (fprintf(fh, "%s\n", stderr_buf) < 0) {
				perror("cronwrap: failed to write to mailx");
				exit(1);
			}
			debug("send_mail", "sending stderr_buf");
			debug("send_mail", stderr_buf);
		}
		my_fclose(fh);
		my_waitpid(pid, &wait_res, NULL);

		if (WIFEXITED(wait_res)) {
			exit_status = WEXITSTATUS(wait_res);

		}

		if (exit_status != 0) {
			/* must go to stdout because cron is likely to discard
			   stderr */
			(void)printf(
				"cronwrap: mailx return with exit status %d\n",
				exit_status);
		}

		if (WIFSIGNALED(wait_res)) {
			exit_sig_num = WTERMSIG(wait_res);
			/* must go to stdout because cron is likely to discard
			   stderr */
			(void)printf(
				"cronwrap: mailx exited due to receipt of signal %d",
				exit_sig_num);
		}
	}
	return;
}


void write_log(char* info_buf, char* stdout_buf, char* stderr_buf)
{
	char* time_str = NULL;
	time_t tas = 0;
	FILE* logh = NULL;

	tas = time(0);
	time_str = ctime(&tas);
	logh = my_fopen(logfile_name, "a");
	(void)fprintf(logh, "-----------------------------------------------------------------------\n");
	(void)fprintf(logh, "Time: %s", time_str);
	(void)fprintf(logh, "Command: %s\n", email_subject);

	if (info_buf != NULL) {

		if (fprintf(logh, "%s\n", info_buf) < 0) {
			perror("cronwrap: failed to write to log");
			exit(1);
		}
		debug("write_log", "writing info_buf:");
		debug("write_log", info_buf);
	}

	if (stdout_buf != NULL) {

		if (fprintf(logh, "\nSTANDARD OUT:\n") < 0) {
			perror("cronwrap: failed to write to log");
			exit(1);
		}
		if (fprintf(logh, "%s\n", stdout_buf) < 0) {
			perror("cronwrap: failed to write to log");
			exit(1);
		}
		debug("write_log", "writing stdout_buf:");
		debug("write_log", stdout_buf);
	}

	if (stderr_buf != NULL) {

		if (fprintf(logh, "\nSTANDARD ERROR:\n") < 0) {
			perror("cronwrap: failed to write to log");
			exit(1);
		}
		if (fprintf(logh, "%s\n", stderr_buf) < 0) {
			perror("cronwrap: failed to write to log");
			exit(1);
		}
		debug("write_log", "writing stderr_buf:");
		debug("write_log", stderr_buf);
	}
	my_fclose(logh);
}


char* read_fd_stream(int fd)
{
	char* buf = NULL;
	char c;
	int buflen = 0;
	int datacount = 0;
	FILE* fh = NULL;

	debug("read_fd_stream", "entered");

	fh = my_fdopen(fd, "r");
	buf = my_realloc(buf, (buflen + 256) * sizeof(char));
	buflen = 256;

	for (;;) {

		errno = 0;
		c = getc(fh);

		if (c == EOF && errno == EINTR) {
			debug("read_fd_stram",
			"continuing loop after getc() interupted. sigalrm?");
			continue;
		}
		else if (c == EOF && errno) {
			perror("cronwrap: error in getc");
			exit(1);
		}

		/* we're done reading */
		if (c == EOF && feof(fh)) {
			break;
		}

		if (buflen == datacount) {
			buf = my_realloc(buf, (buflen + 256) * sizeof(char));
			buflen += 256;
		}
		buf[datacount] = c;
		datacount++;
	}
	buf[datacount] = '\0';
	return buf;
}


static void alarm_handler(int signum)
{
	char* exceed_msg = "Process (pid %d) has exceeded running time of %d seconds.\n\nProcess left to run.";
	char* kill_msg = "Process (pid %d) has exceeded running time of %d seconds.\n\nProcess was killed.\n";
	char msg[100];

	debug("alarm_handler", "entered");

	if (signum != SIGALRM) {
		return;
	}

	if (kill_after_timeout == 1) {

		kill_process_group();
		(void)snprintf(msg, 100, kill_msg, pid, timeout);
		feedback(msg, NULL, NULL);
	}
	else {
		(void)snprintf(msg, 100, exceed_msg, pid, timeout);
		feedback(msg, NULL, NULL);
	}
}


void default_handler(int signum)
{
	char dmsg[80];

	debug("default_handler", "entered");
	(void)snprintf(dmsg, 80, "Parent has received a signal %d\n", signum); 
	debug("default_handler", dmsg);
	kill_process_group();
	exit(2);
}


void my_fclose(FILE *stream)
{
	int rv = 0;

	debug("my_fclose", "entered");

	rv = fclose(stream);

	if (rv != 0) {
			perror("cronwrap: error in fclose");
			exit(1);
	}
}


void my_close(int filedes)
{
	int rv = 0;

	debug("my_close", "entered");

	rv = close(filedes);

	if (rv != 0) {
		perror("cronwrap: failed to close file descriptor");
		exit(1);
	}
}


void my_waitpid(pid_t pid, int *stat_loc, int options)
{
	int rv = 0;

	debug("my_waitpid", "entered");

	do {
		rv = waitpid(pid, stat_loc, options);
	} while (rv == -1 && errno == EINTR);

	if (rv == -1) {
		perror("cronwrap: error ocurred waiting for child");
		exit(1);
	}
}


void debug(char* func_name, char* info_msg)
{
	int pid = -1;
	int pgrp = -1;
	int curr_time = -1;

	
	if (! DEBUG /*CONSTANTCONDITION*/) {
		return;
	}

	curr_time = (int)time(NULL);
	pid = (int)getpid();
	pgrp = (int)getpgrp();
	(void)fprintf(stderr, "time=%d pid=%d pgrp=%d func=%s msg=%s\n", curr_time,
		pid, pgrp, func_name, info_msg);
}


void install_signal_handlers()
{
	int sigs[] = { SIGHUP, SIGINT, SIGTERM, SIGPWR, SIGXCPU, SIGXFSZ, SIGPIPE };
	int num_sigs = sizeof(sigs) / sizeof(int);
	int i = 0;

	debug("install_signal_handlers", "entered");

	for (i = 0; i < num_sigs; ++i) {

		if (sigset(sigs[i], default_handler) == SIG_ERR) {
			perror("cronwrap: unable to install signal handler");
			exit(1);
		}
	}

	if (sigset(SIGALRM, alarm_handler) == SIG_ERR) {
		perror("cronwrap: unable to install SIGALRM handler");
		exit(1);
	}
}


void kill_process_group()
{
	/* the global 'pid' variable is the process id of the child and also the */
	/* process groupd id of that process group */

	debug("kill_process_group", "entered");
	my_sigsend(P_PGID, pid, SIGTERM);
	debug("kill_process_group", "sent child process group SIGTERM");
	(void)sleep(5);
	my_sigsend(P_PGID, pid, SIGKILL);
	debug("kill_process_group", "sent child process group SIGKILL");

	debug("kill_process_group", "giving parent 5 seconds to clean up");
	/* give parent 5 seconds to tidy up */
	if (sigset(SIGALRM, exit_after_signal) == SIG_ERR) {
		perror("cronwrap: unable to install SIGALRM handler");
		exit(1);
	}
	(void)alarm(5);
}


void my_sigsend(idtype_t idtype, id_t id, int sig)
{
	int rv = 0;

	debug("my_sigsend", "entered");
	rv = sigsend(idtype, id, sig);

	if (rv == -1 && errno != ESRCH) {
		perror("cronwrap: failed to sigsend()");
		exit(1);
	}
}


void exit_after_signal(int signum /*ARGSUSED*/)
{
	debug("exit_after_signal", "entered");
	exit(2);
}


FILE* my_tmpfile()
{
	FILE* fh;

	debug("my_tmpfile", "entered");

	fh = tmpfile();

	if (fh == NULL) {
		perror("cronwrap: failed to tmpfile()");
		exit(1);
	}
	return fh;
}


char* read_file(FILE* fh)
{
	char* buf = NULL;
	size_t items_read = 0;
	struct stat file_stats;
	
	debug("read_file", "entered");
	my_fstat(fileno(fh), &file_stats);
	buf = my_malloc(sizeof(char) * (file_stats.st_size + 1));
	
	if (fseek(fh, 0, SEEK_SET) == -1) {
		perror("cronwrap: failed fseek()");
		exit(1);
	}

	clearerr(fh);
	items_read = fread(buf, file_stats.st_size, 1, fh);

	if (items_read == 0 && ferror(fh)) {
		perror("cronwrap: failed to read file to memory");
		exit(1);
	}

	buf[file_stats.st_size] = '\0';
	debug("read_file", "finished reading file. file content is:");
	debug("read_file", buf);
	return buf;
}


FILE* my_fdopen(int fd, const char* mode)
{
	FILE* fh;

	debug("my_fdopen", "entered");
	fh = fdopen(fd, mode);

	if (fh == NULL) {
		perror("cronwrap: failed to create file stream");
		exit(1);
	}
	return fh;
}


void my_fstat(int fd, struct stat* buf)
{
	int rv = 0;

	debug("my_fstat", "entered");
	rv = fstat(fd, buf);

	if (rv == -1) {
		perror("cronwrap: failed to stat file descriptor");
		exit(1);
	}
}


void my_dup2(int fd1, int fd2)
{
	int rv = 0;

	debug("my_dup2", "entered");
	rv = dup2(fd1, fd2);

	if (rv == -1) {
		perror("cronwrap: failed to dup2()");
		exit(1);
	}
}


void* my_malloc(size_t size)
{
	void* mem = 0;
	mem = malloc(size);

	if (mem == NULL) {
		perror("cronwrap: failed to allocate memory");
		exit(1);
	}
	return mem;
}


void* my_realloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);

	if (ptr == NULL) {
		perror("cronwrap: failed to allocate memory");
		exit(1);
	}
	return ptr;
}


FILE* my_fopen(const char* filename, const char* mode)
{
	FILE* fh = NULL;
	char* errstr = NULL;
	int errstr_len = 0;
	fh = fopen(filename, mode);

	if (fh == NULL) {

		errstr_len = strlen(filename) + 48;
		errstr = my_malloc(sizeof(char) * errstr_len);
		(void)snprintf(errstr, errstr_len,
			"cronwrap: failed to open file %s", filename);
		perror(errstr);
		exit(1);
	}
	return fh;
}


void clear_logfiles()
{
	char *content = NULL;
	char *errstr = NULL;
	FILE* fh = NULL;
	int i = 0;
	int file_name_len = 0;
	int errstr_len = 0;
	struct stat file_stats;
	struct utsname uname_st;

	for (i = 0; i < num_clear_logs; i++) {

		fh = NULL;

		if (stat(clear_logs[i], &file_stats) == -1) {
			if (errno == ENOENT) {
				break;
			}
			else {
				errstr_len = strlen(clear_logs[i]) + 64;
				errstr = my_malloc(sizeof(char) * errstr_len);
				(void)snprintf(errstr, errstr_len,
					"cronwrap: problem with log file %s",
					clear_logs[i]);
				perror(errstr);
				exit(1);
			}
		}

		if (file_stats.st_size == 0) {
			break;
		}

		/* get nodename for use in setting subject */
		if (uname(&uname_st) == -1) {
			perror("cronwrap: uname(2) failed");
			exit(1);
		}

		file_name_len = strlen(clear_logs[i]) + SYS_NMLN + 32;
		free(email_subject);
		email_subject = (char*)my_malloc(sizeof(char) * file_name_len);
		(void)snprintf(email_subject, file_name_len,
			"%s cronwrap log: %s", uname_st.nodename,
			clear_logs[i]);

		fh = my_fopen(clear_logs[i], "r");
		content = read_file(fh);
		my_fclose(fh);
		/* truncate file to zero length */
		fh = my_fopen(clear_logs[i], "w");
		my_fclose(fh);
		send_mail(content, NULL, NULL);
		free(content);
	}
}


size_t nullp_strlen(const char *str)
{
	if (str == NULL) {
		return 0;
	}
	return strlen(str);
}
