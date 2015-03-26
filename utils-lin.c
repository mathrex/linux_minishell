/**
 * Operating Sytems 2014 - Assignment 2
 *
 * Mini-shell
 *
 *	Bogdan Stoian
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1
#define ERR 		2

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (dir == NULL || dir->string == NULL)
		return true;
	
	if (chdir(dir->string) < 0)
		return false;

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit()
{

	return SHELL_EXIT;
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;
	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

int is_internal(const char *string) {

	return ((!strcmp(string, "cd")) || (!strcmp(string, "quit")) || (!strcmp(string, "exit")));
}
/*
 * @filedes  - file descriptor to be redirected
 * @filename - filename used for redirection
 * @access_mode - open file for reading or writing
 * @append = io_flags for appending
 */
static int do_redirect(int filedes, const char *filename, int append, int access_mode)
{
	int fd;

	/* Redirect filedes into fd representing filename */

	if (access_mode == READ) {
		fd = open (filename, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Cannot open %s \n for reading", filename);
			exit(EXIT_FAILURE);
		}
	}
	else
	if (!append)
		fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	else
		fd = open (filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0) {
		fprintf(stderr, "Error open file %s \n", filename);
		exit(EXIT_FAILURE);
	}
	dup2(fd,filedes);
	return fd;
}
/* Set the environment variable */
static void set_var(const char *name, const char *value)
{
	setenv(name, value, 111);
}
/* check if a list of word_t structures contains the string specified by word*/
static bool find(word_t* l, const char* word ) {

    while( l ) {
        if ( strcmp( get_word(l), word ) == 0 ) {
            return true;
        }
        l = l->next_word;
    }
    return false;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{

	pid_t pid;
	int status;
	char **argv;
	int argc;
	int fd, ret;
	bool  is_redirect_err = false, is_redirect_out = false;
	int old_fd_out, old_fd_err;
	char *verb_to_string;
	word_t * aux;

	/* sanity checks */
	if (s == NULL || s->verb == NULL)
		return 0;

	/* if builtin command, execute the command */
	if (is_internal(s->verb->string)) {

		/* redirect standard output, standard input and standard error if needed */
		if (s->out != NULL) {
			aux = s->out;
			while (aux != NULL) {

				if (aux->string != NULL) {
					if (is_redirect_out == false) {
						is_redirect_out = true;
						old_fd_out = dup(STDOUT_FILENO);
					}
					fd = do_redirect(STDOUT_FILENO, aux->string, s->io_flags, WRITE);
					/* if s->err contains this filename, redirect both stdout and stderr */
					if (find(s->err, aux->string) == true) {
						if (is_redirect_err == false) {
							is_redirect_err = true;
							old_fd_err = dup(STDERR_FILENO);
						}
						dup2(fd, STDERR_FILENO);
						
					}
				}
				aux = aux->next_word;
			}
		}
		if (s->err != NULL) {
			aux = s->err;
			while (aux != NULL) {
				if (aux->string != NULL) {
					/* redirect stderr if the stderr is not redirected to this file*/
					if(find(s->out, aux->string) == false) 
						if (is_redirect_err == false) {
							is_redirect_err = true;
							old_fd_err = dup(STDERR_FILENO);
						}
						do_redirect(STDERR_FILENO, aux->string, s->io_flags, WRITE);
				}
				aux = aux->next_word;
			}
			
		}

		if (!strcmp(s->verb->string, "cd")) {
			
			if (shell_cd(s->params) == true) 
				ret = 0;
			else
				ret = -1;
		}
		
		if (!strcmp(s->verb->string, "exit") || !strcmp(s->verb->string, "quit")) {
			ret = shell_exit();
		}
		/* if stdout or stderr are redirected, restore stdout and stderr to terminal*/
		if (is_redirect_out == true) {
			dup2(old_fd_out, STDOUT_FILENO);   
		}
		if (is_redirect_err == true)
			dup2(old_fd_err, STDERR_FILENO);
		return ret;
	}
	/* if variable assignment, execute the assignment and return
         * the exit status */
	verb_to_string = get_word(s->verb);
	if (strchr(verb_to_string, '=') != NULL) {
		/* get the name and the value of variable*/
		char *p1 = strtok(verb_to_string, "=");
		char *p2 = strtok(NULL, "\n");

		set_var(p1, p2);
		return 0;
	}

	/* if external command:
         *   1. fork new process
		 *     2c. perform redirections in child
         *     3c. load executable in child
         *   2. wait for child
         *   3. return exit status
	 */


	/* Create a process to execute the command */

	pid = fork();

	switch (pid) {
	case -1:
		/* error */
		return EXIT_FAILURE;
	case 0:
		/* child process */
		/* redirect standard output, standard input and standard error if needed */
		if (s->in != NULL) {

			while (s->in != NULL) {
				if (s->in->string != NULL)
					do_redirect(STDIN_FILENO, get_word(s->in), 0, READ);
				s->in = s->in->next_word;
			}
			
		}
		if (s->out != NULL) {
			aux = s->out;
			while (aux != NULL) {

				
				if (aux->string != NULL) {

					fd = do_redirect(STDOUT_FILENO, get_word(aux), s->io_flags, WRITE);

					if (find(s->err, get_word(aux)) == true) {
						dup2(fd, STDERR_FILENO);
						
					}
				}
				aux = aux->next_word;
			}
		}
		if (s->err != NULL) {

			while (s->err!= NULL) {
				if (s->err->string != NULL) {
					if(find(s->out, get_word(s->err)) == false) 
						do_redirect(STDERR_FILENO, get_word(s->err), s->io_flags, WRITE);
				}
				s->err = s->err->next_word;
			}
			
		}

		argv = get_argv(s, &argc);
		execvp(argv[0],argv);
 
		/* only if exec failed */
		printf("Execution failed for '%s'\n", argv[0]);
		exit(EXIT_FAILURE);
		break;
	default:

		break;
	}

	waitpid(pid, &status, 0);
	
 
	return WEXITSTATUS(status);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* execute cmd1 and cmd2 simultaneously */
	pid_t pid1, pid2;
	int status, ret1, ret2;
	pid1 = fork();

	switch (pid1) {
	case -1:
		/* error */
		return EXIT_FAILURE;
	case 0:
		/* child process for cmd1*/
		return parse_command(cmd1, level, father);
	default:
		/* parent process*/
		pid2 = fork();
		switch (pid2) {

			case -1:
				return EXIT_FAILURE;
			case 0:
				/* child process for cmd2*/	
				return parse_command(cmd2, level, father);
			default:
				break;
		}
	}
	/* waiting for child 1*/
	waitpid(pid1, &status, 0);
	ret1 = WEXITSTATUS(status);

	/* waiting for child 2*/
	waitpid(pid2, &status, 0);
	ret2 = WEXITSTATUS(status);
	
	if (!ret1 || !ret2)
		return true;

	return false;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */
	pid_t pid1, pid2;
	int status, ret1, ret2;
	int filedes[2];
	pid1 = fork();

	switch (pid1) {
		case -1:
			/* error */
			return EXIT_FAILURE;
		case 0:
			/* child process for cmd1*/
			if (pipe(filedes)< 0)
				exit(EXIT_FAILURE);
		
			pid2 = fork();

			switch (pid2) {
				case -1:
					return EXIT_FAILURE;

				case 0:
					/*child-cmd1 process for child-cmd2*/

					/*redirecting STDOUT to pipe and close unused read end  */
					close(filedes[0]);
					dup2(filedes[1], STDOUT_FILENO);
					exit(parse_command(cmd1, level, father));

				default:
					break;
				}
				/* parent of child-cmd1 process */

				/*redirecting STDIN to pipe and close unused write end  */
				close(filedes[1]);
				dup2(filedes[0], STDIN_FILENO);

				ret1 = parse_command(cmd2, level, father);
				/* waiting for child-cmd1*/
				waitpid(pid2, &status, 0);
				ret2 = WEXITSTATUS(status);
				exit(ret1 && ret2);
				break;
		default:
			break;
	}
	/* waiting for child-cmd2*/
	waitpid(pid1, &status, 0);
	ret1 = WEXITSTATUS(status);

	if (!ret1)
		return true;

	return false;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret1, ret2;

	/* sanity checks */
	if (c == NULL)
		return 0;

	if (c->op == OP_NONE) {
		/* execute a simple command */

		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* execute the commands one after the other */
	
		ret1 = parse_command(c->cmd1, level + 1, c);
		ret2 = parse_command(c->cmd2, level + 1, c);
		return (!ret1 || !ret2);

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		if (do_in_parallel(c->cmd1, c->cmd2, level + 1, c) == true)
			return 0;
		
		return -1;

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
                 * returns non zero */
		if (parse_command(c->cmd1, level + 1, c) != 0)
			return parse_command(c->cmd2, level + 1, c);


		return 0;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
                 * returns zero */
		if (parse_command(c->cmd1, level + 1, c) == 0)
			return parse_command(c->cmd2, level + 1, c);
		
		return -1;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second */
		if (do_on_pipe(c->cmd1, c->cmd2, level + 1, c) == true)
			return 0;
		return -1;

	default:
		assert(false);
	}

	return -1;
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

