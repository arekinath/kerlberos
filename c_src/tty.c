/*
%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.
*/

#include "erl_nif.h"
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

static ERL_NIF_TERM
open_tty(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	int fd;
	fd = open("/dev/tty", O_RDWR | O_NONBLOCK);
	if (fd < 0)
		return enif_make_badarg(env);
	return enif_make_int(env, fd);
}

static ERL_NIF_TERM
echo(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	int fd, ena;
	struct termios t;

	if (!enif_get_int(env, argv[0], &fd))
		return enif_make_badarg(env);
	if (!enif_get_int(env, argv[1], &ena))
		return enif_make_badarg(env);

	tcgetattr(fd, &t);
	if (ena)
		t.c_lflag |= ECHO;
	else
		t.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSANOW, &t);

	return enif_make_int(env, 0);
}

static ErlNifFunc nif_funcs[] =
{
	{"open_tty", 0, open_tty},
	{"echo", 2, echo}
};

ERL_NIF_INIT(tty, nif_funcs, NULL, NULL, NULL, NULL)
