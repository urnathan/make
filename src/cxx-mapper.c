/* C++ Module Mapper Machinery.  Experimental!
Copyright (C) 1988-2018 Free Software Foundation, Inc.
Written by Nathan Sidwell <nathan@acm.org> while at FaceBook

This file is part of GNU Make.

GNU Make is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.

GNU Make is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "makeint.h"
#include "os.h"
#include "filedef.h"
#include "variable.h"

#if defined (HAVE_SYS_WAIT_H) || defined (HAVE_UNION_WAIT)
# include <sys/wait.h>
#endif

#include <stdio.h>

#ifdef MAKE_CXX_MAPPER

/* Just presume these exist for now.  */
#define HAVE_AF_UNIX 1

#if defined (HAVE_AF_UNIX)
/* socket, bind, listen, accept{4}  */
# define NETWORKING 1
# include <sys/socket.h>
# ifdef HAVE_AF_UNIX
/* sockaddr_un  */
#  include <sys/un.h>
# endif
# include <netinet/in.h>
#endif

#include <sys/select.h>

static int sock_fd = -1;
static char *sock_name = NULL;
static char *sock_cookie = NULL;

/* Set bits in READERS for clients we're listening to.  */

int
mapper_pre_pselect (int hwm, fd_set *readers)
{
  if (sock_fd >=0)
    {
      FD_SET (sock_fd, readers);
      if (hwm < sock_fd)
	hwm = sock_fd;
    }
  return hwm;
}

/* Process bits in READERS for clients that have something for us.  */

int
mapper_post_pselect (int r, fd_set *readers)
{
  if (sock_fd >= 0 && FD_ISSET (sock_fd, readers))
    {
      r--;
      /* handle new connection.  */
    }
  return r;
}

pid_t
mapper_wait (int *status)
{
  int r;
  sigset_t empty;

  sigemptyset (&empty);
  for (;;)
    {
      fd_set readfds;
      int hwm = 0;

      FD_ZERO (&readfds);
      hwm = mapper_pre_pselect (0, &readfds);
      r = pselect (hwm + 1, &readfds, NULL, NULL, NULL, &empty);
      if (r < 0)
        switch (errno)
          {
          case EINTR:
	    {
	      /* SIGCHLD will show up as an EINTR.  We're in a loop,
		 so no need to EINTRLOOP here.  */
	      pid_t pid = wait (status);
	      if (pid > 0)
		return pid;
	    }
	    break;

          default:
            pfatal_with_name (_("pselect mapper"));
          }
      else
	r = mapper_post_pselect (r, &readfds);
    }
}

/* Non-zero if the mapper is running.  */

int
mapper_enabled (void)
{
  return sock_fd >= 0;
}

/* Setup a socket according to bound to the address OPTION.
   Listen for connections.
   Returns non-zero.  */

int
mapper_setup (const char *option)
{
  int err = 0;
  const char *errmsg = NULL;
  char *writable = xstrdup (variable_expand (option));
  size_t len;
#ifdef NETWORKING
  int af = AF_UNSPEC;
#ifdef HAVE_AF_UNIX
  struct sockaddr_un un;
  size_t un_len = 0;
#endif
#endif

  sock_cookie = strchr (writable, '?');
  if (sock_cookie)
    *sock_cookie++ = 0;
  len = strlen (writable);

  /* Does it look like a socket?  */
  if (writable[0] == '=')
    {
      /* A local socket.  */
#ifdef HAVE_AF_UNIX
      if (len < sizeof (un.sun_path))
	{
	  memset (&un, 0, sizeof (un));
	  un.sun_family = AF_UNIX;
	  memcpy (un.sun_path, writable + 1, len);
	}
      un_len = offsetof (struct sockaddr_un, sun_path) + len + 1;
      af = AF_UNIX;
#else
      errmsg = "unix protocol unsupported";
#endif
      sock_name = writable;
    }

  if (sock_name)
    {
#ifdef NETWORKING
      if (af != AF_UNSPEC)
	{
	  sock_fd = socket (af, SOCK_STREAM, 0);
	  if (sock_fd >= 0)
	    fd_noinherit (sock_fd);
	}
#endif
#ifdef HAVE_AF_UNIX
      if (un_len)
	if (sock_fd < 0 || bind (sock_fd, (struct sockaddr *)&un, un_len) < 0)
	  if (sock_fd >= 0)
	    {
	      close (sock_fd);
	      sock_fd = -1;
	    }
#endif
      if (sock_fd < 0 && !errmsg)
	{
	  err = errno;
	  errmsg = "binding socket";
	}

      /* I don't know what a good listen queue length might be.  */
      if (!errmsg && listen (sock_fd, 5))
	{
	  err = errno;
	  errmsg = "listening";
	}
    }

  if (sock_name && !errmsg)
    {
      const char *name = "CXX_MODULE_MAPPER";
      char *val = sock_name;
      struct variable *var;

      if (sock_cookie)
	val = xstrdup (concat (3, val, "?", sock_cookie));
      var = define_variable_global (name, strlen (name), val,
				    o_command, 0, NILF);
      var->export = v_export;
    }
  else
    {
      const char *arg;

      if (!errmsg)
	errmsg = "initialization";
      arg = (!sock_name ? "Option malformed"
	     : !err ? "Facility not provided" : strerror (err));
      error (NILF, strlen (errmsg) + strlen (option) + strlen (arg),
	     "failed %s of mapper `%s': %s", errmsg, option, arg);
      free (writable);
    }

  return 1;
}

void
mapper_clear (void)
{
  if (sock_fd >= 0)
    close (sock_fd);
  sock_fd = -1;
  if (sock_name && sock_name[0] == '=')
    unlink (sock_name + 1);
  free (sock_name);
  sock_name = NULL;
}

#endif /* MAKE_CXX_MAPPER */
