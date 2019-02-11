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

/* Experimental component to deal with C++ modules.  Perhaps a more
   general plugin archicture is needed to make this acceptable?  Let's
   at least get it to work first.  */

/* Only local connections for now -- unlike GCC's mapper example,
   which also permits ipv6.
   Error behaviour is rather abrupt, and incomplete.  */

#include "makeint.h"
#include "os.h"
#include "filedef.h"
#include "variable.h"
#include "dep.h"
#include "job.h"
#include "rule.h"
#include "debug.h"

#if defined (HAVE_SYS_WAIT_H) || defined (HAVE_UNION_WAIT)
# include <sys/wait.h>
#endif

#include <stdarg.h>
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

/*
  C++.PREFIX := {repodir/pfx}

  # module name-> bmi name mapping
  # C++.{modulename} : {bminame} ; @#nop
  %.c++m : $(C++.PREFIX)%.gcm ;
  "%".c++m : $(C++.PREFIX)%.gcmu ;
  <%>.c++m : $(C++.PREFIX)%.gcms ;

  ## bmi dependency:
  # {bminame} : {sources} | objectname
  # {bminame} : {sources} ; CCrule
  
  $(C++.PREFIX)%.gcm : %.cc | %.o ;
  $(C++.PREFIX)%.gcmu : % ; $(COMPILE.cc) -fmodule-legacy='"$*"' $<
  $(C++.PREFIX)%.gcms : % ; $(COMPILE.cc) -fmodule-legacy='<$*>' $<
 */

#define MAPPER_VERSION 0

#define LEGACY_VAR "CXX_MODULE_LEGACY"
#define MAPPER_VAR "CXX_MODULE_MAPPER"
#define MODULE_SUFFIX "c++m"
#define BMI_SUFFIX "gcm"

enum response_codes
{
  CC_HANDSHAKE,
  CC_IMPORT,
  CC_INCLUDE,
  CC_EXPORT,
  CC_DONE,
  CC_ERROR,
  CC_TRANSLATE,
};

struct client_request
{
  enum response_codes code : 8;
  unsigned waiting : 8;
  const char *resp;
  struct file *file;
};

struct client_state 
{
  struct child *job;  /* The job this is for.  */

  char *buf;
  size_t buf_size;
  size_t buf_pos;

  unsigned cix;
  int fd;

  int reading : 1;  /* Filling read buffer.  */
  int bol : 1;
  int last : 1;
  int corking : 16;  /* number of lines, if corked.  */

  struct client_request *requests;
  unsigned num_requests;
  unsigned num_awaiting;
};

static int sock_fd = -1;
static char *sock_name = NULL;
static struct client_state **clients = NULL;
static unsigned num_clients = 0;
static unsigned alloc_clients = 0;
static unsigned waiting_clients = 0;

/* Set up a new connection.  */
static void
new_client (void)
{
  static unsigned factory = 0;

  struct client_state *client;
  int client_fd = accept (sock_fd, NULL, NULL);
  if (client_fd < 0)
    {
      mapper_clear ();
      return;
    }

  client = xmalloc (sizeof (*client));
  memset (client, 0, sizeof (*client));
  client->cix = ++factory;
  client->job = NULL;  /* Discovered during handshake.  */
  client->fd = client_fd;
  client->reading = 1;
  client->buf_size = 10; /* Exercise expansion.  */
  client->buf = xmalloc (client->buf_size);

  client->buf_pos = 0;
  client->bol = 1;
  client->last = client->corking = 0;
  client->num_requests = client->num_awaiting = 0;
  client->requests = NULL;

  if (num_clients == alloc_clients)
    {
      alloc_clients = (alloc_clients ? alloc_clients : 10) * 2;
      clients = xrealloc (clients, alloc_clients * sizeof (*clients));
    }

  DB (DB_PLUGIN, ("module:%u connected\n", client->cix));

  clients[num_clients++] = client;
}

static void
delete_client (struct client_state *client, unsigned slot)
{
  DB (DB_PLUGIN, ("module:%u destroyed\n", client->cix));
  close (client->fd);
  free (client->buf);
  free (client->requests);
  free (client);

  if (slot + 1 != num_clients)
    clients[slot] = clients[num_clients-1];
  clients[--num_clients] = NULL; /* Make unreachable.  */
}

static void
client_print (struct client_state *client, const char *fmt, ...)
{
  size_t actual;
  if (client->corking)
    client->buf[client->buf_pos++] = '+';

  for (;;)
    {
      va_list args;
      size_t space;

      va_start (args, fmt);
      space = client->buf_size - client->buf_pos;
      actual = vsnprintf (client->buf + client->buf_pos, space, fmt, args);
      va_end (args);
      /* Guarantee 3 trailing elts.  */
      if (actual + 3 <= space)
	break;
      client->buf_size *= 2;
      client->buf = xrealloc (client->buf, client->buf_size);
      if (actual < space)
	break;
    }
  DB (DB_PLUGIN, ("module:%u sending '%.*s'\n",
		  client->cix, (int)(actual + client->corking),
		  &client->buf[client->buf_pos - client->corking]));
  client->buf_pos += actual;
  client->buf[client->buf_pos++] = '\n';
}

static char *
client_token (struct client_state *client)
{
  char *ptr = &client->buf[client->buf_pos];
  char *token = ptr;

  token = ptr;
  while (*ptr && !isblank (*ptr))
    ptr++;

  if (token == ptr)
    token = NULL;
  else if (*ptr)
    {
      *ptr++ = 0;
      while (isblank (*ptr))
	ptr++;
    }

  client->buf_pos = ptr - client->buf;
  return token;
}

/* Generate the BMI name from the dependency of file, removing the
   prefix.   */

static const char *
bmi_name (struct file *file)
{
  /* Not a rule-specific expansion.  */
  char *repo = variable_expand ("$(.C++.PREFIX)");
  const char *name = file->deps->file->name;
  size_t len = strlen (repo);

  if (strlen (name) > len && !memcmp (repo, name, len))
    name += len;

  return name;
}

static int
client_parse (struct client_state *client)
{
  char *token;
  struct client_request *resp = &client->requests[client->num_requests];
  unsigned req = CC_ERROR;

  resp->waiting = 0;
  resp->file = NULL;
  resp->resp = "Unknown request";

  DB (DB_PLUGIN, ("module:%u processing '%s'\n",
		  client->cix, &client->buf[client->buf_pos]));
  if (client->buf[client->buf_pos] == '+'
      || client->buf[client->buf_pos] == '-')
    client->buf_pos++;

  token = client_token (client);
  if (!token)
    {
      client->buf_pos++;
      return 1;
    }
  else if (!client->job)
    {
      if (!strcmp (token, "HELLO"))
	{
	  /* HELLO $version $compiler $cookie  */
	  const char *ver = client_token (client);
	  const char *compiler = ver ? client_token (client) : NULL;
	  char *ident = &client->buf[client->buf_pos];
	  char *e = ident;
	  unsigned long cookie = ident ? strtoul (ident, &e, 0) : 0;
	  struct child *job = ident && !*e
	    ? find_job_by_cookie ((void *)cookie) : NULL;

	  (void)compiler;
	  if (!job)
	    resp->resp = "Cannot find matching job";
	  else
	    {
	      client->job = job;
	      req = CC_HANDSHAKE;
	    }
	}
      else
	resp->resp = "Expected handshake";
    }
  else
    {
      /* Same order as enum response_codes.  */
      static const char *const words[] = 
	{
	  "IMPORT",  /* IMPORT $modulename  */
	  "INCLUDE", /* INCLUDE $includefile  */
	  "EXPORT",  /* EXPORT $modulename  */
	  "DONE",    /* DONE $modulename  */
	  NULL
	};

      for (req = CC_IMPORT; req != CC_ERROR; req++)
	if (!strcmp (token, words[req-CC_IMPORT]))
	  {
	    char *operand = client_token (client);
	    if (!operand)
	      {
		req = CC_ERROR;
		resp->resp = "Malformed request";
		break;
	      }
	    else
	      {
		/* look for a target called {modulename}.{MODULE_SUFFIX}  */
		size_t len = strlen (operand);
		char *target_name = xmalloc (len + 2 + strlen (MODULE_SUFFIX));
		struct file *f;

		memcpy (target_name, operand, len);
		strcpy (target_name + len, "." MODULE_SUFFIX);

		f = lookup_file (target_name);
		if (req == CC_INCLUDE)
		  {
		    // FIXME: think about remapping.
		    if (f)
		      req = CC_TRANSLATE;
		    resp->resp = "";
		    break;
		  }

		if (req == CC_DONE)
		  {
		    /* Ignore DONE for the moment.  */
		    break;
		  }

		if (!f)
		  {
		    f = enter_file (strcache_add (target_name));
		    f->last_mtime = NONEXISTENT_MTIME;
		    f->mtime_before_update = NONEXISTENT_MTIME;
		  }

		f->phony = 1;
		f->is_target = 1;
		if (!f->deps)
		  try_implicit_rule (f, 0);
		if (req == CC_IMPORT)
		  {
		    // FIXME: loop detection
		  }
		free (target_name);

		/* There should be exactly one dependency.  */
		if (!f->deps)
		  {
		    resp->resp = "Unknown module name";
		    req = CC_ERROR;
		  }
		else if (f->deps->next)
		  {
		    resp->resp = "Ambiguous module name";
		    req = CC_ERROR;
		  }
		else if (req == CC_EXPORT
			 || f->command_state == cs_finished)
		  // FIXME: note of build failing?
		  resp->resp = bmi_name (f);
		else
		  {
		    if (!f->mapper_target)
		      {
			f->deps->file->precious = 1;
			add_mapper_goal (f);
		      }
		    resp->file = f;
		    resp->waiting = 1;
		    client->num_awaiting++;
		  }
		break;
	      }
	  }
    }

  resp->code = req;
  client->num_requests++;

  while (client->buf[client->buf_pos])
    client->buf_pos++;
  client->buf_pos++;

  return 1;
}

static void
client_write (struct client_state *client, unsigned slot)
{
  unsigned ix;

  client->buf_pos = 0;
  client->corking = client->num_requests > 1;

  for (ix = 0; ix != client->num_requests; ix++)
    {
      struct client_request *req = &client->requests[ix];

      switch (req->code)
	{
	case CC_HANDSHAKE:
	  {
	    char *repo = variable_expand ("$(.C++.PREFIX)");
	    client_print (client, "HELLO %u GNUMake %s", MAPPER_VERSION, repo);
	  }
	  break;

	case CC_ERROR:
	  client_print (client, "ERROR %s", req->resp);
	  break;

	case CC_INCLUDE:
	  client_print (client, "INCLUDE %s", req->resp);
	  break;

	case CC_TRANSLATE:
	  client_print (client, "IMPORT %s", req->resp);
	  break;
	  
	case CC_IMPORT:
	case CC_EXPORT:
	  client_print (client, "OK %s", req->resp);
	  break;

	case CC_DONE:;
	}
    }

  free (client->requests);
  client->requests = NULL;
  client->num_requests = client->num_awaiting = 0;

  if (client->buf_pos)
    {
      ssize_t bytes;

      if (client->corking)
	client->buf[client->buf_pos++] = '\n';
      EINTRLOOP (bytes, write (client->fd, client->buf, client->buf_pos));
      if (bytes < 0 || (size_t)bytes != client->buf_pos)
	{
	  delete_client (client, slot);
	  return;
	}
    }

  /* Set up for more reading.  */
  client->buf_pos = 0;
  client->bol = 1;
  client->corking = 0;
  client->last = 0;
  client->reading = 1;
}

static int
client_process (struct client_state *client, unsigned slot)
{
  unsigned reqs = client->corking + !client->corking;
  size_t end = client->buf_pos;

  client->reading = 0;
  client->requests = xmalloc (reqs * sizeof (*client->requests));
  client->num_requests = client->num_awaiting = 0;

  client->buf_pos = 0;
  while (end != client->buf_pos && client_parse (client))
    continue;

  if (client->num_awaiting)
    {
      /* Even though the thing we're waiting on might have already
         started, it is still correct to note that we're paused, so
         that something else can run while we wait.  */
      DB (DB_JOBS, ("Pausing job\n"));
      jobs_paused++;
      if (job_slots)
	job_slots++;
      waiting_clients++;
    }
  else
    client_write (client, slot);

  return client->num_awaiting != 0;
}

void
mapper_file_finish (struct file *f)
{
  unsigned slot, ix;

  /* Do backwards because completion could delete a client.  */
  for (slot = num_clients; slot--;)
    if (clients[slot]->num_awaiting)
      {
	struct client_state *client = clients[slot];
	for (ix = client->num_requests; ix--;)
	  {
	    struct client_request *req = &client->requests[ix];

	    if (req->waiting && req->file == f)
	      {
		// FIXME: failure code?
		req->waiting = 0;
		req->resp = bmi_name (req->file);
		client->num_awaiting--;
	      }
	  }

	if (!client->num_awaiting)
	  {
	    /* Unpause the job.  This could lead to short-term over commit,
	       as we may have a still-running job borrowing the paused
	       slot.  */
	    DB (DB_JOBS, ("Unpausing job\n"));
	    jobs_paused--;
	    if (job_slots)
	      job_slots--;
	    waiting_clients--;
	    client_write (client, slot);
	  }
      }
}

/* Read data from a client.  Return non-zero if we blocked.  */

static int
client_read (struct client_state *client, unsigned slot)
{
  ssize_t bytes;

  if (client->buf_size - client->buf_pos < 2)
    {
      client->buf_size *= 2;
      client->buf = xrealloc (client->buf, client->buf_size);
    }

  bytes = read (client->fd, client->buf + client->buf_pos,
		client->buf_size - client->buf_pos - 1);
  if (bytes <= 0)
    {
      /* Error or EOF.  */
      delete_client (client, slot);
      return 0;
    }

  DB (DB_PLUGIN, ("module:%u read %u bytes '%.*s'\n",
		  client->cix, (unsigned) bytes,
		  (int) bytes, client->buf + client->buf_pos));

  /* Data.  */
  for (; bytes;)
    {
      char *probe;
      size_t len;

      if (client->bol)
	{
	  int plus = client->buf[client->buf_pos] == '+';
	  if (client->corking)
	    {
	      client->corking++;
	      client->last = !plus;
	    }
	  else
	    client->corking = plus;
	  client->bol = 0;
	}

      probe = memchr (client->buf + client->buf_pos, '\n', bytes);
      if (!probe)
	break;

      len = probe - (client->buf + client->buf_pos) + 1;
      client->buf_pos += len;
      client->buf[client->buf_pos - 1] = 0;
      bytes -= len;
      client->bol = 1;
    }
  client->buf_pos += bytes;

  if (!client->bol || !client->buf_pos)
    return 0;

  if (client->corking && !client->last)
    return 0;

  return client_process (client, slot);
}

/* Set bits in READERS for clients we're listening to.  */

int
mapper_pre_pselect (int hwm, fd_set *readers)
{
  unsigned ix;

  if (sock_fd >=0)
    {
      if (hwm < sock_fd)
	hwm = sock_fd;
      FD_SET (sock_fd, readers);
    }

  for (ix = num_clients; ix--;)
    if (clients[ix]->reading)
      {
	if (hwm < clients[ix]->fd)
	  hwm = clients[ix]->fd;
	FD_SET (clients[ix]->fd, readers);
      }
  
  return hwm;
}

/* Process bits in READERS for clients that have something for us.  */

int
mapper_post_pselect (int r, fd_set *readers)
{
  int blocked = 0;
  unsigned ix;

  if (sock_fd >= 0 && FD_ISSET (sock_fd, readers))
    {
      r--;
      new_client ();
    }

  if (r)
    /* Do backwards because reading can cause client deletion.  */
    for (ix = num_clients; ix--;)
      if (clients[ix]->reading && FD_ISSET(clients[ix]->fd, readers))
	blocked |= client_read (clients[ix], ix);

  return blocked;
}

pid_t
mapper_wait (int *status)
{
  int r;
  sigset_t empty;
  struct timespec spec;
  struct timespec *specp = NULL;

  spec.tv_sec = spec.tv_nsec = 0;

  sigemptyset (&empty);
  for (;;)
    {
      fd_set readfds;
      int hwm = 0;

      FD_ZERO (&readfds);
      hwm = mapper_pre_pselect (0, &readfds);
      r = pselect (hwm + 1, &readfds, NULL, NULL, specp, &empty);
      if (r < 0)
        switch (errno)
          {
          case EINTR:
	    {
	      /* SIGCHLD will show up as an EINTR.  We're in a loop,
		 so no need to EINTRLOOP here.  */
	      pid_t pid = waitpid ((pid_t)-1, status, WNOHANG);
	      if (pid > 0)
		return pid;
	    }
	    break;

          default:
            pfatal_with_name (_("pselect mapper"));
          }
      else if (!r)
	return 0; /* Timed out, but have new suspended job.  */
      else if (mapper_post_pselect (r, &readfds))
	specp = &spec;
    }
}

/* Install the implicit rules.  */

static void
mapper_default_rules (void)
{
  static struct pspec rules[] =
    {
      {"\"%\"." MODULE_SUFFIX, "$(C++.PREFIX)%." BMI_SUFFIX "u", ""},
      {"<%>." MODULE_SUFFIX, "$(C++.PREFIX)%." BMI_SUFFIX "s", ""},
      {"%." MODULE_SUFFIX, "$(C++.PREFIX)%." BMI_SUFFIX, ""},

      /* Order Only! */
      {"$(C++.PREFIX)%." BMI_SUFFIX, "%.cc | %.o", ""},
      {"$(C++.PREFIX)%." BMI_SUFFIX, "%.cxx | %.o", ""},
      {"$(C++.PREFIX)%." BMI_SUFFIX, "%.cpp | %.o", ""},

      {"$(C++.PREFIX)%." BMI_SUFFIX "u", "%", "$(COMPILE.cc)"
       " $(call " LEGACY_VAR ",\"$*\") $(OUTPUT_OPTION) $<"},
      {"$(C++.PREFIX)%." BMI_SUFFIX "s", "%", "$(COMPILE.cc)"
       " $(call " LEGACY_VAR ",<$*>) $(OUTPUT_OPTION) $<"},
	
      {0, 0, 0}
    };
  struct pspec *p;

  define_variable_global (LEGACY_VAR, strlen (LEGACY_VAR),
			  "-fmodule-legacy='$1'", o_default, 1, NILF);

  for (p = rules; p->target; p++)
    {
      /* We must expand the C++.PREFIX now.  */
      if (p->target[0] == '$')
	p->target = xstrdup (variable_expand (p->target));
      if (p->dep[0] == '$')
	p->dep = xstrdup (variable_expand (p->dep));
      install_pattern_rule (p, 0);
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
   Returns non-zero if enabled.  */

int
mapper_setup (const char *option)
{
  int err = 0;
  const char *errmsg = NULL;
  size_t len = 0;
#ifdef NETWORKING
  int af = AF_UNSPEC;
#ifdef HAVE_AF_UNIX
  struct sockaddr_un un;
  size_t un_len = 0;
#endif
#endif
  char *writable;

  if (!option || !option[0])
    {
      char *var = variable_expand ("$("MAPPER_VAR")");
      if (!var[0] && !option)
	return 0;
      option = var;
    }

  if (!option[0] || (option[0] == '=' && !option[1]))
    {
      pid_t pid = getpid ();
      writable = xmalloc (30);
      len = snprintf (writable, 30, "=/tmp/make-mapper-%d", (int)pid);
    }
  else
    {
      writable = xstrdup (option);
      len = strlen (option);
    }

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
    /* Force it to be undefined now, and we'll define it per-job.  */
    undefine_variable_global (MAPPER_VAR, strlen (MAPPER_VAR), o_automatic);
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

  if (!no_builtin_rules_flag)
    mapper_default_rules ();

  return 1;
}

char *
mapper_ident (void *cookie)
{
  char *assn;
  
  if (!sock_name)
    return 0;
  assn = xmalloc (100);
  sprintf (assn, MAPPER_VAR "=%s?%#lx", sock_name, (unsigned long)cookie);
  return assn;
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

  while (num_clients)
    delete_client (clients[0], 0);

  free (clients);
  clients = NULL;
  num_clients = alloc_clients = 0;
}

#endif /* MAKE_CXX_MAPPER */
