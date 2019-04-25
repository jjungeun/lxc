#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "log.h"
#include "utils.h"
#include "memory_utils.h"
#include "initutils.h"
lxc_log_define(lxc_group, lxc);

static const struct option my_longopts[] = {
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname     = "lxc-group",
	.help         = "\
--name=NAME --template=TEMPLATE [OPTION...] [-- template-options]\n\
\n\
lxc-mgroup creates a container\n\
\n\
Options :\n\
  -g, --name=NAME              NAME of the container group\n\
  -c, --create=CREATE           Create container group\n\
  -d, --delete=DELETE           Destroy container group\n\
  -n, --name=NAME           NAME of the container\n",
	.options      = my_longopts,
	.parser       = NULL,
	.checker      = NULL,
	.log_priority = "ERROR",
	.log_file     = "none",
};

static int do_create_group_dir(const char *path)
{
    __do_free char *p = NULL;
	int lasterr;
	int ret = -1;

	mode_t mask = umask(0002);
	ret = mkdir(path, 0770);
	lasterr = errno;
	umask(mask);
	errno = lasterr;
	if (ret) {
		if (errno != EEXIST)
			return -1;

		ret = 0;
	}

	return ret;
}

static bool create_group_dir(const char *path,const char *group_name)
{
	int ret;
	size_t len;
	char *s;

	len = strlen(path) + strlen(group_name) + 2;
	s = malloc(len);
	if (!s)
		return false;

	ret = snprintf(s, len, "%s/%s", path, group_name);
	if (ret < 0 || (size_t)ret >= len) {
		free(s);
		return false;
	}
    if(dir_exists(s)){
        printf("%s group is already exists.\n",group_name);
        free(s);
		return false;
    }
	ret = do_create_group_dir(s);
    if (ret == -1){
        printf("Fail to create %s group.\n",group_name);
        free(s);
		return false;
    }

	free(s);
	return ret == 0;
}

static bool destroy_group_dir(const char *path,const char *group_name)
{
	int ret;
	size_t len;
	char *s;

	len = strlen(path) + strlen(group_name) + 2;
	s = malloc(len);
	if (!s)
		return false;

	ret = snprintf(s, len, "%s/%s", path, group_name);
	if (ret < 0 || (size_t)ret >= len) {
		free(s);
		return false;
	}
    if(!dir_exists(s)){
        printf("%s group is not exists.\n",group_name);
        free(s);
		return false;
    }
	ret = rmdir(s);
    if (ret == -1){
        printf("Fail to destroy %s group.\n",group_name);
        free(s);
		return false;
    }

	free(s);
	return ret == 0;
}

static bool add_container(const char *path,const char *group_name,const char *container_name)
{
    int ret;
	size_t len;
	char *s;
    char *oldpath = (char *)lxc_global_config_value("lxc.lxcpath");
    size_t oldlen;

	len = strlen(path) + strlen(group_name) + strlen(container_name) + 3;
	s = malloc(len);
	if (!s)
		return false;

	ret = snprintf(s, len, "%s/%s", path, group_name);
	if (ret < 0 || (size_t)ret >= len - strlen(container_name) -1) {
		free(s);
		return false;
	}
    if(!dir_exists(s)){
        printf("%s group is not exists.\n",group_name);
        free(s);
		return false;
    }

    ret = snprintf(s, len, "%s/%s/%s", path, group_name, container_name);
    if (ret < 0 || (size_t)ret >= len) {
		free(s);
		return false;
	}

    oldlen= strlen(oldpath)+ strlen(container_name) + 2;
    ret = sprintf(oldpath, "%s/%s", oldpath, container_name);
    if (ret<= 0 || (size_t)ret >= oldlen){
        free(s);
		return false;
    }
    if (!dir_exists(oldpath)) {
        printf("%s container is not exists.\n",container_name);
        free(s);
		return false;
    }
	ret = symlink(oldpath,s);
    
    if (ret == -1){
        if (errno == EEXIST){
            printf("%s container is already in %s group\n",container_name,group_name);
        } else {
            printf("Fail to add container\n");
        }
        free(s);
        return false;
    }

    free(s);
	return ret == 0;
}

static bool del_container(const char *path,const char *group_name,const char *container_name)
{
    int ret;
	size_t len;
	char *s;

	len = strlen(path) + strlen(group_name) + strlen(container_name) + 3;
	s = malloc(len);
	if (!s)
		return false;

	ret = snprintf(s, len, "%s/%s", path, group_name);
	if (ret < 0 || (size_t)ret >= len - strlen(container_name) -1) {
		free(s);
		return false;
	}
    if(!dir_exists(s)){
        printf("%s group is not exists.\n",group_name);
        free(s);
		return false;
    }

    ret = snprintf(s, len, "%s/%s/%s", path, group_name, container_name);
    if (ret < 0 || (size_t)ret >= len) {
		free(s);
		return false;
	}
    if(!dir_exists(s)){
        printf("%s container is not in %s group.\n",container_name,group_name);
        free(s);
		return false;
    }

	ret = remove(s);
    
    if (ret == -1){
        printf("Fail to del container\n");
        free(s);
        return false;
    }

    free(s);
	return ret == 0;
}

int main(int argc, char *argv[])
{
    struct lxc_container *c;
    char * action;
    char *path = "/usr/local/var/lib/lxcgroup";
    char *rundir;
    int ret = -1;
    FILE *fp;
    /* lxc_arguments_parse requires that my_args.name is set.
     * So setting dummy name. 
     */
    my_args.name  = "";
    if(lxc_arguments_parse(&my_args, argc, argv))
        exit(EXIT_FAILURE);
    printf("main\n");
    
    //action이 없는 경우
    if (my_args.argc < 1) {
		ERROR("Error: no command given (Please see --help output)");
		goto err;
	}

    action = my_args.argv[0];

    //lxcgroup dir이 없는 경우
    if(!dir_exists(path)){
        if(mkdir(path,0770) != 0){
            ERROR("Error: fail to make directory");
        }
    }

    if (strncmp(action, "create", strlen(action)) == 0){
        if (my_args.gname) {
            if(create_group_dir(path,my_args.gname)){
                printf("Successfully create group %s.\n",my_args.gname);
            }
        } else {
            ERROR("Error: no group name given (Please see --help output)");
            goto err;
        }
    } else if (strncmp(action, "destroy", strlen(action)) == 0){
        if (my_args.gname) {
            if(destroy_group_dir(path,my_args.gname)){
                printf("Successfully destroy group %s.\n",my_args.gname);
            }
        } else {
            ERROR("Error: no group name given (Please see --help output)");
            goto err;
        }
    } else if (strncmp(action, "add", strlen(action)) == 0){
        //컨테이너가 존재하는지는 argument에서 확인함.
        if (my_args.name != "" && my_args.gname) {
            if(add_container(path,my_args.gname,my_args.name)){
                printf("Successfully add %s container to %s group.\n",my_args.name,my_args.gname);
            }
        } else {
            ERROR("Error: no conainer name or group name given (Please see --help output)");
            goto err;
        }
    } else if (strncmp(action, "del", strlen(action)) == 0){
        //Todo : 해당 컨테이너 있는지 검사,그룹존재
        if (my_args.name != "" && my_args.gname) {
            if(del_container(path,my_args.gname,my_args.name)){
                printf("Successfully delete %s container from %s group.\n",my_args.name,my_args.gname);
            }
        } else {
            ERROR("Error: no conainer name or group name given (Please see --help output)");
            goto err;
        }
    } else {
        ERROR("Error: Please use create or destroy for group.\n\
                      Please use add or del for group member. (Please see --help output)");
		goto err;
    }

    exit(EXIT_SUCCESS);

err:
	// lxc_container_put(c);
	exit(EXIT_FAILURE);

out:
    return ret;

}


