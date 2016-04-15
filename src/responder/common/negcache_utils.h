/*
    Authors:
        Petr Čech <pcech@redhat.com>

    Copyright (C) 2016 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NEGCACHE_UTILS_H_
#define NEGCACHE_UTILS_H_


struct sss_nc_ctx;

int sss_ncache_init_from_confdb(TALLOC_CTX *mem_ctx,
                                struct confdb_ctx *cdb,
                                const char *section,
                                struct sss_nc_ctx **_ncache);

int sss_ncache_check_user_with_locals(struct sss_nc_ctx *ncache,
                                      struct sss_domain_info *dom,
                                      const char *name);

int sss_ncache_check_uid_with_locals(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *dom, uid_t uid);

int sss_ncache_check_group_with_locals(struct sss_nc_ctx *ncache,
                                       struct sss_domain_info *dom,
                                       const char *name);

int sss_ncache_check_gid_with_locals(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *dom, uid_t gid);

#endif /* NEGCACHE_UTILS_H_ */
