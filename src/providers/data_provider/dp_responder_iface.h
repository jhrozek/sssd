/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef DP_RESPONDER_IFACE_H_
#define DP_RESPONDER_IFACE_H_

#include "providers/data_provider/dp_iface_generated.h"
#include "providers/data_provider/dp_flags.h"

#define DP_PATH "/org/freedesktop/sssd/dataprovider"

/*
 * Request optimization of saving the data provider results. The data provider
 * might "downgrade" the optimization for example if the back end doesn't
 * support modifyTimestamps, but never "upgrade" it to more aggressive.
 */
enum dp_req_opt_level {
    /*
     * Never optimize anything, always save all data in both the synchronous
     * cache and the timestamp cache. Suitable for authentication lookups
     * such as initgroups from the PAM responder
     */
    DP_REQ_OPT_NONE,
    /*
     * Compare the returned attribute values with what is stored in the
     * synchronous cache. Only update the timestamp cache if none of the
     * attributes differ
     */
    DP_REQ_OPT_ATTR_VAL,
    /* Only update the timestamp cache if the modifyTimestamp attribute values
     * are the same between the cached object and the remote object. If the
     * modstamp value differs, compare the attribute values as if
     * CREQ_OPT_ATTR_VAL was selected
     */
    DP_REQ_OPT_MODSTAMP,
};

#endif /* DP_RESPONDER_IFACE_H_ */
