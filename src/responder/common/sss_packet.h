/*
    Copyright (C) 2015 Red Hat

    SSSD : Responder packet definition

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

#ifndef __SSS_PACKET_H_
#define __SSS_PACKET_H_

#include <stdint.h>
#include <stdlib.h>

struct sss_packet {
    size_t memsize;

    /* Structure of the buffer:
    * Bytes    Content
    * ---------------------------------
    * 0-15     packet header
    * 0-3      packet length (uint32_t)
    * 4-7      command type (uint32_t)
    * 8-11     status (uint32_t)
    * 12-15    reserved
    * 16+      packet body */
    uint8_t *buffer;

    /* io pointer */
    size_t iop;
};

#endif /* __SSS_PACKET_H_ */
