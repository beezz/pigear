import os
import sys
import time
import socket
import struct
from  datetime import datetime
import collections
import pprint


"""
snort/src/output-plugins/spo_alert_unixsock.h

/*
** Copyright (C) 2002-2011 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* This file gets included in plugbase.h when it is integrated into the rest 
 * of the program.  Sometime in The Future, I'll whip up a bad ass Perl script
 * to handle automatically loading all the required info into the plugbase.*
 * files.
 */

#ifndef __SPO_ALERT_UNIXSOCK_H__
#define __SPO_ALERT_UNIXSOCK_H__

#include <sys/types.h>
#include "event.h"
#include "pcap_pkthdr32.h"

/* this struct is for the alert socket code.... */
// FIXTHIS alert unix sock supports l2-l3-l4 encapsulations
typedef struct _Alertpkt
{
    uint8_t alertmsg[ALERTMSG_LENGTH]; /* variable.. */
    struct pcap_pkthdr32 pkth;
    uint32_t dlthdr;       /* datalink header offset. (ethernet, etc.. ) */
    uint32_t nethdr;       /* network header offset. (ip etc...) */
    uint32_t transhdr;     /* transport header offset (tcp/udp/icmp ..) */
    uint32_t data;
    uint32_t val;  /* which fields are valid. (NULL could be
                    * valids also) */
    /* Packet struct --> was null */
#define NOPACKET_STRUCT 0x1
    /* no transport headers in packet */
#define NO_TRANSHDR    0x2
    uint8_t pkt[65535];
    Event event;
} Alertpkt;

#include "pcap_pkthdr32.h"


typedef struct _Event
{
    uint32_t sig_generator;   /* which part of snort generated the alert? */
    uint32_t sig_id;          /* sig id for this generator */
    uint32_t sig_rev;         /* sig revision for this id */
    uint32_t  classification;  /* event classification */
    uint32_t priority;          /* event priority */
    uint32_t event_id;        /* event ID  */
    uint32_t event_reference; /* reference to other events that   have gone off,
                                * such as in the case  of tagged packets...
                                */
    struct sf_timeval32 ref_time;   /* reference time for the event reference */

    /* Don't add to this structure because this is the serialized      data
     * struct for unified logging.
     */
} Event;          


{
    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
};    
"""

SOCKET_FILE = "/var/log/snort/snort_alert"
ALERTMSG_LENGTH = 256
SNAPLEN = 1500

# FIXME: Find way how to calculate this.
DATA_OFFSET = 22

alert_message_format = "%ds9I%ds9I" % (ALERTMSG_LENGTH, SNAPLEN)
alert_message_format_size = struct.calcsize(alert_message_format)

#


alert_parts = (
    # Alertpkt
    "msg", "ts_sec", "ts_usec", "caplen",
    "pktlen", "dlthdr", "nethdr", "transhdr", "data", "val",
)
afmt = "%ds9I" % ALERTMSG_LENGTH
afmt_size = struct.calcsize(afmt)
#
alert_part_names = (
    # Alertpkt
    "msg",
    "ts_sec",
    "ts_usec",
    "caplen",
    "pktlen",
    "dlthdr",
    "nethdr",
    "transhdr",
    "data",
    "val",
    "pkt",
    # Event
    "sig_generator",
    "sig_id",
    "sig_rev",
    "classification",
    "priority",
    "event_id",
    "event_reference",
    # sf_timeval32
    "tv_sec",
    "tv_usec",
)
# # Event
# "sig_generator", "sig_id", "sig_rev", "classification", "priority", "event_id", "event_reference",
# # sf_timeval32
# "tv_sec", "tv_usec",
AlertMessageBase = collections.namedtuple('AlertMessageBase', alert_parts)
AlertMessage = collections.namedtuple('AlertMessage', alert_part_names)
def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # This format does NOT include the 'Event' struct which is the last element
    # of the _AlertPkt struct in src/output-plugins/spo_alert_unixsock.h 
    # Thus, we must truncate the messages ('datain[:fmt_size]') before passing 
    # them to struct.unpacket() 
    try:
        os.remove(SOCKET_FILE)
    except OSError:
        pass
    s.bind(SOCKET_FILE)
    print "Socket created ....[%s]" % SOCKET_FILE
    while True:
        try:
            (datain, addr) = s.recvfrom(65864)
            alert = AlertMessageBase._make(struct.unpack(
                afmt,
                datain[:afmt_size]))
            alert_message_format = "%ds9I%ds9I" % (ALERTMSG_LENGTH, 65535)
            alert_message_format_size = struct.calcsize(alert_message_format)

            alert = AlertMessage._make(struct.unpack(
                alert_message_format,
                datain[:alert_message_format_size]))
             # (msg, ts_sec, ts_usec, caplen, pktlen, dlthdr, nethdr, transhdr, data, val, pkt) = \
             #         struct.unpack(fmt, datain[:fmt_size])

            print(70 * '-')
            print("%s" % alert.pkt[alert.data:])
            print(70 * '-')

            print("%s" % datetime.fromtimestamp(float("%s.%s" % (alert.ts_sec, alert.ts_usec))))
            print(70 * '-')
            for name in alert_part_names:
                print(70 * '-')
                pprint.pprint(name)
                pprint.pprint(getattr(alert, name))
                print(70 * '-')
            print(70 * '-')

            # print(70 * '-')
            # alert_context = {}
            # for part, name in  zip(alert, alert_part_names):
            #     alert_context[name] = part
            #     print("%s: %s" % (name, part))
            # print(70 * '-')
            # print("%s" % alert_context['pkt'][alert_context['dlthdr'] + alert_context['nethdr'] + alert_context['transhdr'] + DATA_OFFSET:])
            # print("%s" % alert_context['pkt'][alert_context['data']:])
            # print("%s" % datetime.fromtimestamp(float("%s.%s" % (alert_context['ts_sec'], alert_context['ts_usec']))))
            # print("%s" % type(time.time()))
            # print(70 * '-')
            # optionally, do something with the pcap pkthdr (ts_sec + ts_usec + 
            # caplen + pktlen) and packet body (pkt) 
        except struct.error, e:
            print "bad message? (msglen=%d): %s" % (len(datain), e.message)

if __name__ == '__main__':
    main()
