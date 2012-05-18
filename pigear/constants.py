"""
    pcap_pkthdr32.h
    struct sf_timeval32

    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
"""
STRUCT_SF_TIMEVAL32 = (
    ("tv_sec", "I"),
    ("tv_usec", "I"),
)

"""
    event.h
    struct Event

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
"""
STRUCT_EVENT = (
    ("sig_generator", "I"),
    ("sig_id", "I"),
    ("sig_rev", "I"),
    ("classification", "I"),
    ("priority", "I"),
    ("event_id", "I"),
    ("event_reference", "I"),
) + STRUCT_SF_TIMEVAL32

"""
    pcap_pkthdr32.h
    struct pcap_pkthdr32

    struct sf_timeval32 ts;   /* packet timestamp */
    uint32_t caplen;          /* packet capture length */
    uint32_t len;             /* packet "real" length */
"""
STRUCT_PCAP_PKTHDR32 = (
    ("ts_sec", "I"),
    ("ts_usec", "I"),
    ("caplen", "I"),
    ("pktlen", "I"),
)

"""
    spo_alert_unixsock.h
    struct Alertpkt

    decode.h
    ALERTMSG_LENGTH = 256

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
"""
ALERTMSG_LENGTH = 256
PKT_LENGTH = 65535

STRUCT_ALERTPKT = (
    ("msg", "%ds" % ALERTMSG_LENGTH),
) + STRUCT_PCAP_PKTHDR32 + (
    ("dlthdr", "I"),
    ("nethdr", "I"),
    ("transhdr", "I"),
    ("data", "I"),
    ("val", "I"),
    ("pkt", "%ds" % PKT_LENGTH),
) + STRUCT_EVENT
