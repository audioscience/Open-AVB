#ifdef __linux__
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#else
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#define PRIu64       "I64u"
#define PRIx64       "I64x"
#endif

#include "CppUTest/TestHarness.h"

extern "C"
{
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mrp_doubles.h"
#include "mrp.h"
#include "msrp.h"
#include "parse.h"

/* Most MSRP commands operate on the global DB */
extern struct msrp_database *MSRP_db;

void msrp_event_observer(int event, struct msrp_attribute *attr);
char *msrp_attrib_type_string(int t);
char *mrp_event_string(int e);
}

struct msrp_TA_firstValue {
	uint8_t streamID[8];
	uint8_t DA[6];
	uint8_t vlan[2];
	uint8_t tspecMaxFrameSize[2];
	uint8_t tspecFrameInterval[2];
	uint8_t priorityAndRank;
	uint8_t accumlatedLatency[4];
};

struct msrp_TA_pkt {
	uint8_t destMAC[6];
	uint8_t srcMAC[6];
	uint8_t etherType[2];

	uint8_t protocolVersion;

	uint8_t attribType;
	uint8_t attribFirstValueLength;
	uint8_t attribListLength[2];

	uint8_t vectorHeader[2];

	struct msrp_TA_firstValue firstValue;

	uint8_t threePackedEvent;

	uint8_t endMarkAttrib[2];

	uint8_t endMarkPkt[2];
	
};

struct msrp_TA_pkt test_pkt = {
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }, /* Destination MAC */
	{ 0x00, 0x0f, 0xd7, 0x00, 0x23, 0x58 }, /* Source MAC */
	{ 0x22, 0xea },                         /* Ethertype */

	0x00,         /* Protocol Version */

	/* Message Start */
	0x01,             /* Attribute Type */
	0x19,             /* Attribute FirstValue Length */
	{ 0x00, 0x1f },   /* Attribute ListLength */

	/* Vector Header */
	{ 0x00, 0x01 },

	/* FirstValue */
	{
		{ 0x00, 0x0f, 0xd7, 0x00, 0x23, 0x4d, 0x00, 0x00 }, /* streamID */
		{ 0x91, 0xe0, 0xf0, 0x00, 0xb7, 0x1a }, /* DA */
		{ 0x00, 0x00 }, /* vlan */
		{ 0x00, 0x38 }, /* Tspec Max Frame Size */
		{ 0x00, 0x01 }, /* Tspec Frame Interval */
		0x60, /* Priority and Rank */
		{ 0x00, 0x02, 0x1f, 0xd8 } /* MSRP accum latency */
	},

	/* ThreePackedEvents */
	0x00,

	{ 0x00, 0x00 },  /* EndMark */

	{ 0x00, 0x00 }   /* EndMark */

};


/* Needed for msrp_recv_cmd() */
static struct sockaddr_in client;

/* Test doubles for the mrpd functionality enable feeding PDU buffers
 * into the msrp code as if they were received from the network and
 * observing the resulting MSRP events.
 *
 * test_state.rx_PDU - a buffer to hold packet data for simulated Rx
 *
 * test_state.rx_PDU_len - store the length of stored PDU data here
 *
 * test_state.forward_msrp_events - when set to 0, only the test
 *    double code for observing events will run. When set to 1, the
 *    observation code will run and then the events will pass to the
 *    normal processing.
 *
 * test_state.msrp_observe - a function pointer that, if not NULL,
 *    will be called on every event that occurs during a test.
 */

/******* Start of test cases *******/

TEST_GROUP(MsrpFloodTests)
{
	void setup() {
		mrpd_reset();
		msrp_init(1, MSRP_INTERESTING_STREAM_ID_COUNT, 0);
	}
	void teardown() {
		msrp_reset();
		mrpd_reset();
	}
};

/* 
 * This is a sample packet captured via wireshark, not really a
 * specific test case, but many are based on it. We test that
 * the test_pkt works and the attrib is created.
 */
TEST(MsrpFloodTests, ParseExamplePkt)
{
	struct msrp_attribute a_ref;
	struct msrp_attribute *attrib;
	int rv;

	memcpy(test_state.rx_PDU, &test_pkt, sizeof test_pkt);
	test_state.rx_PDU_len = sizeof test_pkt;
	rv = msrp_recv_msg();
	LONGS_EQUAL(0, rv);


	/* here we fill in a_ref struct with target values */
	memcpy(a_ref.attribute.talk_listen.StreamID, test_pkt.firstValue.streamID, sizeof test_pkt.firstValue.streamID);
	a_ref.type = MSRP_TALKER_ADV_TYPE;

	/* lookup the created attrib (it should be present) */
	attrib = msrp_lookup(&a_ref);
	CHECK(attrib != NULL);

}

/*
 * Test many TA processing. Make sure that the underlying processing
 * can handle 100 TAs without any issues.
 */
TEST(MsrpFloodTests, ParseManyTAs)
{
	uint64_t streamID;
	int rv;
	int i;

	streamID = eui64_read(test_pkt.firstValue.streamID);

	for (i = 0; i < 100; i++)
	{
		eui64_write(test_pkt.firstValue.streamID, streamID);

		memcpy(test_state.rx_PDU, &test_pkt, sizeof test_pkt);
		test_state.rx_PDU_len = sizeof test_pkt;
		rv = msrp_recv_msg();
		LONGS_EQUAL(0, rv);

		/* add 2 to prevent vectorizing */
		streamID += 2;
	}

	
	/* trigger a Tx event */
	msrp_event(MRP_EVENT_TX, NULL);

}

