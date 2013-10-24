/*
Test the DHTMessage class
*/

#undef _M_CEE_PURE
#undef new

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "DHTMessage.h"

// ***************************************************************************************
// DHTMessage class tests
// ***************************************************************************************
TEST(DHTMessageClassTest, DecodePingQueryTest)
{
	char bMessage[] = {"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"}; // a ping query
	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_PING, message.dhtCommand);
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
}

TEST(DHTMessageClassTest, DecodeFindNodeQueryTest)
{
	char bMessage[] = {"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe"}; // a find_node query
	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_FIND_NODE, message.dhtCommand);
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));

	EXPECT_FALSE(memcmp((byte*)"mnopqrstuvwxyz123456", message.target.b, 20));
}

TEST(DHTMessageClassTest, DecodeGetPeersQueryTest)
{
	char bMessage[] = {"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"}; // a get_peer query
	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_GET_PEERS, message.dhtCommand);
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	ASSERT_EQ(message.infoHash.len, 20);
	EXPECT_FALSE(memcmp((byte*)"mnopqrstuvwxyz123456", message.infoHash.b, 20));
}

TEST(DHTMessageClassTest, DecodeAnnouncePeerQueryTest)
{
	char bMessage[] = {"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token20:12345678901234567890e1:q13:announce_peer1:t2:aa1:y1:qe"}; // a announce_peer query
	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_ANNOUNCE_PEER, message.dhtCommand);

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));
	ASSERT_EQ(20, message.infoHash.len);
	EXPECT_FALSE(memcmp((byte*)"mnopqrstuvwxyz123456", message.infoHash.b, 20));
	ASSERT_EQ(6881, message.portNum);
	EXPECT_FALSE(memcmp((byte*)"12345678901234567890", message.token.b, 20));
}

TEST(DHTMessageClassTest, DecodeImmutableGetQueryTest)
{
	char bMessage[] = {"d1:y1:q1:ad2:id20:abcdefghij01234567896:target20:11112222333344445555e1:q3:get1:t2:aae"}; // a immutable put query
	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_GET, message.dhtCommand);

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));
	EXPECT_FALSE(memcmp((byte*)"11112222333344445555", message.target.b, 20));
	EXPECT_EQ(0, message.key.len);
}

TEST(DHTMessageClassTest, DecodeImmutablePutQueryTest)
{
	char bMessage[] = {"d1:y1:q1:ad2:id20:abcdefghij01234567891:v28:bencoded data in 'v' elemente1:q3:put1:t2:aae"}; // a immutable put query

	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_PUT, message.dhtCommand);

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));
	EXPECT_TRUE(message.vBuf.b); // should not be NULL
	EXPECT_EQ(31, message.vBuf.len);
	EXPECT_EQ('2', message.vBuf.b[0]); // of *2*8:benco...... of the v element
	EXPECT_EQ('b', message.vBuf.b[3]); // of 28:*b*enco...... of the v element
}

TEST(DHTMessageClassTest, DecodeMutableGetQueryTest)
{
	const char* frontText = "d1:y1:q1:ad2:id20:abcdefghij01234567891:k248:";
	const char* backText = "6:target20:11112222333344445555e1:q3:get1:t2:aae";

	// build up a query with a 248 byte key element 'k'
	std::string bMessage;
	bMessage += frontText;
	for(int x=0; x<31; ++x) bMessage += "kkkkkkkk"; // put 248 k's in the 'k' element
	bMessage += backText;

	DHTMessage message((unsigned char*)bMessage.c_str(), bMessage.length());

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_GET, message.dhtCommand);

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));
	EXPECT_FALSE(memcmp((byte*)"11112222333344445555", message.target.b, 20));
	EXPECT_EQ(248, message.key.len);
	EXPECT_EQ('k', message.key.b[0]);   // first character should be 'k'
	EXPECT_EQ('k', message.key.b[247]); // last character should be 'k'
}

TEST(DHTMessageClassTest, DecodeMutablePutQueryTest)
{
	const char* frontText = "d1:y1:q1:ad2:id20:abcdefghij01234567891:k268:";
	const char* seqSigText = "3:seqi787e3:sig256:";
	const char* backText = "5:token20:azaztokenzaztokenzaz1:v28:bencoded data in 'v' elemente1:q3:put1:t2:aae"; // a immutable put query

	std::string bMessage;
	bMessage += frontText; // start the bencoded message string
	for(int x=0; x<268; ++x) bMessage += "k"; // add 268 characters for the 'key' element
	bMessage += seqSigText; // add the sequence number and set up for the signature element
	for(int x=0; x<256; ++x) bMessage += "s"; // add 256 characters for the 'sig' element
	bMessage += backText; // finish the bencoded string

	DHTMessage message((unsigned char*)bMessage.c_str(), bMessage.length());

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_PUT, message.dhtCommand);

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));
	EXPECT_TRUE(message.vBuf.b); // should not be NULL

	// test the 'v' element data
	EXPECT_EQ(31, message.vBuf.len);
	EXPECT_FALSE(memcmp(message.vBuf.b, "28:bencoded data in 'v' element", message.vBuf.len));

	// test the key info
	EXPECT_EQ(268, message.key.len);
	EXPECT_EQ('k', message.key.b[0]);   // first character should be 'k'
	EXPECT_EQ('k', message.key.b[267]); // last character should be 'k'

	// test the sig info
	EXPECT_EQ(256, message.signature.len);
	EXPECT_EQ('s', message.signature.b[0]);   // first character should be 'k'
	EXPECT_EQ('s', message.signature.b[255]); // last character should be 'k'

	// test the seq number
	EXPECT_EQ(787, message.sequenceNum);

	// check the token
	EXPECT_EQ('a', message.token[0]);
	EXPECT_EQ('z', message.token[1]);
}

TEST(DHTMessageClassTest, DecodeMutablePutQueryTestWithRegion)
{
	const char* frontText = "d1:y1:q1:ad2:id20:abcdefghij01234567891:k268:";
	const char* seqSigText = "3:seqi787e3:sig256:";
	const char* backText = "5:token20:azaztokenzaztokenzaz1:v28:bencoded data in 'v' elemente1:q3:put1:t2:aae"; // a immutable put query

	std::string bMessage;
	bMessage += frontText; // start the bencoded message string
	for(int x=0; x<268; ++x) bMessage += "k"; // add 268 characters for the 'key' element
	bMessage += seqSigText; // add the sequence number and set up for the signature element
	for(int x=0; x<256; ++x) bMessage += "s"; // add 256 characters for the 'sig' element
	bMessage += backText; // finish the bencoded string

	DHTMessage message((unsigned char*)bMessage.c_str(), bMessage.length());

	EXPECT_EQ(DHT_QUERY, message.dhtMessageType);
	EXPECT_EQ(DHT_QUERY_PUT, message.dhtCommand);

	// the transaction id should have a length of 2 and a value of "aa"
	ASSERT_EQ(2, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"aa", message.transactionID.b, 2));
	EXPECT_FALSE(memcmp((byte*)"abcdefghij0123456789", message.id, 20));

	// test the 'v' element region data
	EXPECT_EQ(31, message.vBuf.len);
	EXPECT_FALSE(memcmp(message.vBuf.b, "28:bencoded data in 'v' element", message.vBuf.len));

	// test the key info
	EXPECT_EQ(268, message.key.len);
	EXPECT_EQ('k', message.key.b[0]);   // first character should be 'k'
	EXPECT_EQ('k', message.key.b[267]); // last character should be 'k'

	// test the sig info
	EXPECT_EQ(256, message.signature.len);
	EXPECT_EQ('s', message.signature.b[0]);   // first character should be 'k'
	EXPECT_EQ('s', message.signature.b[255]); // last character should be 'k'

	// test the seq number
	EXPECT_EQ(787, message.sequenceNum);

	// check the token
	EXPECT_EQ('a', message.token[0]);
	EXPECT_EQ('z', message.token[1]);
}

TEST(DHTMessageClassTest, DecodeReply)
{
	char bMessage[] = {"d1:rd2:id20:1111BBBBCCCCDDDD00005:nodes26:26_byte_nearist_node_addr.5:token20:20_byte_reply_token.e1:t4:٤g�1:y1:re"}; // a response message
	DHTMessage message((unsigned char*)bMessage, sizeof(bMessage));

	EXPECT_EQ(DHT_RESPONSE, message.dhtMessageType);

	// the transaction id should have a length of 4 and a value of "٤g�"
	ASSERT_EQ(4, message.transactionID.len);
	EXPECT_FALSE(memcmp((byte*)"٤g�", message.transactionID.b, 4));
}
