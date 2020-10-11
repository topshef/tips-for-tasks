import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;

public class HCSRunningHashDemo {

    static final int RUNNING_HASH_VERSION = 3;
    static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		
		// example data https://hbar.live/mirror/hcs/?topicId=0.0.43738&fromSeq=5801&sortBy=asc&limit=2&unpack=hex&mirrornode=dragonglass&outputformat=debug
		
        HederaId topicId = new HederaId(0, 0, 43738);
		
	// details of the first message
		long sequenceNumber = 5801;
		
        String currentRunningHashInHex = "5e75efe15c385d6561f54dec9e7303653a6ce732aca25fb33de3533ade9b903443877837391ab55532cd5ff38272db98";
        // use running hash in byte array format. Hedera Java SDK natively only returns byte array.
        byte[] currHash = hexToByteArray(currentRunningHashInHex);


    // details of the next message
		HederaId payer = new HederaId(0, 0, 27498);
		
        Instant timestamp = Instant.parse("2020-10-05T22:16:03.442497001Z");
		// get consensus time from Kabuto https://docs.kabuto.sh/reference#transaction
		// https://api.kabuto.sh/v1/transaction?q={%22id%22:%20%220.0.27498@1601936153.164000000%22}

        //message to send: (needs to be in byte array)
		//https://explorer.kabuto.sh/mainnet/topic/0.0.43738/message/5802
        String messageInString = "W3siZXZlbnRJZCI6ImtwYXlsaXRlQDE2MDE5MzYxNjMuMDgyIiwiY2hhcmdlIjpbeyJoYXNoTWVtYmVyIjoiODcxNTA5YzU1Y2VjMTE1OGRlNmQ1YWM3NWM2ZTU1YmU3MDUxZGIzNWJkZGRhNzkwOTYzOTRhY2FiYjUxMjgyMCIsImhhc2hLcGF5SWQiOiIzMDQwYzg4ODI1ZGIwZWMxNjVjMzFkYTBkYjBjNjJjMjE0NTBhMGZlYjhiN2M4YjQ0MDExYTJiNzg4MTc0MTc4IiwiYW1vdW50IjoiMC4xIiwicmVjaXBpZW50SWQiOiIwLjAuMjc0OTciLCJtZW1vIjoidmVzYXVydXMuY29tICh2aWEga3BheWxpdGUgYXBpKSJ9XX1d";
        byte[] message = messageInString.getBytes();

        System.out.println("Given: "
                + "\n\tPayer: " + payer
                + "\n\tTopic: " + topicId
                + "\n\tCurrent Running Hash (in hex string): " + currentRunningHashInHex
                + "\n\tCurrent sequence number: " + sequenceNumber
                + "\n\tMessage to send: " + messageInString
                + "\n\tConsensus timestamp: " + timestamp
        );

        byte[] nextHash = HCSRunningHashDemo.getNextHash(currHash, payer, topicId, timestamp, sequenceNumber, message);
        System.out.println("\nNext running hash at sequence number " + (sequenceNumber + 1) + " is: "
                + "\nin hex string: " + bytesToHex(nextHash)
                + "\nin byte array: " + Arrays.toString(nextHash)
				+ "\nverify this on Kabuto/Dragonglass for the correct sequence number, topic ID, message and consensusTimestamp."
        );
    }

    /**
     * Method that creates the next hash in sequence:
     *
     * @param topicId            - topic id of the hcs message
	 * @param sequenceNumber     - sequence number of the first message
	 * @param runningHash        - running hash of first message
	 
	 * remaining parameters related to the next message:
     * @param payer              - account id that paid for sending the hcs message
     * @param consensusTimestamp - timestamp (in nanoseconds) when the message reached consensus
     * @param message            - hcs message string
     * @return 					 - the new expected running hash
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] getNextHash(byte[] runningHash,
                                     HederaId payer,
                                     HederaId topicId,
                                     Instant consensusTimestamp,
                                     long sequenceNumber,
                                     byte[] message
    ) throws IOException, NoSuchAlgorithmException {

        ByteArrayOutputStream boas = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(boas)) {
            out.writeObject(runningHash);
            out.writeLong(RUNNING_HASH_VERSION);
            out.writeLong(payer.shard);
            out.writeLong(payer.realm);
            out.writeLong(payer.id);
            out.writeLong(topicId.shard);
            out.writeLong(topicId.realm);
            out.writeLong(topicId.id);
            out.writeLong(consensusTimestamp.getEpochSecond());
            out.writeInt(consensusTimestamp.getNano());
            out.writeLong(sequenceNumber + 1);
            out.writeObject(MessageDigest.getInstance("SHA-384").digest(message));
            out.flush();
            final byte[] nextRunningHash = MessageDigest.getInstance("SHA-384").digest(boas.toByteArray());
            return nextRunningHash;
        }
    }

    //Utility method that converts a byte array into a hex string
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    //Utility method that converts a hex string to byte array.
    public static byte[] hexToByteArray(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    //Utility method that helps when converting a hex string to byte array
    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    //Utility method that helps when converting a hex string to byte array
    public static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    //Utility class that models Hedera AccountId, Topic Id.
    public static class HederaId {
        public long shard;
        public long realm;
        public long id;

        public HederaId(long shard, long realm, long id) {
            this.shard = shard;
            this.realm = realm;
            this.id = id;
        }

        @Override
        public String toString() {
            return "HederaId{" + "shard=" + shard + ", realm=" + realm + ", id=" + id + '}';
        }
    }
}
