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
        HederaId payer = new HederaId(0, 0, 6205);
        HederaId topicId = new HederaId(0, 0, 63956);

        // using hash of message 1 of Topic 0.0.63956.
        String currentRunningHashInHex = "b2b0a6dde101e7e8860fc3e3ceef91c9d68ae6bc6b8f60b7c0f74f94c60039c07f6355d48e86456a603e91854eb0c5cf";
        // use running hash in byte array format. Hedera Java SDK natively only returns byte array.
        //byte[] currHash = new byte[]{-78, -80, -90, -35, -31, 1, -25, -24, -122, 15, -61, -29, -50, -17, -111, -55, -42, -118, -26, -68, 107, -113, 96, -73, -64, -9, 79, -108, -58, 0, 57, -64, 127, 99, 85, -44, -114, -122, 69, 106, 96, 62, -111, -123, 78, -80, -59, -49};
        byte[] currHash = hexToByteArray(currentRunningHashInHex);

        long sequenceNumber = 1;

        //Timestamp to send second message.
        Instant timestamp = Instant.parse("2020-10-07T09:13:35.277456002Z");

        //message to send: (needs to be in byte array)
        String messageInString = "hcs demo - 10x";
        byte[] message = messageInString.getBytes();

        System.out.println("Given: "
                + "\n\tPayer: " + payer
                + "\n\tTopic: " + topicId
                + "\n\tCurrent Running Hash (in hex string): " + currentRunningHashInHex
                + "\n\tCurrent sequence number: " + sequenceNumber
                + "\n\tMessage to send: " + messageInString
                + "\n\tTimestamp to send on: " + timestamp
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
     * @param runningHash        - current hash
     * @param payer              - account id that paid for sending the hcs message
     * @param topicId            - topic id of the hcs message
     * @param consensusTimestamp - timestamp when the NEW message must be sent
     * @param sequenceNumber     - sequenece number of the current message (not the new one)
     * @param message            - message to be sent
     * @return - the new expected running hash
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
