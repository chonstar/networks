package dns;

import java.net.DatagramPacket;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Class representing a single DNS message.
 *
 * @version 1.0
 */
public class DNSMessage {
    // max length of a DNS message is 512 bytes
    final private static int MAX_DNS_MSG_LENGTH = 512;

    // the UDP packet provided to the constructor
    private DatagramPacket pkt;
    private byte[] data;
    private int data_length;

    // track the next byte we'll read from the buffer when building a request message
    private int next_byte;

    // the DNS message ID field
    private int id;

    // the DNS message Flags field, with individual flags parsed out
    private int flags;
    private int flag_qr;
    private int flag_opcode;
    private int flag_aa;
    private int flag_tc;
    private int flag_rd;
    private int flag_ra;
    private int flag_rcode;

    // the four DNS Message fields for the # of questions, answers, and RRs
    private int num_questions;
    private int num_answers;
    private int num_auth_rrs;
    private int num_additional_rrs;

    // map the various required Class numbers to their human readable names
    private static HashMap<Integer,String> classes;

    // map the various required Type numbers to their human readable names
    private static HashMap<Integer,String> types;

    // use a static initialization block to create the above maps
    static {
        classes = new HashMap<Integer,String>();
        classes.put(1,"IN");

        types = new HashMap<Integer,String>();
        types.put(1,"A");
        types.put(2,"NS");
        types.put(5,"CNAME");
        types.put(6,"SOA");
        types.put(12,"PTR");
        types.put(28,"AAAA");
    }

    // the DNS message fields to represent a single question (including type and class as both numbers and strings
    // note that we still only support a single question per packet
    private String question_name;
    private int question_type;
    private String question_type_str;
    private int question_class;
    private String question_class_str;

    // a list of all answer records for a response
    private ArrayList<DNSRecord> answers;

    /**
     * constructor to make a DNS Message object given a UDP packet
     *
     * @param pkt a UDP packet that should contain a DNS message
     */
    public DNSMessage(DatagramPacket pkt) {
        this.pkt = pkt;

        // track where we are in the UDP packet byte buffer 
        next_byte = 0;

        parseHeader();
        parseFlags();
        parseQuestions();

        // make the list to hold the answers then fill it in
        this.answers = new ArrayList<DNSRecord>();
        parseAnswers();
    }

    /**
     * constructor to make a DNS Message response object given a DNS request message and record information
     *
     * @param   request a complete DNS request message
     * @param   answers the list of answers to includ
     * @param   isAuthoritative whether this answer is authoritative (came from our zone) or not (came from the cache or another server)
     */
    public DNSMessage(DNSMessage request, ArrayList<DNSRecord> answers, boolean isAuthoritative) {
        // fill in all of the fields for this object
        this.answers = answers;
        createHeader(request, isAuthoritative);
        createQuestions(request);

        // file in the byte buffer according to DNS message format
        createBuffer();
    }

    /**
     * utility method to initialize the message fields from ID through the question/record numbers
     *
     * @param   request a complete DNS request message
     * @param   isAuthoritative whether this answer is authoritative (came from our zone) or not (came from the cache or another server)
     */
    private void createHeader(DNSMessage request, boolean isAuthoritative) {
        // the id, opcode flag, recursion desired flag, and #questions is the same as in the request message
        this.id = request.id;
        this.flag_opcode = request.flag_opcode; 
        this.flag_rd = request.flag_rd;
        this.num_questions = request.num_questions;

        // the query response flag is 1 since this is a response
        this.flag_qr = 1;

        // set the authoritative flag based on the given parameter
        if(isAuthoritative) {
            this.flag_aa = 1;
        } else {
            this.flag_aa = 0;
        }

        // set the recursion available flag to 1 since we can do recursion now
        this.flag_ra = 1;
        
        // other flags are zero except for response code below
        this.flag_tc = 0;
        this.num_auth_rrs = 0;
        this.num_additional_rrs = 0;

        if(answers.size() != 0) {
            // if we found a record, then response code is 0 with the given number of answers
            this.flag_rcode = 0;
            this.num_answers = answers.size();
        } else {
            // if we didn't find a record, then response code is 3 with 0 answers
            this.flag_rcode = 3;
            this.num_answers = 0;
        }

        // make the full flags field from the individual flags above
        createFlags();
    }

    /**
     * utility method to put the individual flags together into one 16-bit field
     */
    private void createFlags() {
        // see the documentation for individual flag positions within the 16-bit field
        flags = (flag_qr & 0x1) << 15;
        flags |= (flag_opcode & 0xf) << 11;
        flags |= (flag_aa & 0x1) << 10;
        flags |= (flag_tc & 0x1) << 9;
        flags |= (flag_rd & 0x1) << 8;
        flags |= (flag_ra & 0x1) << 7;
        flags |= (flag_rcode & 0xf);
    }

    /**
     * utility method to initialize the question section for a response message
     *
     * @param request a full DNS request message
     */
    private void createQuestions(DNSMessage request) {
        // this server only supports responses with a single question
        if(num_questions != 1) {
            return;
        }

        // all of the question fields are copied over directly from the request message
        this.question_name = request.question_name;
        this.question_type = request.question_type;
        this.question_type_str = request.question_type_str;
        this.question_class = request.question_class;
        this.question_class_str = request.question_class_str;
    }

    /**
     * utility method to fill in the byte buffer with a 4-byte int
     *
     * @param   i   the integer to add to the buffer
     */
    private void writeInt(int i) {
        data[data_length] = (byte)((i & 0xff000000) >> 24);
        data[data_length+1] = (byte)((i & 0xff0000) >> 16);
        data[data_length+2] = (byte)((i & 0xff00) >> 8);
        data[data_length+3] = (byte)(i & 0xff);
        data_length += 4;
    }

    /**
     * utility method to fill in the byte buffer with a 2-byte int
     *
     * @param   s   the short to add to the buffer
     */
    private void writeShort(int s) {
        data[data_length] = (byte)((s & 0xff00) >> 8);
        data[data_length+1] = (byte)(s & 0xff);
        data_length += 2;
    }

    /**
     * utility method to fill in the byte buffer with a 1-byte int
     *
     * @param   b   the byte to add to the buffer
     */
    private void writeByte(int b) {
        data[data_length] = (byte)b;
        data_length += 1;
    }

    /**
     * utility method to fill in the byte buffer with an IP address
     *
     * @param   ip   the IP address string to add to the buffer
     */
    private void writeIP(String ip) {
        // get the octets
        var octets = ip.split("\\.");

        // write each octet into the buffer as a 1-byte int
        for(String octet : octets) {
            writeByte(Integer.parseInt(octet));
        }
    }

    /**
     * utility method to fill in the byte buffer with a hostname
     *
     * @param   s   the hostname string to add to the buffer
     */
    private void writeName(String s) {
        // split on dots
        var labels = s.split("\\.");

        // write each label separately
        for (String label : labels) {
            // each label starts with the length of the label
            var len = label.length();
            writeByte(len);

            // then each character in the label
            for(int i=0; i<label.length(); i++) {
                writeByte(label.charAt(i));
            }
        }

        // write a zero byte at the end to indicate the name is done
        writeByte(0);
    }

    /**
     * utility method to write one question to the byte buffer
     */
    private void writeQuestion() {
        // this server only supports one question
        if(num_questions != 1) {
            return;
        }

        // see the DNS documentation for the order
        writeName(question_name);
        writeShort(question_type);
        writeShort(question_class);
    }

    /**
     * utility method to write all answers to the byte buffer
     */
    private void writeAnswer() {
        // write each answer
        for(var record : answers) {

            // see the DNS documentation for thr order
            writeName(record.getName());
            writeShort(record.getTypeNum());
            writeShort(record.getClassNum());
            writeInt(record.getTTL());
            writeShort(record.getDataLength());

            // write the rdata depending on the record type
            if(record.getTypeNum() == 1) {
                writeIP(record.getData());
            } else {
                writeName(record.getData());
            }
        }
    }

    /**
     * utility method to fill in the byte buffer from the instance variables in this object
     */
    private void createBuffer() {
        // make a new buffer to store the response message for UDP
        data = new byte[MAX_DNS_MSG_LENGTH];

        // track how many bytes we add to the buffer
        // this also tells us the next index into the buffer to use
        data_length = 0;

        // fill in the initial 6 fields
        writeShort(id);
        writeShort(flags);
        writeShort(num_questions);
        writeShort(num_answers);
        writeShort(num_auth_rrs);
        writeShort(num_additional_rrs);

        // fill in the question and answer sections
        writeQuestion();
        writeAnswer();
    }

    /**
     * utility method to convert two bytes into a single short (16-bit) value
     *
     * @param b0 the first/left/top bits
     * @param b1 the second/right/bottom bits
     */
    private int bytesToShort(byte b0, byte b1) {
        int i0 = b0 & 0xff;
        int i1 = b1 & 0xff;
        return (i0 << 8) | i1;
    }

    /**
     * utility method to convert four bytes into a single int (32-bit) value
     *
     * @param b0 the first/left/top bits
     * @param b1 the second set of bits
     * @param b2 the third set of bits
     * @param b3 the fourth/right/bottom bits
     */
    private int bytesToInt(byte b0, byte b1, byte b2, byte b3) {
        int i0 = b0 & 0xff;
        int i1 = b1 & 0xff;
        int i2 = b2 & 0xff;
        int i3 = b3 & 0xff;
        return (i0 << 24) | (i1 << 16) | (i2 << 8) | i3;
    }

    /**
     * utility method to parse out the id, flags, and # fields from the UDP packet
     */
    private void parseHeader() {
        // get the packet data a byte[]
        data = pkt.getData();

        // grab the length for now, though we don't need it yet
        data_length = pkt.getLength();

        // the first 12 bytes in the message are the 6 2-byte fields that start the message
        id = bytesToShort(data[0], data[1]);
        flags = bytesToShort(data[2], data[3]);
        num_questions = bytesToShort(data[4], data[5]);
        num_answers = bytesToShort(data[6], data[7]);
        num_auth_rrs = bytesToShort(data[8], data[9]);
        num_additional_rrs = bytesToShort(data[10], data[11]);
        next_byte = 12;
    }

    /**
     * utility method to parse the flags into individual flag variables
     */
    private void parseFlags() {
        // see the documentation for individual flag positions within the 16-bit field
        flag_qr = flags >> 15 & 0x1;
        flag_opcode = flags >> 11 & 0xf;
        flag_aa = flags >> 10 & 0x1;
        flag_tc = flags >> 9 & 0x1;
        flag_rd = flags >> 8 & 0x1;
        flag_ra = flags >> 7 & 0x1;
        flag_rcode = flags & 0xf;
    }

    /**
     * utility method to parse a 2-byte int from the byte buffer
     * 
     * @return the next 2-byte int from the buffer
     */
    private int parseShort() {
        int s = bytesToShort(data[next_byte], data[next_byte+1]);
        next_byte += 2;
        return s;
    }

    /**
     * utility method to parse a 4-byte int from the byte buffer
     * 
     * @return the next 4-byte int from the buffer
     */
    private int parseInt() {
        int i = bytesToInt(data[next_byte], data[next_byte+1], data[next_byte+2], data[next_byte+3]);
        next_byte += 4;
        return i;
    }

    /**
     * utility method to parse a compressed name from the byte buffer
     *
     * @return the name from the buffer location indicated in the offset
     */
    private String parseCompressedName() {
        // get the offset location of the name
        int offset = parseShort() & 0x3fff;

        // save our location parsing through the message
        int save_next_byte = next_byte;
        next_byte = offset;

        // parse the name out from the offset location
        var name = parseName();

        // reset our location to pick up where we left off
        next_byte = save_next_byte;

        return name;
    }

    /**
     * utility method to parse a name from the byte buffer
     *
     * @return the next name from the buffer 
     */
    private String parseName() {
        // build up the name as we go
        String name = "";

        // get the length of the next label from the message
        int next_label_len = data[next_byte] & 0xff;

        // have to handle label compresion, indicated by the top two bits being 1s
        if(next_label_len >= 192) {
            return parseCompressedName();
        }

        // otherwise, the name is stored as a series of one-byte lengths followed by that many chars, each representing a single label

        // the name is complete whtn the final length field is zero
        while(next_label_len != 0) {

            // read the number of bytes out of the message corresponding to the length
            int i;
            for(i=next_byte+1; i <= next_byte+next_label_len; i++) {
                name += (char)data[i];
            }

            // each label is separated by a dot
            name += ".";

            // move on to the next label
            next_byte = i;
            next_label_len = data[next_byte] & 0xff;
        }

        // the above loop adds the trailing dot, so let's remove that
        name = name.substring(0, name.length()-1);

        // move past the zero byte
        next_byte++;

        return name;
    }

    /**
     * utility method to parse an IP from the byte buffer
     *
     * @return the next IP from the buffer 
     */
    private String parseIP() {
        // build up the string as we go
        String ip = "";

        // get each octet in order
        for(int i = 0; i < 4; i++) {
            int b = data[next_byte] & 0xff;

            // turn the byte into a String
            ip += String.valueOf(b);
            next_byte++;

            // adds dots between each octet
            if (i != 3) {
                ip += ".";
            }
        }
        return ip;
    }

    /**
     * utility method to parse out the questions section
     */
    private void parseQuestions() {
        // for our server, we only support a single question
        if(num_questions != 1) {
            System.out.println("Warning, unexpected number of questions.");
            return;
        }

        // get the name, type and class for this question
        question_name = parseName();
        question_type = parseShort();
        question_class = parseShort(); 

        // get the string version of the question type
        if(types.containsKey(question_type)) {
            question_type_str = types.get(question_type);
        } else {
            question_type_str = String.format("%d", question_type);
        }

        // get the string version of the question class
        if(classes.containsKey(question_class)) {
            question_class_str = classes.get(question_class);
        } else {
            question_class_str = String.format("%d", question_class);
        }
    }

    /**
     * utility method to parse out the answers section
     */
    private void parseAnswers() {
        // get each answer in order
        for(int i = 0; i < num_answers; i++) {

            // get the name, type (number), class (number), TTL, and rdata length
            var answer_name = parseName();
            var answer_type = parseShort();
            var answer_class = parseShort();
            var answer_ttl = parseInt();
            var answer_rdlength = parseShort();

            // get the rdata based on the type
            String answer_data = "";
            if(answer_type == 1) {
                answer_data = parseIP();
            } else {
                answer_data = parseName();
            }

            // make a new record and add it to the answers list
            var record = new DNSRecord(answer_name, answer_ttl, answer_class, answer_type, answer_data);
            answers.add(record);
        }
    }

    /**
     * return a string version of this message
     *
     * @return  the String version of this message
     */
    public String toString() {
        // use StringBuilder because many String concatenations is inefficient in Java
        var sb = new StringBuilder();

        // add the inital 6 fields
        sb.append(String.format("ID: 0x%04X%n",id));
        sb.append(String.format("Flags: 0x%04X%n",flags));
        if(flag_qr == 0 && flag_opcode == 0) {
            sb.append(String.format("- Standard Query%n"));
        } else if(flag_qr == 1 && flag_rcode == 0) {
            sb.append(String.format("- Standard Response%n"));
        } else if(flag_qr == 1 && flag_rcode == 3) {
            sb.append(String.format("- Response NXDomain%n"));
        } else {
            sb.append(String.format("- Unexpected QR/opcode%n"));
        }
        if(flag_aa == 1) {
            sb.append(String.format("- Authoritative Answer%n"));
        }
        if(flag_rd == 1) {
            sb.append(String.format("- Recursion Requested%n"));
        }
        if(flag_ra == 1) {
            sb.append(String.format("- Recursion Available%n"));
        }
        sb.append(String.format("# Questions: %d%n",num_questions));
        sb.append(String.format("# Answers: %d%n",num_answers));
        sb.append(String.format("# Authority RRs: %d%n",num_auth_rrs));
        sb.append(String.format("# Additional RRs: %d%n",num_additional_rrs));

        // add the question section if there is a question
        if(num_questions == 1) {
            sb.append(String.format("Questions:%n"));
            sb.append(String.format("- %s, %s, %s%n", question_name, question_type_str, question_class_str));
        }

        // add the answer section if there is an answer
        if(num_answers != 0) {
            sb.append(String.format("Answers:%n"));

            // add each answer
            for(var answer : answers) {
              sb.append(String.format("- %s, %s, %s, %d, %s%n", answer.getName(), answer.getTypeStr(), answer.getClassStr(), answer.getTTL(), answer.getData()));
            }
        }

        return sb.toString();
    }

    /**
     * check if this message is query or response
     *
     * @return true if this message is a query, false otherwise
     */
    public boolean isQuery() {
        if(flag_qr == 0) {
            return true;
        }
        return false;
    }

    /**
     * accessor for the ID of this message
     *
     * @return  the ID of this message
     */
    public int getID() {
        return id;
    }

    /**
     * accessor for the name in the question section
     *
     * @return  the name in the question section
     */
    public String getQuestionName() {
        return question_name;
    }

    /**
     * accessor for the type in the question section
     *
     * @return  the type, as a string, in the question section
     */
    public String getQuestionType() {
        return question_type_str;
    }

    /**
     * accessor for the class in the question section
     *
     * @return  the class, as a string, in the question section
     */
    public String getQuestionClass() {
        return question_class_str;
    }

    /**
     * accessor to get all of the answers in the message (if any)
     *
     * @return  a list of all answers in this message
     */
    public ArrayList<DNSRecord> getAnswers() {
        return answers;
    }

    /**
     * accessor for the byte buffer for this entire message
     *
     * @return  the full byte buffer representation of this message
     */
    public byte[] getData() {
        return data;
    }

    /**
     * accessor for the byte buffer length for this message
     *
     * @return  the number of bytes in the full byte buffer representation of this message
     */
    public int getDataLength() {
        return data_length;
    }

    /**
     * accessor for the original UDP for this DNS message
     *
     * @return  the original DatagramPacket object this message was built from
     */
    public DatagramPacket getPacket() {
        return pkt;
    }
}
