package dns;

import java.time.Instant;
import java.util.Map;
import java.util.HashMap;

/**
 * Class representing a single DNS record.
 *
 * @version 1.0
 */
public class DNSRecord {

    /**
     * the name stored in this record
     */
    private String name;

    /**
     * the ttl (in seconds) for this record
     */
    private int ttl;

    /**
     * the class code, both as number and string
     */
    private int class_num;
    private String class_str;

    /**
     * the type, both as number and string
     */
    private int type_num;
    private String type_str;

    /**
     * length of the data field (in bytes)
     */
    private int data_length;

    /**
     * the data field, e.g., the IPv4 address in an A record
     */
    private String data;

    // Something to track when this record object was stored
    private Instant currentTime;
    
    /**
     * map the various required Class numbers to their human readable names
     */
    private static HashMap<Integer,String> classes;

    /**
     * map the various required Type numbers to their human readable names
     */
    private static HashMap<Integer,String> types;

    // use a static initialization block to create the above maps
    static {
        classes = new HashMap<Integer,String>();
        classes.put(1,"IN");

        types = new HashMap<Integer,String>();
        types.put(1,"A");
        types.put(5,"CNAME");
    }

    /**
     * constructor to make a record given the class/type as Strings
     *
     * @param   name        the record's name
     * @param   ttl         the record's TTL
     * @param   class_str   the record's class as a String
     * @param   type_str    the record's type as a String
     * @param   data        the record's data
     */
    public DNSRecord(String name, int ttl, String class_str, String type_str, String data) {
        // set the class and type strings
        this.class_str = class_str;
        this.type_str = type_str;

        // set the class and type numbers
        this.class_num = classStringToNum(class_str);
        this.type_num = typeStringToNum(type_str);

        // initialize everything else
        initialize(name, ttl, data);
        currentTime = Instant.now();
    }

    /**
     * constructor to make a record given the class/type as numbers
     *
     * @param   name        the record's name
     * @param   ttl         the record's TTL
     * @param   class_str   the record's class as a number
     * @param   type_str    the record's type as a number
     * @param   data        the record's data
     */
    public DNSRecord(String name, int ttl, int class_num, int type_num, String data) {
        // set the class and type numbers
        this.class_num = class_num;
        this.type_num = type_num;

        // set the class and type strings
        this.class_str = classNumToString(this.class_num);
        this.type_str = typeNumToString(this.type_num);

        // initialize everything else
        initialize(name, ttl, data);
        currentTime = Instant.now();
    }

    /**
     * utility method to convert a class string to a class number
     *
     * @param   class_str   the DNS class as a String
     * @return              the DNS class as a number
     */
    private static int classStringToNum(String class_str) {
        // go through the map to get the class number for the given class string
        for (Map.Entry<Integer, String> entry : classes.entrySet()) {
            if(entry.getValue().equals(class_str)) {
                return entry.getKey();
            }
        }

        // if it's an unsupported class, set the class number to be zero
        return 0;
    }

    /**
     * utility method to convert a type string to a type number
     *
     * @param   type_str   the DNS type as a String
     * @return             the DNS type as a number
     */
    private static int typeStringToNum(String type_str) {
        // go through the map to get the type number for the given type string
        for (Map.Entry<Integer, String> entry : types.entrySet()) {
            if(entry.getValue().equals(type_str)) {
                return entry.getKey();
            }
        }

        // if it's an unsupported type, set the type number to be zero
        return 0;
    }

    /**
     * utility method to convert a class number to a class string
     *
     * @param   class_num   the DNS class as a number
     * @return              the DNS class as a String
     */
    private static String classNumToString(int class_num) {
        // get the string version of the class number
        if(classes.containsKey(class_num)) {
            return classes.get(class_num);
        }
        return String.format("%d", class_num);
    }

    /**
     * utility method to convert a type number to a type string
     *
     * @param   type_num    the DNS type as a number
     * @return              the DNS type as a String
     */
    private static String typeNumToString(int type_num) {
        // get the string version of the type number
        if(types.containsKey(type_num)) {
            return types.get(type_num);
        }
        return String.format("%d", type_num);
    }

    /**
     * utility method for both constructors to initialize all the shared fields
     *
     * @param   name        the record's name
     * @param   ttl         the record's TTL
     * @param   data        the record's data
     */
    private void initialize(String name, int ttl, String data) {
        // set all the instance variables for the record
        this.name = name;
        this.ttl = ttl;
        this.data = data;
        setDataLength();
    }

    /**
     * utility method to set the data length based on the record type
     */
    private void setDataLength() {
        if (this.type_num == 1) {
            // A records store IPv4 address (4 bytes)
            this.data_length = 4;
        } else if (this.type_num == 5) {
            // CNAME records store strings; have to include the null byte also
            this.data_length = data.length() + 1;
        } else {
            // any other record types aren't supported by this server
            System.out.println("This server only handles A and CNAME records.");
            System.exit(0);
        }
    }

    /**
     * accessor to get the record's name field
     * 
     * @return the record's name field
     */
    public String getName() {
        return name;
    }

    /**
     * accessor to get the record's TTL
     * 
     * @return the record's TTL field (seconds)
     */
    public int getTTL() {
        return ttl;
    }

    /**
     * accessor to get the record's Class code as a number
     * 
     * @return the record's Class code as a number
     */
    public int getClassNum() {
        return class_num;
    }

    /**
     * accessor to get the record's Class code in human readable fashion
     * 
     * @return the record's Class code as a String
     */
    public String getClassStr() {
        return class_str;
    }

    /**
     * accessor to get the record's Type as a number
     * 
     * @return the record's code as a number
     */
    public int getTypeNum() {
        return type_num;
    }

    /**
     * accessor to get the record's Type in human readable fashion
     * 
     * @return the record's Type code as a String
     */
    public String getTypeStr() {
        return type_str;
    }

    /**
     * accessor to get the record's data length (bytes)
     * 
     * @return the record's data length in bytes
     */
    public int getDataLength() {
        return data_length;
    }

    /**
     * accessor to get the record's data (String)
     * 
     * @return the record's data as a String
     */
    public String getData() {
        return data;
    }

    public Instant getTime() {
        return currentTime;
    }
}
