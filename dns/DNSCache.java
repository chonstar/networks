package dns;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * Class representing a cache of stored DNS records.
 *
 * @version 1.0
 */
public class DNSCache {

    private ArrayList<DNSRecord> cachedRecords;

    public DNSCache() {
        cachedRecords = new ArrayList<DNSRecord>();
    }
    public void addRecord(DNSRecord record) {
        cachedRecords.add(record);
    }
    public ArrayList<DNSRecord> getMatches(String name, String type, String rclass) {
        var matches = new ArrayList<DNSRecord>();
        for (var record : cachedRecords) {
            if (record.getName().equals(name) &&
                record.getTypeStr().equals(type) &&
                record.getClassStr().equals(rclass)) {
                matches.add(record);
            }
        }
        return matches;
    }
    public void cleanCache() {
        Instant currentTime = Instant.now();
        Iterator<DNSRecord> iterator = cachedRecords.iterator();
        while (iterator.hasNext()) {
            DNSRecord record = iterator.next();
            Duration duration = Duration.between(record.getTime(), currentTime);
            long timeDiff = duration.getSeconds(); // No issues as TTL shouldn't ever be greater than max int value
            if (timeDiff > (long) record.getTTL()) { 
                iterator.remove();
            }
        }
    }
}
