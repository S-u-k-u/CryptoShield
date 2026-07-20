package cryptoshield.agent;

import cryptoshield.policy.ViolationRecord;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/**
 * Simple in-process event bus for the live dashboard.
 * The dashboard polls this queue to render enforcement events.
 */
public class CryptoShieldDashboard {

    private static final List<ViolationRecord> queue = new CopyOnWriteArrayList<>();
    private static final List<DashboardListener> listeners = new CopyOnWriteArrayList<>();

    public interface DashboardListener {
        void onEvent(ViolationRecord rec);
    }

    public static void push(ViolationRecord rec) {
        queue.add(rec);
        for (DashboardListener l : listeners) {
            try { l.onEvent(rec); } catch (Exception ignored) {}
        }
    }

    public static void addListener(DashboardListener l) { listeners.add(l); }
    public static List<ViolationRecord> getQueue()       { return queue; }
    public static void clear()                           { queue.clear(); }
}
