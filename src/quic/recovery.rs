
use std::collections::HashMap;
use std::time::{Duration, Instant};
/// Default initial RTT (100ms as per RFC 9002)
const INITIAL_RTT: Duration = Duration::from_millis(100);
/// Minimum RTT to use
const MIN_RTT: Duration = Duration::from_millis(1);
/// Time threshold for loss detection (9/8 of max RTT)
const TIME_THRESHOLD_MULTIPLIER: f64 = 9.0 / 8.0;
/// Packet threshold for loss detection
const PACKET_THRESHOLD: u64 = 3;
/// Initial congestion window (in bytes)
const INITIAL_CWND: u64 = 14720; // 10 * 1472 (typical MTU payload)
/// Minimum congestion window
const MIN_CWND: u64 = 2 * 1472;
/// Information about a sent packet
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// Packet number
    pub packet_number: u64,
    /// When the packet was sent
    pub time_sent: Instant,
    /// Size of the packet in bytes
    pub size: usize,
    /// Whether this packet is ack-eliciting
    pub ack_eliciting: bool,
    /// Whether this packet has been acknowledged
    pub acked: bool,
    /// Whether this packet is declared lost
    pub lost: bool,
    /// Frame data that needs retransmission if lost
    pub retransmit_data: Option<Vec<u8>>,
}
impl SentPacket {
    pub fn new(packet_number: u64, size: usize, ack_eliciting: bool) -> Self {
        Self {
            packet_number,
            time_sent: Instant::now(),
            size,
            ack_eliciting,
            acked: false,
            lost: false,
            retransmit_data: None,
        }
    }
}
/// RTT (Round-Trip Time) estimator
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Latest RTT sample
    pub latest_rtt: Duration,
    /// Smoothed RTT
    pub smoothed_rtt: Duration,
    /// RTT variance
    pub rtt_var: Duration,
    /// Minimum RTT observed
    pub min_rtt: Duration,
    /// Whether we have a sample yet
    has_sample: bool,
}
impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}
impl RttEstimator {
    pub fn new() -> Self {
        Self {
            latest_rtt: INITIAL_RTT,
            smoothed_rtt: INITIAL_RTT,
            rtt_var: INITIAL_RTT / 2,
            min_rtt: Duration::MAX,
            has_sample: false,
        }
    }
    /// Update RTT estimate with a new sample
    pub fn update(&mut self, rtt_sample: Duration) {
        self.latest_rtt = rtt_sample;
        
        // Update min_rtt
        if rtt_sample < self.min_rtt {
            self.min_rtt = rtt_sample;
        }
        if !self.has_sample {
            // First sample
            self.smoothed_rtt = rtt_sample;
            self.rtt_var = rtt_sample / 2;
            self.has_sample = true;
        } else {
            // RFC 9002 Section 5.3
            // rtt_var = 3/4 * rtt_var + 1/4 * |smoothed_rtt - rtt_sample|
            let rtt_var_sample = if self.smoothed_rtt > rtt_sample {
                self.smoothed_rtt - rtt_sample
            } else {
                rtt_sample - self.smoothed_rtt
            };
            self.rtt_var = (self.rtt_var * 3 + rtt_var_sample) / 4;
            
            // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * rtt_sample
            self.smoothed_rtt = (self.smoothed_rtt * 7 + rtt_sample) / 8;
        }
        tracing::debug!(
            "RTT updated: latest={:?}, smoothed={:?}, var={:?}, min={:?}",
            self.latest_rtt,
            self.smoothed_rtt,
            self.rtt_var,
            self.min_rtt
        );
    }
    /// Get the loss detection timeout
    pub fn loss_delay(&self) -> Duration {
        // max(smoothed_rtt, latest_rtt) * time_threshold
        let max_rtt = self.smoothed_rtt.max(self.latest_rtt);
        Duration::from_secs_f64(max_rtt.as_secs_f64() * TIME_THRESHOLD_MULTIPLIER)
            .max(Duration::from_millis(1))
    }
    /// Get the probe timeout (PTO)
    pub fn pto(&self) -> Duration {
        self.smoothed_rtt + self.rtt_var.max(Duration::from_millis(1)) * 4
    }
}
/// Congestion controller state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow start phase
    SlowStart,
    /// Congestion avoidance phase
    CongestionAvoidance,
    /// Recovery phase (after loss)
    Recovery,
}
/// Simplified Cubic-like congestion controller
#[derive(Debug)]
pub struct CongestionController {
    /// Current congestion window (bytes)
    pub cwnd: u64,
    /// Slow start threshold
    pub ssthresh: u64,
    /// Bytes in flight
    pub bytes_in_flight: u64,
    /// Current state
    pub state: CongestionState,
    /// Recovery start packet number
    recovery_start_pn: u64,
}
impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}
impl CongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            state: CongestionState::SlowStart,
            recovery_start_pn: 0,
        }
    }
    /// Called when a packet is sent
    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_in_flight += bytes;
    }
    /// Called when a packet is acknowledged
    pub fn on_packet_acked(&mut self, bytes: u64, packet_number: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        // Exit recovery if we've acknowledged past the recovery point
        if self.state == CongestionState::Recovery && packet_number > self.recovery_start_pn {
            self.state = CongestionState::CongestionAvoidance;
            tracing::debug!("Exiting recovery, cwnd={}", self.cwnd);
        }
        // Don't grow cwnd during recovery
        if self.state == CongestionState::Recovery {
            return;
        }
        match self.state {
            CongestionState::SlowStart => {
                // Double cwnd for each RTT (exponential growth)
                self.cwnd += bytes;
                
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                    tracing::debug!("Entering congestion avoidance, cwnd={}", self.cwnd);
                }
            }
            CongestionState::CongestionAvoidance => {
                // Linear growth: increase by 1 MSS per cwnd acknowledged
                // Simplified: cwnd += MSS * bytes / cwnd
                self.cwnd += (1472 * bytes) / self.cwnd;
            }
            CongestionState::Recovery => {
                // Don't increase cwnd during recovery
            }
        }
        tracing::trace!("cwnd={}, bytes_in_flight={}", self.cwnd, self.bytes_in_flight);
    }
    /// Called when a packet is declared lost
    pub fn on_packet_lost(&mut self, bytes: u64, largest_acked: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        // Only enter recovery once per RTT
        if self.state != CongestionState::Recovery {
            self.state = CongestionState::Recovery;
            self.recovery_start_pn = largest_acked;
            
            // Multiplicative decrease
            self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
            self.cwnd = self.ssthresh;
            
            tracing::info!(
                "Packet loss detected! Entering recovery. cwnd={}, ssthresh={}",
                self.cwnd,
                self.ssthresh
            );
        }
    }
    /// Check if we can send more data
    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }
    /// Get available congestion window
    pub fn available_cwnd(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }
}
/// Loss detector and recovery manager
#[derive(Debug)]
pub struct RecoveryManager {
    /// Sent packets awaiting acknowledgment
    pub sent_packets: HashMap<u64, SentPacket>,
    /// RTT estimator
    pub rtt: RttEstimator,
    /// Congestion controller
    pub congestion: CongestionController,
    /// Largest acknowledged packet number
    pub largest_acked: u64,
    /// Packets declared lost (need retransmission)
    pub lost_packets: Vec<u64>,
    /// Time of last ack-eliciting packet sent
    pub last_ack_eliciting_time: Option<Instant>,
    /// PTO count (for exponential backoff)
    pub pto_count: u32,
}
impl Default for RecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}
impl RecoveryManager {
    pub fn new() -> Self {
        Self {
            sent_packets: HashMap::new(),
            rtt: RttEstimator::new(),
            congestion: CongestionController::new(),
            largest_acked: 0,
            lost_packets: Vec::new(),
            last_ack_eliciting_time: None,
            pto_count: 0,
        }
    }
    /// Record a sent packet
    pub fn on_packet_sent(&mut self, packet: SentPacket) {
        let pn = packet.packet_number;
        let size = packet.size;
        let ack_eliciting = packet.ack_eliciting;
        self.sent_packets.insert(pn, packet);
        self.congestion.on_packet_sent(size as u64);
        if ack_eliciting {
            self.last_ack_eliciting_time = Some(Instant::now());
        }
        tracing::debug!("Sent packet {}, {} bytes", pn, size);
    }
    /// Process an ACK frame
    pub fn on_ack_received(
        &mut self,
        largest_acked: u64,
        ack_delay: Duration,
        ack_ranges: &[(u64, u64)], // (start, end) inclusive
    ) {
        let now = Instant::now();
        // Update largest_acked
        if largest_acked > self.largest_acked {
            self.largest_acked = largest_acked;
        }
        // Mark acknowledged packets
        let mut newly_acked = Vec::new();
        
        for &(range_start, range_end) in ack_ranges {
            for pn in range_start..=range_end {
                if let Some(packet) = self.sent_packets.get_mut(&pn) {
                    if !packet.acked {
                        packet.acked = true;
                        newly_acked.push(pn);
                    }
                }
            }
        }
        // Update RTT from the largest newly acknowledged packet
        if let Some(packet) = self.sent_packets.get(&largest_acked) {
            if newly_acked.contains(&largest_acked) {
                let rtt_sample = now.duration_since(packet.time_sent);
                // Subtract ack_delay for a more accurate RTT
                let adjusted_rtt = rtt_sample.saturating_sub(ack_delay);
                if adjusted_rtt >= MIN_RTT {
                    self.rtt.update(adjusted_rtt);
                }
            }
        }
        // Update congestion controller for acked packets
        for pn in &newly_acked {
            if let Some(packet) = self.sent_packets.get(pn) {
                self.congestion.on_packet_acked(packet.size as u64, *pn);
            }
        }
        // Reset PTO count on successful ack
        if !newly_acked.is_empty() {
            self.pto_count = 0;
        }
        // Detect lost packets
        self.detect_lost_packets();
        tracing::debug!(
            "ACK processed: largest={}, newly_acked={}, lost={}",
            largest_acked,
            newly_acked.len(),
            self.lost_packets.len()
        );
    }
    /// Detect lost packets based on time and packet thresholds
    fn detect_lost_packets(&mut self) {
        let now = Instant::now();
        let loss_delay = self.rtt.loss_delay();
        
        let mut lost = Vec::new();
        for (&pn, packet) in &self.sent_packets {
            if packet.acked || packet.lost {
                continue;
            }
            // Time-based loss detection
            let time_since_sent = now.duration_since(packet.time_sent);
            if time_since_sent > loss_delay {
                lost.push(pn);
                continue;
            }
            // Packet number-based loss detection
            if self.largest_acked >= pn + PACKET_THRESHOLD {
                lost.push(pn);
            }
        }
        // Mark packets as lost and notify congestion controller
        for pn in &lost {
            if let Some(packet) = self.sent_packets.get_mut(pn) {
                packet.lost = true;
                self.congestion.on_packet_lost(packet.size as u64, self.largest_acked);
                self.lost_packets.push(*pn);
            }
        }
    }
    /// Get packets that need retransmission
    pub fn get_lost_packets(&mut self) -> Vec<SentPacket> {
        let lost_pns: Vec<u64> = self.lost_packets.drain(..).collect();
        
        lost_pns
            .iter()
            .filter_map(|pn| self.sent_packets.remove(pn))
            .collect()
    }
    /// Check if we should send a PTO probe
    pub fn should_send_pto(&self) -> bool {
        if let Some(last_time) = self.last_ack_eliciting_time {
            let pto = self.rtt.pto() * 2u32.pow(self.pto_count);
            Instant::now().duration_since(last_time) > pto
        } else {
            false
        }
    }
    /// Called when PTO fires
    pub fn on_pto(&mut self) {
        self.pto_count += 1;
        tracing::warn!("PTO fired! count={}", self.pto_count);
    }
    /// Check if we can send based on congestion control
    pub fn can_send(&self) -> bool {
        self.congestion.can_send()
    }
    /// Get available bytes to send
    pub fn available_bytes(&self) -> u64 {
        self.congestion.available_cwnd()
    }
    /// Clean up acknowledged packets
    pub fn cleanup(&mut self) {
        self.sent_packets.retain(|_, packet| !packet.acked);
    }
    /// Get statistics
    pub fn stats(&self) -> RecoveryStats {
        RecoveryStats {
            smoothed_rtt: self.rtt.smoothed_rtt,
            min_rtt: self.rtt.min_rtt,
            cwnd: self.congestion.cwnd,
            bytes_in_flight: self.congestion.bytes_in_flight,
            packets_in_flight: self.sent_packets.len(),
        }
    }
}
/// Statistics from the recovery manager
#[derive(Debug, Clone)]
pub struct RecoveryStats {
    pub smoothed_rtt: Duration,
    pub min_rtt: Duration,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
    pub packets_in_flight: usize,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rtt_estimator() {
        let mut rtt = RttEstimator::new();
        
        rtt.update(Duration::from_millis(50));
        assert!(rtt.smoothed_rtt <= Duration::from_millis(100));
        
        rtt.update(Duration::from_millis(60));
        rtt.update(Duration::from_millis(55));
        
        // Should converge toward the samples
        assert!(rtt.smoothed_rtt < Duration::from_millis(100));
        assert!(rtt.min_rtt <= Duration::from_millis(50));
    }
    #[test]
    fn test_congestion_controller_slow_start() {
        let mut cc = CongestionController::new();
        let initial_cwnd = cc.cwnd;
        
        // Simulate acking 1000 bytes
        cc.on_packet_acked(1000, 1);
        
        // In slow start, cwnd should increase
        assert!(cc.cwnd > initial_cwnd);
        assert_eq!(cc.state, CongestionState::SlowStart);
    }
    #[test]
    fn test_congestion_controller_loss() {
        let mut cc = CongestionController::new();
        cc.cwnd = 50000;
        cc.bytes_in_flight = 30000;
        
        // Simulate packet loss
        cc.on_packet_lost(1000, 10);
        
        assert_eq!(cc.state, CongestionState::Recovery);
        assert!(cc.cwnd < 50000); // cwnd should decrease
        assert_eq!(cc.ssthresh, cc.cwnd);
    }
    #[test]
    fn test_recovery_manager_ack() {
        let mut rm = RecoveryManager::new();
        
        // Send some packets
        rm.on_packet_sent(SentPacket::new(0, 1000, true));
        rm.on_packet_sent(SentPacket::new(1, 1000, true));
        rm.on_packet_sent(SentPacket::new(2, 1000, true));
        
        // Wait a bit (simulate delay)
        std::thread::sleep(Duration::from_millis(10));
        
        // ACK packets 0-2
        rm.on_ack_received(2, Duration::from_millis(5), &[(0, 2)]);
        
        // All should be acked
        assert!(rm.sent_packets.get(&0).unwrap().acked);
        assert!(rm.sent_packets.get(&1).unwrap().acked);
        assert!(rm.sent_packets.get(&2).unwrap().acked);
    }
    #[test]
    fn test_loss_detection() {
        let mut rm = RecoveryManager::new();
        
        // Send packets 0-5
        for i in 0..6 {
            rm.on_packet_sent(SentPacket::new(i, 1000, true));
        }
        
        // ACK only packets 3, 4, 5 (leaving 0, 1, 2 unacked)
        rm.on_ack_received(5, Duration::ZERO, &[(3, 5)]);
        
        // Packets 0, 1, 2 should be marked as lost (PACKET_THRESHOLD = 3)
        // 0 is 5 packets behind largest_acked (5 >= 0 + 3) ✓
        // 1 is 4 packets behind (5 >= 1 + 3) ✓
        // 2 is 3 packets behind (5 >= 2 + 3) ✓
        assert!(!rm.lost_packets.is_empty());
    }
}