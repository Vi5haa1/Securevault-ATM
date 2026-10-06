export type UserRole = 'CUSTOMER' | 'ATM_OPERATOR' | 'SECURITY_ANALYST' | 'BANK_ADMIN' | 'SUPER_ADMIN';

export type AtmStatus = 'ONLINE' | 'OFFLINE' | 'MAINTENANCE' | 'LOCKDOWN' | 'DISABLED';

export type SensorState = 'NORMAL' | 'WARNING' | 'ALERT';

export interface AtmSensor {
  sensor_type: string;
  state: SensorState;
  last_updated: string;
}

export interface AtmInventory {
  denomination: number;
  note_count: number;
}

export interface Atm {
  id: number;
  atm_code: string;
  city: string;
  address: string;
  latitude: number;
  longitude: number;
  status: AtmStatus;
  network_status: string;
  cash_total: number;
  low_cash_threshold: number;
  security_status: string;
  last_heartbeat: string;
  sensors?: AtmSensor[];
  inventories?: AtmInventory[];
}

export interface ZeroTrustTrace {
  step_name: string;
  status: 'PASSED' | 'WARNING' | 'FAILED';
  details: string;
  timestamp: string;
}

export interface Transaction {
  id: number;
  account_id: number;
  atm_id: number;
  type: string;
  amount: number;
  status: string;
  risk_score: number;
  risk_level: string;
  risk_factors?: any;
  receipt_no: string;
  dispensed_notes?: { denomination: number; count: number }[];
  new_balance?: number;
  created_at: string;
  zero_trust_trace?: ZeroTrustTrace[];
}

export interface Alert {
  id: number;
  event_id: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  message: string;
  status: 'NEW' | 'ACKNOWLEDGED' | 'CLOSED';
  created_at: string;
}

export interface IncidentAction {
  id: number;
  action_type: string;
  result: string;
  created_at: string;
}

export interface IncidentNote {
  id: number;
  author_id: number;
  author_name?: string;
  text: string;
  created_at: string;
}

export interface Incident {
  id: number;
  incident_code: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_type: string;
  atm_id?: number;
  account_id?: number;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  summary: string;
  created_at: string;
  resolved_at?: string;
  is_simulated: boolean;
  actions: IncidentAction[];
  notes: IncidentNote[];
}

export interface AuditVerify {
  total_logs: number;
  verified_logs: number;
  tampered: boolean;
  broken_sequence_no?: number;
  broken_log_id?: number;
  status: string;
  details: string;
  verified_at: string;
}

export interface SimulationResult {
  simulation_id: string;
  simulation_type: string;
  threat_detected: boolean;
  detection_rule: string;
  actions_triggered: string[];
  incident_code?: string;
  alert_title?: string;
  steps: { step: string; status: string; detail: string }[];
}
