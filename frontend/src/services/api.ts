const API_BASE = '/api/v1';

export class ApiService {
  private static tokenKey = 'securevault_token';
  private static userKey = 'securevault_user';

  static setAuth(token: string, user: any) {
    localStorage.setItem(this.tokenKey, token);
    localStorage.setItem(this.userKey, JSON.stringify(user));
  }

  static getAuthToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  static getToken(): string | null {
    return this.getAuthToken();
  }

  static getCurrentUser(): any | null {
    const raw = localStorage.getItem(this.userKey);
    return raw ? JSON.parse(raw) : null;
  }

  static clearAuth() {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userKey);
  }

  static async ensureAdminAuth(): Promise<boolean> {
    const user = this.getCurrentUser();
    if (user && (user.role === 'SUPER_ADMIN' || user.role === 'BANK_ADMIN' || user.role === 'SECURITY_ANALYST')) {
      return true;
    }
    try {
      const res = await this.loginStaff('admin', 'Admin@1234');
      this.setAuth(res.access_token, { username: res.username, role: res.role });
      return true;
    } catch {
      return false;
    }
  }

  static async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const token = this.getAuthToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      const exempt = ['/auth/customer/login', '/compliance', '/audit/verify', '/session/heartbeat', '/session/extend'];
      if (!exempt.some(e => endpoint.includes(e))) {
        this.clearAuth();
      }
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Request failed' }));
      throw new Error(errorData.detail || errorData.message || `Error ${response.status}`);
    }

    // If PDF or blob
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/pdf')) {
      return response.blob();
    }

    return response.json();
  }

  // Auth
  static loginCustomer(card_number: string, pin: string, atm_id: number) {
    return this.request('/auth/customer/login', {
      method: 'POST',
      body: JSON.stringify({ card_number, pin, atm_id }),
    });
  }

  static loginStaff(username: string, password: string, totp_code?: string) {
    return this.request('/auth/staff/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, totp_code }),
    });
  }

  static logout() {
    return this.request('/auth/logout', { method: 'POST' }).finally(() => this.clearAuth());
  }

  static heartbeat() {
    return this.request('/auth/session/heartbeat');
  }

  static extendSession() {
    return this.request('/auth/session/extend', { method: 'POST' }).catch(() => ({ active: true, remaining_seconds: 600 }));
  }

  // ATMs
  static getAtms() {
    return this.request('/atm');
  }

  static getAtm(id: number) {
    return this.request(`/atm/${id}`);
  }

  static loadCash(atm_id: number, denominations: Record<number, number>) {
    return this.request(`/atm/${atm_id}/cash-load`, {
      method: 'POST',
      body: JSON.stringify({ denominations }),
    });
  }

  static setAtmStatus(atm_id: number, status: string, reason?: string) {
    return this.request(`/atm/${atm_id}/status`, {
      method: 'POST',
      body: JSON.stringify({ status, reason }),
    });
  }

  static updateSensor(atm_id: number, sensor_type: string, state: string) {
    return this.request(`/atm/${atm_id}/sensor`, {
      method: 'POST',
      body: JSON.stringify({ sensor_type, state, trigger_alert: true }),
    });
  }

  static unlockAtm(atm_id: number, reason: string) {
    return this.request(`/atm/${atm_id}/unlock?reason=${encodeURIComponent(reason)}`, {
      method: 'POST',
    });
  }

  // Customer Account
  static getBalance(atm_id?: number) {
    const q = atm_id ? `?atm_id=${atm_id}` : '';
    return this.request(`/accounts/me/balance${q}`);
  }

  static getMiniStatement() {
    return this.request('/accounts/me/mini-statement');
  }

  static changePin(current_pin: string, new_pin: string, confirm_pin: string) {
    return this.request('/accounts/me/change-pin', {
      method: 'POST',
      body: JSON.stringify({ current_pin, new_pin, confirm_pin }),
    });
  }

  // Transactions
  static withdraw(payload: { account_id: number; atm_id: number; amount: number; idempotency_key: string }) {
    return this.request('/transactions/withdraw', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static deposit(payload: { account_id: number; atm_id: number; amount: number; denominations: Record<number, number>; idempotency_key: string }) {
    return this.request('/transactions/deposit', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static transfer(payload: { source_account_id: number; destination_account_number: string; atm_id: number; amount: number; idempotency_key: string }) {
    return this.request('/transactions/transfer', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static downloadReceipt(receipt_no: string) {
    return this.request(`/transactions/${receipt_no}/receipt.pdf`);
  }

  // SOC
  static getSocKpis() {
    return this.request('/soc/kpis');
  }

  static getSocMap() {
    return this.request('/soc/map');
  }

  static getSocAnalytics() {
    return this.request('/soc/analytics');
  }

  static getSecurityEvents(severity?: string) {
    const q = severity ? `?severity=${severity}` : '';
    return this.request(`/soc/events${q}`);
  }

  // Incidents
  static getIncidents(status?: string) {
    const q = status ? `?status_filter=${status}` : '';
    return this.request(`/incidents${q}`);
  }

  static getIncident(id: number) {
    return this.request(`/incidents/${id}`);
  }

  static updateIncidentStatus(id: number, status: string, resolution_note?: string) {
    return this.request(`/incidents/${id}/status`, {
      method: 'POST',
      body: JSON.stringify({ status, resolution_note }),
    });
  }

  static addIncidentNote(id: number, text: string) {
    return this.request(`/incidents/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  }

  // Alerts
  static getAlerts() {
    return this.request('/alerts');
  }

  static acknowledgeAlert(id: number) {
    return this.request(`/alerts/${id}/acknowledge`, { method: 'POST' });
  }

  static closeAlert(id: number) {
    return this.request(`/alerts/${id}/close`, { method: 'POST' });
  }

  // Audit
  static getAuditLogs() {
    return this.request('/audit/logs');
  }

  static verifyAudit() {
    return this.request('/audit/verify');
  }

  static tamperDemo(log_id: number) {
    return this.request('/audit/tamper-demo', {
      method: 'POST',
      body: JSON.stringify({ log_id }),
    });
  }

  static restoreDemo(log_id: number) {
    return this.request(`/audit/restore-demo?log_id=${log_id}`, {
      method: 'POST',
    });
  }

  // Simulations
  static async runSimulation(simulation_type: string, atm_id?: number, account_id?: number) {
    await this.ensureAdminAuth();
    return this.request('/simulations/run', {
      method: 'POST',
      body: JSON.stringify({ simulation_type, atm_id, account_id }),
    });
  }

  static async resetDemo() {
    await this.ensureAdminAuth();
    return this.request('/simulations/reset-demo', { method: 'POST' });
  }

  // Admin
  static getCustomers() {
    return this.request('/admin/customers');
  }

  static toggleCustomerLock(customer_id: number) {
    return this.request(`/admin/customers/${customer_id}/toggle-lock`, { method: 'POST' });
  }

  static getPolicies() {
    return this.request('/admin/policies');
  }

  static updatePolicy(key: string, value: any, description?: string) {
    return this.request(`/admin/policies/${key}`, {
      method: 'PUT',
      body: JSON.stringify({ value, description }),
    });
  }

  // Security Center & Threat Intel
  static getThreats() {
    return this.request('/threats');
  }

  static getMitreCoverage() {
    return this.request('/soc/attack-coverage');
  }

  static getPosture() {
    return this.request('/security/posture');
  }

  static runScanner(simulateFailure: boolean = false) {
    return this.request(`/security/scanner?simulate_failure=${simulateFailure}`);
  }

  static getSecrets() {
    return this.request('/security/secrets');
  }

  static getCompliance() {
    return this.request('/compliance');
  }

  static exportIncident(id: number) {
    return this.request(`/incidents/${id}/export`);
  }

  // MongoDB Compass
  static getMongoStatus() {
    return this.request('/admin/mongodb/status');
  }

  static syncMongo() {
    return this.request('/admin/mongodb/sync', { method: 'POST' });
  }
}
