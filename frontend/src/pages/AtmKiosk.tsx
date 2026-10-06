import React, { useState, useEffect, useRef } from 'react';
import { 
  CreditCard, KeyRound, ArrowRight, ShieldCheck, AlertTriangle, 
  Download, RefreshCw, LogOut, CheckCircle, Clock, Banknote, 
  Send, FileText, ChevronRight, Hash, ShieldAlert, PlusCircle, Printer, X
} from 'lucide-react';
import { ApiService } from '../services/api';
import { Atm, Transaction } from '../types';

export const AtmKiosk: React.FC = () => {
  // ATM list and selection
  const [atms, setAtms] = useState<Atm[]>([]);
  const [selectedAtmId, setSelectedAtmId] = useState<number>(1);
  const [selectedAtm, setSelectedAtm] = useState<Atm | null>(null);

  // Kiosk screens: 'LOGIN' | 'MENU' | 'WITHDRAW' | 'DEPOSIT' | 'BALANCE' | 'TRANSFER' | 'STATEMENT' | 'CHANGE_PIN' | 'RECEIPT'
  const [screen, setScreen] = useState<string>('LOGIN');

  // Login inputs
  const [cardNumber, setCardNumber] = useState('4532015893024826');
  const [pin, setPin] = useState('4826');
  const [cardHolder, setCardHolder] = useState('Rahul Sharma (Mumbai)');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // Authenticated State
  const [token, setToken] = useState<string | null>(null);
  const [sessionRemaining, setSessionRemaining] = useState<number>(600); // 10 minutes generous session
  const [activeAccount, setActiveAccount] = useState<any>(null);

  // Transaction States
  const [withdrawAmount, setWithdrawAmount] = useState<number>(2000);
  const [customAmount, setCustomAmount] = useState('');
  const [depositNotes, setDepositNotes] = useState<Record<number, number>>({ 500: 2, 200: 5 });
  const [transferTarget, setTransferTarget] = useState('SV1000000002');
  const [transferAmount, setTransferAmount] = useState('1000');
  const [miniStatement, setMiniStatement] = useState<any[]>([]);
  const [currentReceipt, setCurrentReceipt] = useState<Transaction | null>(null);
  const [showReceiptModal, setShowReceiptModal] = useState(false);

  // Change PIN inputs
  const [currentPin, setCurrentPin] = useState('');
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [pinChangeMsg, setPinChangeMsg] = useState<{ success: boolean; text: string } | null>(null);

  // Activity timer ref
  const timerRef = useRef<any>(null);

  // Fetch ATMs
  const loadAtms = async () => {
    try {
      const data = await ApiService.getAtms();
      setAtms(data);
      if (data.length > 0 && !selectedAtm) {
        setSelectedAtmId(data[0].id);
        setSelectedAtm(data[0]);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadAtms();
  }, []);

  useEffect(() => {
    const found = atms.find(a => a.id === Number(selectedAtmId));
    if (found) setSelectedAtm(found);
  }, [selectedAtmId, atms]);

  // Extend / Reset session activity
  const resetUserActivity = () => {
    setSessionRemaining(prev => Math.max(prev, 300));
  };

  const handleExtendSession = async () => {
    try {
      const res = await ApiService.extendSession();
      setSessionRemaining(res.remaining_seconds || 600);
    } catch {
      setSessionRemaining(600);
    }
  };

  // Session timer local countdown and periodic heartbeat
  useEffect(() => {
    if (!token) return;

    // Countdown interval (1 second ticks)
    const countdownInterval = setInterval(() => {
      setSessionRemaining(prev => {
        if (prev <= 1) {
          handleLogout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    // Heartbeat every 20 seconds to sync with backend
    const hbInterval = setInterval(async () => {
      try {
        const hb = await ApiService.heartbeat();
        if (hb && hb.active) {
          if (hb.remaining_seconds && hb.remaining_seconds > 0) {
            setSessionRemaining(hb.remaining_seconds);
          }
        }
      } catch (err) {
        console.warn('Heartbeat poll notice:', err);
      }
    }, 20000);

    return () => {
      clearInterval(countdownInterval);
      clearInterval(hbInterval);
    };
  }, [token]);

  const handleKeypadPress = (val: string) => {
    resetUserActivity();
    if (screen === 'LOGIN') {
      if (pin.length < 6) setPin(prev => prev + val);
    } else if (screen === 'CHANGE_PIN') {
      if (newPin.length < 6) setNewPin(prev => prev + val);
    } else if (screen === 'WITHDRAW') {
      setCustomAmount(prev => prev + val);
    }
  };

  const handleKeypadBackspace = () => {
    resetUserActivity();
    if (screen === 'LOGIN') {
      setPin(prev => prev.slice(0, -1));
    } else if (screen === 'CHANGE_PIN') {
      setNewPin(prev => prev.slice(0, -1));
    } else if (screen === 'WITHDRAW') {
      setCustomAmount(prev => prev.slice(0, -1));
    }
  };

  const handleKeypadClear = () => {
    resetUserActivity();
    if (screen === 'LOGIN') setPin('');
    else if (screen === 'CHANGE_PIN') {
      setCurrentPin('');
      setNewPin('');
      setConfirmPin('');
    } else if (screen === 'WITHDRAW') {
      setCustomAmount('');
    }
  };

  const setPresetCard = (num: string, pinCode: string, name: string) => {
    setCardNumber(num);
    setPin(pinCode);
    setCardHolder(name);
    setLoginError(null);
    resetUserActivity();
  };

  const handleLogin = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!pin) {
      setLoginError('Please enter your 4-6 digit PIN.');
      return;
    }
    setLoginError(null);
    setIsProcessing(true);
    try {
      const res = await ApiService.loginCustomer(cardNumber, pin, selectedAtmId);
      ApiService.setAuth(res.access_token, { username: res.username, role: res.role });
      setToken(res.access_token);
      setSessionRemaining(600); // 10 minutes
      
      // Load balance immediately
      const bal = await ApiService.getBalance(selectedAtmId);
      setActiveAccount(bal);
      setScreen('MENU');
    } catch (err: any) {
      setLoginError(err.message || 'Login failed. Verify card number and PIN.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleLogout = async () => {
    try {
      await ApiService.logout();
    } catch {}
    setToken(null);
    setPin('');
    setActiveAccount(null);
    setScreen('LOGIN');
    setMiniStatement([]);
    setCurrentReceipt(null);
    setShowReceiptModal(false);
  };

  // Perform Withdrawal
  const handleWithdraw = async (amt: number) => {
    resetUserActivity();
    setIsProcessing(true);
    try {
      const res = await ApiService.withdraw({
        account_id: activeAccount?.id || 1,
        atm_id: selectedAtmId,
        amount: amt,
        idempotency_key: `SV-WTH-${Date.now()}-${Math.floor(Math.random() * 10000)}`
      });
      setCurrentReceipt(res.transaction);
      setShowReceiptModal(true);
      // Reload balance
      const bal = await ApiService.getBalance(selectedAtmId);
      setActiveAccount(bal);
      setScreen('RECEIPT');
    } catch (err: any) {
      alert(`Withdrawal Failed: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  // Perform Deposit
  const handleDeposit = async () => {
    resetUserActivity();
    setIsProcessing(true);
    try {
      const totalAmt = (depositNotes[500] || 0) * 500 + (depositNotes[200] || 0) * 200 + (depositNotes[100] || 0) * 100 + (depositNotes[2000] || 0) * 2000;
      const res = await ApiService.deposit({
        account_id: activeAccount?.id || 1,
        atm_id: selectedAtmId,
        amount: totalAmt,
        denominations: depositNotes,
        idempotency_key: `SV-DEP-${Date.now()}-${Math.floor(Math.random() * 10000)}`
      });
      setCurrentReceipt(res.transaction);
      setShowReceiptModal(true);
      const bal = await ApiService.getBalance(selectedAtmId);
      setActiveAccount(bal);
      setScreen('RECEIPT');
    } catch (err: any) {
      alert(`Deposit Failed: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  // Perform Transfer
  const handleTransfer = async () => {
    resetUserActivity();
    if (!transferTarget || !transferAmount) return;
    setIsProcessing(true);
    try {
      const res = await ApiService.transfer({
        source_account_id: activeAccount?.id || 1,
        destination_account_number: transferTarget,
        atm_id: selectedAtmId,
        amount: parseFloat(transferAmount),
        idempotency_key: `SV-XFER-${Date.now()}-${Math.floor(Math.random() * 10000)}`
      });
      setCurrentReceipt(res.transaction);
      setShowReceiptModal(true);
      const bal = await ApiService.getBalance(selectedAtmId);
      setActiveAccount(bal);
      setScreen('RECEIPT');
    } catch (err: any) {
      alert(`Transfer Failed: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  // Load Mini Statement
  const handleLoadStatement = async () => {
    resetUserActivity();
    setIsProcessing(true);
    try {
      const stmts = await ApiService.getMiniStatement();
      setMiniStatement(stmts);
      setScreen('STATEMENT');
    } catch (err: any) {
      alert(`Failed to load statement: ${err.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  // Change PIN
  const handleChangePin = async () => {
    resetUserActivity();
    if (newPin !== confirmPin) {
      setPinChangeMsg({ success: false, text: 'New PIN and Confirm PIN do not match.' });
      return;
    }
    if (newPin.length < 4 || newPin.length > 6) {
      setPinChangeMsg({ success: false, text: 'PIN must be between 4 and 6 digits.' });
      return;
    }
    setIsProcessing(true);
    try {
      await ApiService.changePin(currentPin, newPin, confirmPin);
      setPinChangeMsg({ success: true, text: 'PIN successfully changed! Please remember your new PIN.' });
      setCurrentPin('');
      setNewPin('');
      setConfirmPin('');
    } catch (err: any) {
      setPinChangeMsg({ success: false, text: err.message || 'PIN change failed.' });
    } finally {
      setIsProcessing(false);
    }
  };

  // Format time mm:ss
  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <div className="min-h-screen bg-guilloche py-8 px-4 sm:px-6 lg:px-8 text-zinc-100 flex flex-col justify-center">
      <div className="max-w-6xl mx-auto w-full space-y-6">

        {/* Top Control Bar: ATM Terminal Selector & Presets */}
        <div className="glass-card rounded-xl p-4 border border-amber-500/30 shadow-2xl flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-zinc-100 text-zinc-950 flex items-center justify-center font-bold text-xs font-mono shadow-md">
              ATM
            </div>
            <div>
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest block">
                TERMINAL HARDWARE LOCATION
              </span>
              <div className="flex items-center space-x-2">
                <select
                  value={selectedAtmId}
                  onChange={e => setSelectedAtmId(Number(e.target.value))}
                  disabled={screen !== 'LOGIN'}
                  className="bg-zinc-900 border border-zinc-700 text-xs text-white rounded px-3 py-1 font-mono focus:outline-none focus:border-zinc-300"
                >
                  {atms.map(a => (
                    <option key={a.id} value={a.id}>
                      {a.atm_code} • {a.city} ({a.status})
                    </option>
                  ))}
                </select>
                <span className="text-[11px] font-mono text-zinc-400">
                  Total Cash: ₹{selectedAtm?.cash_total ? Number(selectedAtm.cash_total).toLocaleString() : 'Loading...'}
                </span>
              </div>
            </div>
          </div>

          {/* Quick Insert Customer Cards Presets */}
          {screen === 'LOGIN' && (
            <div className="flex items-center space-x-2 flex-wrap">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider mr-1">
                DEMO CARDS:
              </span>
              <button
                type="button"
                onClick={() => setPresetCard('4532015893024826', '4826', 'Rahul Sharma (Mumbai)')}
                className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded text-[11px] font-mono text-zinc-200 transition"
              >
                Mumbai (4826)
              </button>
              <button
                type="button"
                onClick={() => setPresetCard('5241890248107391', '7391', 'Priya Patel (Bangalore)')}
                className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded text-[11px] font-mono text-zinc-200 transition"
              >
                Bangalore (7391)
              </button>
              <button
                type="button"
                onClick={() => setPresetCard('4111222233339182', '9182', 'Aravind Swamy (Chennai)')}
                className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded text-[11px] font-mono text-zinc-200 transition"
              >
                Chennai (9182)
              </button>
              <button
                type="button"
                onClick={() => setPresetCard('4000123456786254', '6254', 'Ananya Sen (Delhi)')}
                className="px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded text-[11px] font-mono text-zinc-200 transition"
              >
                Delhi (6254)
              </button>
            </div>
          )}
        </div>

        {/* ============================================================== */}
        {/* MAIN CLASSIC ATM PHYSICAL CABINET */}
        {/* ============================================================== */}
        <div className="atm-cabinet rounded-3xl p-6 sm:p-8 max-w-4xl mx-auto shadow-2xl relative border-2 border-amber-500/40 shadow-[0_0_40px_rgba(245,158,11,0.12)]">
          
          {/* Cabinet Header & Heraldry */}
          <div className="text-center pb-5 mb-5 border-b border-zinc-800 relative">
            <div className="flex items-center justify-center space-x-2 text-zinc-400 mb-1">
              <ShieldCheck className="w-5 h-5 text-zinc-300" />
              <span className="text-xs font-mono tracking-[0.3em] uppercase text-zinc-300 font-bold">
                SECUREVAULT BANK & TRUST
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black text-white font-classic tracking-widest uppercase">
              AUTOMATED TELLER MACHINE
            </h2>
            <div className="flex items-center justify-center space-x-4 text-[10px] font-mono text-zinc-500 mt-1">
              <span>STAN: #84920</span>
              <span>•</span>
              <span>ENC: AES-256-GCM</span>
              <span>•</span>
              <span>ISO 8583 COMPLIANT</span>
              <span>•</span>
              <span className="text-zinc-300 font-semibold">TERMINAL ID: {selectedAtm?.atm_code || 'SV-ATM-101'}</span>
            </div>

            {/* Session Countdown & Extend Button in Header */}
            {token && (
              <div className="absolute right-0 top-0 flex items-center space-x-2">
                <div className="bg-zinc-950 border border-amber-500/40 rounded px-2.5 py-1 flex items-center space-x-2 shadow-[0_0_10px_rgba(245,158,11,0.2)]">
                  <Clock className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
                  <span className="font-mono text-xs font-bold text-amber-300 tracking-wider">
                    {formatTime(sessionRemaining)}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleExtendSession}
                  className="px-2.5 py-1 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 rounded text-[10px] font-mono font-bold text-amber-300 flex items-center space-x-1 transition shadow-[0_0_10px_rgba(245,158,11,0.15)]"
                  title="Extend session time"
                >
                  <PlusCircle className="w-3 h-3 text-amber-400" />
                  <span>+10 MIN</span>
                </button>
              </div>
            )}
          </div>

          {/* ========================================================== */}
          {/* ATM SCREEN & FLANKING SIDE BUTTONS */}
          {/* ========================================================== */}
          <div className="grid grid-cols-12 gap-3 items-center my-4">
            
            {/* Left Hardware Side Buttons (F1 - F4) */}
            <div className="col-span-1 hidden md:flex flex-col space-y-8 justify-around py-6">
              {[1, 2, 3, 4].map(idx => (
                <button
                  key={`left-${idx}`}
                  type="button"
                  onClick={() => {
                    resetUserActivity();
                    if (screen === 'MENU') {
                      if (idx === 1) setScreen('WITHDRAW');
                      if (idx === 2) setScreen('BALANCE');
                      if (idx === 3) handleLoadStatement();
                      if (idx === 4) setScreen('DEPOSIT');
                    }
                  }}
                  className="atm-side-btn h-11 w-full rounded flex items-center justify-center text-xs font-mono font-bold text-zinc-400 hover:text-white"
                >
                  ◀
                </button>
              ))}
            </div>

            {/* Central High-Contrast CRT/OLED Display */}
            <div className="col-span-12 md:col-span-10 atm-crt-screen rounded-2xl p-6 sm:p-8 min-h-[380px] flex flex-col justify-between border-2 border-zinc-800">
              
              {/* Screen Top Status Banner */}
              <div className="flex items-center justify-between text-xs font-mono border-b border-zinc-800/80 pb-3 text-zinc-400">
                <div className="flex items-center space-x-2">
                  <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
                  <span className="text-white font-bold tracking-wider">
                    {screen === 'LOGIN' ? 'AUTHENTICATION GATEWAY' : 'CUSTOMER SESSION ACTIVE'}
                  </span>
                </div>
                
                {token && activeAccount && (
                  <div className="flex items-center space-x-3 text-zinc-300">
                    <span>A/C: {activeAccount.account_number}</span>
                    <span>|</span>
                    <span className="text-white font-bold">BAL: ₹{Number(activeAccount.balance).toLocaleString()}</span>
                  </div>
                )}
              </div>

              {/* SCREEN CONTENT AREA */}
              <div className="my-auto py-4">
                
                {/* 1. LOGIN SCREEN */}
                {screen === 'LOGIN' && (
                  <div className="space-y-6 max-w-md mx-auto text-center">
                    <div className="space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        INSERT CARD & ENTER PIN
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Please verify card credentials to begin your banking session.
                      </p>
                    </div>

                    <form onSubmit={handleLogin} className="space-y-4">
                      {/* Card Number Input */}
                      <div className="space-y-1 text-left">
                        <label className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block">
                          CARD NUMBER (PAN)
                        </label>
                        <div className="relative">
                          <CreditCard className="w-4 h-4 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="text"
                            value={cardNumber}
                            onChange={e => { setCardNumber(e.target.value); resetUserActivity(); }}
                            placeholder="4532 0158 9302 4826"
                            className="w-full bg-zinc-950 border border-zinc-700 rounded-lg pl-10 pr-4 py-2.5 font-mono text-sm text-white tracking-widest focus:outline-none focus:border-zinc-300"
                          />
                        </div>
                        <span className="text-[10px] font-mono text-zinc-500 block">
                          Cardholder: {cardHolder}
                        </span>
                      </div>

                      {/* Masked PIN Display */}
                      <div className="space-y-1 text-left">
                        <label className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block">
                          SECURITY PIN (ENTER ON KEYPAD BELOW)
                        </label>
                        <div className="relative">
                          <KeyRound className="w-4 h-4 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="password"
                            maxLength={6}
                            value={pin}
                            readOnly
                            placeholder="••••"
                            className="w-full bg-zinc-950 border border-zinc-700 rounded-lg pl-10 pr-4 py-2.5 font-mono text-base tracking-[0.4em] text-center text-white focus:outline-none cursor-default"
                          />
                        </div>
                      </div>

                      {loginError && (
                        <div className="p-3 bg-zinc-900 border border-zinc-700 rounded-lg text-xs font-mono text-zinc-200 flex items-center space-x-2 text-left">
                          <AlertTriangle className="w-4 h-4 text-white shrink-0" />
                          <span>{loginError}</span>
                        </div>
                      )}

                      <button
                        type="submit"
                        disabled={isProcessing}
                        className="w-full atm-key py-3 rounded-lg text-xs font-mono font-bold tracking-widest text-white uppercase hover:text-zinc-200 transition shadow-lg"
                      >
                        {isProcessing ? 'AUTHENTICATING ENCLAVE...' : 'AUTHENTICATE & ENTER'}
                      </button>
                    </form>
                  </div>
                )}

                {/* 2. MAIN MENU SCREEN */}
                {screen === 'MENU' && (
                  <div className="space-y-6">
                    <div className="text-center space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        SELECT TRANSACTION
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Choose your banking service using the side buttons or screen controls.
                      </p>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-lg mx-auto">
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('WITHDRAW'); }}
                        className="atm-key p-4 rounded-xl text-left border border-zinc-700/80 hover:border-white transition space-y-1 group"
                      >
                        <div className="flex items-center justify-between text-white">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">1. CASH WITHDRAWAL</span>
                          <Banknote className="w-4 h-4 text-zinc-300 group-hover:scale-110 transition" />
                        </div>
                        <p className="text-[11px] font-serif-vintage text-zinc-400">Fast cash & custom denominations</p>
                      </button>

                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('BALANCE'); }}
                        className="atm-key p-4 rounded-xl text-left border border-zinc-700/80 hover:border-white transition space-y-1 group"
                      >
                        <div className="flex items-center justify-between text-white">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">2. BALANCE INQUIRY</span>
                          <FileText className="w-4 h-4 text-zinc-300 group-hover:scale-110 transition" />
                        </div>
                        <p className="text-[11px] font-serif-vintage text-zinc-400">View real-time ledger balance</p>
                      </button>

                      <button
                        type="button"
                        onClick={handleLoadStatement}
                        className="atm-key p-4 rounded-xl text-left border border-zinc-700/80 hover:border-white transition space-y-1 group"
                      >
                        <div className="flex items-center justify-between text-white">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">3. MINI STATEMENT</span>
                          <FileText className="w-4 h-4 text-zinc-300 group-hover:scale-110 transition" />
                        </div>
                        <p className="text-[11px] font-serif-vintage text-zinc-400">Recent 10 account transactions</p>
                      </button>

                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('DEPOSIT'); }}
                        className="atm-key p-4 rounded-xl text-left border border-zinc-700/80 hover:border-white transition space-y-1 group"
                      >
                        <div className="flex items-center justify-between text-white">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">4. CASH DEPOSIT</span>
                          <Banknote className="w-4 h-4 text-zinc-300 group-hover:scale-110 transition" />
                        </div>
                        <p className="text-[11px] font-serif-vintage text-zinc-400">Feed currency notes into slot</p>
                      </button>

                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('TRANSFER'); }}
                        className="atm-key p-4 rounded-xl text-left border border-zinc-700/80 hover:border-white transition space-y-1 group"
                      >
                        <div className="flex items-center justify-between text-white">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">5. FUND TRANSFER</span>
                          <Send className="w-4 h-4 text-zinc-300 group-hover:scale-110 transition" />
                        </div>
                        <p className="text-[11px] font-serif-vintage text-zinc-400">Direct peer account transfer</p>
                      </button>

                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('CHANGE_PIN'); }}
                        className="atm-key p-4 rounded-xl text-left border border-zinc-700/80 hover:border-white transition space-y-1 group"
                      >
                        <div className="flex items-center justify-between text-white">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">6. CHANGE PIN</span>
                          <KeyRound className="w-4 h-4 text-zinc-300 group-hover:scale-110 transition" />
                        </div>
                        <p className="text-[11px] font-serif-vintage text-zinc-400">Update confidential access PIN</p>
                      </button>
                    </div>
                  </div>
                )}

                {/* 3. WITHDRAWAL SCREEN */}
                {screen === 'WITHDRAW' && (
                  <div className="space-y-6 max-w-lg mx-auto">
                    <div className="text-center space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        CASH DISPENSING
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Select a fast denomination or enter custom amount (multiples of ₹100).
                      </p>
                    </div>

                    <div className="grid grid-cols-3 gap-3">
                      {[500, 1000, 2000, 5000, 10000].map(amt => (
                        <button
                          key={amt}
                          type="button"
                          onClick={() => handleWithdraw(amt)}
                          disabled={isProcessing}
                          className="atm-key py-3 rounded-lg font-mono text-xs font-bold text-white hover:text-zinc-200 border border-zinc-700 transition"
                        >
                          ₹{amt.toLocaleString()}
                        </button>
                      ))}
                      <button
                        type="button"
                        onClick={() => {
                          const amt = parseInt(customAmount);
                          if (amt && amt > 0) handleWithdraw(amt);
                        }}
                        disabled={!customAmount || isProcessing}
                        className="atm-key py-3 rounded-lg font-mono text-xs font-bold text-white bg-zinc-800 border border-zinc-600 transition"
                      >
                        ENTER CUSTOM
                      </button>
                    </div>

                    <div className="space-y-1">
                      <label className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block">
                        CUSTOM AMOUNT (USE KEYPAD)
                      </label>
                      <input
                        type="text"
                        value={customAmount ? `₹${customAmount}` : ''}
                        readOnly
                        placeholder="₹0.00"
                        className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-4 py-2.5 font-mono text-base text-center text-white focus:outline-none"
                      />
                    </div>

                    <div className="flex justify-between items-center pt-2">
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('MENU'); }}
                        className="px-4 py-2 bg-zinc-900 border border-zinc-700 rounded text-xs font-mono text-zinc-300 hover:text-white"
                      >
                        ◀ BACK TO MENU
                      </button>
                    </div>
                  </div>
                )}

                {/* 4. BALANCE INQUIRY SCREEN */}
                {screen === 'BALANCE' && (
                  <div className="space-y-6 max-w-md mx-auto text-center">
                    <div className="space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        ACCOUNT LEDGER BALANCE
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Official verified ledger statement as of current UTC timestamp.
                      </p>
                    </div>

                    <div className="bg-zinc-950/90 border border-zinc-800 rounded-2xl p-6 space-y-4 font-mono text-left">
                      <div className="flex justify-between border-b border-zinc-800/80 pb-2">
                        <span className="text-xs text-zinc-400">ACCOUNT NUMBER:</span>
                        <span className="text-xs font-bold text-white">{activeAccount?.account_number}</span>
                      </div>
                      <div className="flex justify-between border-b border-zinc-800/80 pb-2">
                        <span className="text-xs text-zinc-400">ACCOUNT TYPE:</span>
                        <span className="text-xs font-bold text-white">{activeAccount?.type || 'SAVINGS'}</span>
                      </div>
                      <div className="flex justify-between border-b border-zinc-800/80 pb-2">
                        <span className="text-xs text-zinc-400">CURRENCY:</span>
                        <span className="text-xs font-bold text-white">{activeAccount?.currency || 'INR (₹)'}</span>
                      </div>
                      <div className="flex justify-between border-b border-zinc-800/80 pb-2">
                        <span className="text-xs text-zinc-400">DAILY WITHDRAW LIMIT:</span>
                        <span className="text-xs font-bold text-white">₹{Number(activeAccount?.daily_withdrawal_limit || 50000).toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between pt-2 text-base">
                        <span className="text-xs font-bold text-zinc-300">AVAILABLE BALANCE:</span>
                        <span className="font-extrabold text-white text-lg">
                          ₹{Number(activeAccount?.balance || 0).toLocaleString()}
                        </span>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => { resetUserActivity(); setScreen('MENU'); }}
                      className="px-6 py-2.5 bg-zinc-900 border border-zinc-700 rounded-lg text-xs font-mono text-zinc-200 hover:text-white"
                    >
                      ◀ RETURN TO MAIN MENU
                    </button>
                  </div>
                )}

                {/* 5. MINI STATEMENT SCREEN */}
                {screen === 'STATEMENT' && (
                  <div className="space-y-4 max-w-xl mx-auto">
                    <div className="text-center space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        RECENT 10 TRANSACTIONS
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Cryptographically logged mini statement from the core audit ledger.
                      </p>
                    </div>

                    <div className="bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden max-h-[220px] overflow-y-auto">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-zinc-900 text-zinc-400 border-b border-zinc-800">
                          <tr>
                            <th className="p-2.5">TIMESTAMP</th>
                            <th className="p-2.5">TYPE</th>
                            <th className="p-2.5">AMOUNT</th>
                            <th className="p-2.5">STATUS</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800/60">
                          {miniStatement.map((st, i) => (
                            <tr key={i} className="hover:bg-zinc-900/50">
                              <td className="p-2.5 text-zinc-400 text-[11px]">
                                {new Date(st.created_at).toLocaleDateString()} {new Date(st.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                              </td>
                              <td className="p-2.5 text-white font-bold">{st.type}</td>
                              <td className="p-2.5 text-white">₹{Number(st.amount).toLocaleString()}</td>
                              <td className="p-2.5">
                                <span className="px-1.5 py-0.5 rounded text-[10px] bg-zinc-900 text-zinc-300 border border-zinc-700">
                                  {st.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <div className="text-center pt-2">
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('MENU'); }}
                        className="px-6 py-2 bg-zinc-900 border border-zinc-700 rounded text-xs font-mono text-zinc-300 hover:text-white"
                      >
                        ◀ BACK TO MENU
                      </button>
                    </div>
                  </div>
                )}

                {/* 6. CASH DEPOSIT SCREEN */}
                {screen === 'DEPOSIT' && (
                  <div className="space-y-6 max-w-md mx-auto text-center">
                    <div className="space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        CURRENCY NOTE DEPOSIT
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Specify denominations of banknotes to be validated and deposited.
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-left font-mono">
                      {[500, 200, 100, 2000].map(denom => (
                        <div key={denom} className="bg-zinc-950 border border-zinc-800 p-3 rounded-lg flex items-center justify-between">
                          <span className="text-xs text-zinc-400">₹{denom} Notes:</span>
                          <input
                            type="number"
                            min="0"
                            max="50"
                            value={depositNotes[denom] || 0}
                            onChange={e => {
                              resetUserActivity();
                              const val = parseInt(e.target.value) || 0;
                              setDepositNotes(prev => ({ ...prev, [denom]: val }));
                            }}
                            className="w-16 bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-white text-center focus:outline-none"
                          />
                        </div>
                      ))}
                    </div>

                    <div className="p-3 bg-zinc-900/80 border border-zinc-700 rounded-lg text-xs font-mono text-zinc-300">
                      Total Deposit Value:{' '}
                      <strong className="text-white text-sm">
                        ₹{(
                          (depositNotes[500] || 0) * 500 +
                          (depositNotes[200] || 0) * 200 +
                          (depositNotes[100] || 0) * 100 +
                          (depositNotes[200] || 0) * 2000
                        ).toLocaleString()}
                      </strong>
                    </div>

                    <div className="flex justify-between">
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('MENU'); }}
                        className="px-4 py-2 bg-zinc-900 border border-zinc-700 rounded text-xs font-mono text-zinc-300"
                      >
                        ◀ CANCEL
                      </button>
                      <button
                        type="button"
                        onClick={handleDeposit}
                        disabled={isProcessing}
                        className="atm-key px-6 py-2 rounded text-xs font-mono font-bold text-white"
                      >
                        CONFIRM DEPOSIT ▶
                      </button>
                    </div>
                  </div>
                )}

                {/* 7. FUND TRANSFER SCREEN */}
                {screen === 'TRANSFER' && (
                  <div className="space-y-6 max-w-md mx-auto text-center">
                    <div className="space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        INTER-ACCOUNT TRANSFER
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        Transfer funds instantly to any registered SecureVault account number.
                      </p>
                    </div>

                    <div className="space-y-3 text-left font-mono text-xs">
                      <div className="space-y-1">
                        <label className="text-zinc-400">DESTINATION ACCOUNT NUMBER</label>
                        <input
                          type="text"
                          value={transferTarget}
                          onChange={e => { resetUserActivity(); setTransferTarget(e.target.value); }}
                          placeholder="SV1000000002"
                          className="w-full bg-zinc-950 border border-zinc-700 rounded px-3 py-2 text-white focus:outline-none"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-zinc-400">TRANSFER AMOUNT (₹)</label>
                        <input
                          type="number"
                          value={transferAmount}
                          onChange={e => { resetUserActivity(); setTransferAmount(e.target.value); }}
                          placeholder="1000"
                          className="w-full bg-zinc-950 border border-zinc-700 rounded px-3 py-2 text-white focus:outline-none"
                        />
                      </div>
                    </div>

                    <div className="flex justify-between">
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('MENU'); }}
                        className="px-4 py-2 bg-zinc-900 border border-zinc-700 rounded text-xs font-mono text-zinc-300"
                      >
                        ◀ BACK
                      </button>
                      <button
                        type="button"
                        onClick={handleTransfer}
                        disabled={isProcessing}
                        className="atm-key px-6 py-2 rounded text-xs font-mono font-bold text-white"
                      >
                        CONFIRM TRANSFER ▶
                      </button>
                    </div>
                  </div>
                )}

                {/* 8. CHANGE PIN SCREEN */}
                {screen === 'CHANGE_PIN' && (
                  <div className="space-y-6 max-w-md mx-auto text-center">
                    <div className="space-y-1">
                      <h3 className="text-lg font-classic font-bold text-white tracking-widest uppercase">
                        CHANGE CONFIDENTIAL PIN
                      </h3>
                      <p className="text-xs font-serif-vintage text-zinc-400">
                        PIN policy enforces 4-6 digits and rejects sequential/trivial patterns.
                      </p>
                    </div>

                    <div className="space-y-3 text-left font-mono text-xs">
                      <div className="space-y-1">
                        <label className="text-zinc-400">CURRENT PIN</label>
                        <input
                          type="password"
                          maxLength={6}
                          value={currentPin}
                          onChange={e => { resetUserActivity(); setCurrentPin(e.target.value); }}
                          placeholder="••••"
                          className="w-full bg-zinc-950 border border-zinc-700 rounded px-3 py-2 text-center text-white focus:outline-none"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-zinc-400">NEW PIN</label>
                        <input
                          type="password"
                          maxLength={6}
                          value={newPin}
                          onChange={e => { resetUserActivity(); setNewPin(e.target.value); }}
                          placeholder="••••"
                          className="w-full bg-zinc-950 border border-zinc-700 rounded px-3 py-2 text-center text-white focus:outline-none"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-zinc-400">CONFIRM NEW PIN</label>
                        <input
                          type="password"
                          maxLength={6}
                          value={confirmPin}
                          onChange={e => { resetUserActivity(); setConfirmPin(e.target.value); }}
                          placeholder="••••"
                          className="w-full bg-zinc-950 border border-zinc-700 rounded px-3 py-2 text-center text-white focus:outline-none"
                        />
                      </div>
                    </div>

                    {pinChangeMsg && (
                      <div className={`p-3 rounded text-xs font-mono border ${pinChangeMsg.success ? 'bg-zinc-900 border-zinc-500 text-white' : 'bg-zinc-900 border-zinc-700 text-zinc-300'}`}>
                        {pinChangeMsg.text}
                      </div>
                    )}

                    <div className="flex justify-between">
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('MENU'); setPinChangeMsg(null); }}
                        className="px-4 py-2 bg-zinc-900 border border-zinc-700 rounded text-xs font-mono text-zinc-300"
                      >
                        ◀ CANCEL
                      </button>
                      <button
                        type="button"
                        onClick={handleChangePin}
                        disabled={isProcessing}
                        className="atm-key px-6 py-2 rounded text-xs font-mono font-bold text-white"
                      >
                        UPDATE PIN ▶
                      </button>
                    </div>
                  </div>
                )}

                {/* 9. RECEIPT PREVIEW ON SCREEN */}
                {screen === 'RECEIPT' && (
                  <div className="space-y-4 max-w-md mx-auto text-center font-mono">
                    <CheckCircle className="w-10 h-10 text-white mx-auto animate-bounce" />
                    <h3 className="text-lg font-classic font-bold text-white uppercase tracking-wider">
                      TRANSACTION SUCCESSFUL
                    </h3>
                    <p className="text-xs text-zinc-400">
                      Your transaction has been approved and cryptographically logged to the audit chain.
                    </p>
                    <div className="flex justify-center space-x-3 pt-2">
                      <button
                        type="button"
                        onClick={() => setShowReceiptModal(true)}
                        className="atm-key px-4 py-2 rounded text-xs font-mono text-white flex items-center space-x-1.5"
                      >
                        <Printer className="w-3.5 h-3.5 text-zinc-300" />
                        <span>VIEW THERMAL RECEIPT</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => { resetUserActivity(); setScreen('MENU'); }}
                        className="px-4 py-2 bg-zinc-900 border border-zinc-700 rounded text-xs font-mono text-zinc-300"
                      >
                        ANOTHER TRANSACTION
                      </button>
                    </div>
                  </div>
                )}

              </div>

              {/* Screen Bottom Bar */}
              <div className="flex items-center justify-between text-[11px] font-mono border-t border-zinc-800/80 pt-3 text-zinc-400">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-zinc-300" />
                  <span>256-BIT ENCRYPTED CHANNEL</span>
                </div>
                {token ? (
                  <div className="flex items-center space-x-3">
                    <span className="text-zinc-400">AUTO-LOGOUT: {formatTime(sessionRemaining)}</span>
                    <button
                      type="button"
                      onClick={handleLogout}
                      className="text-zinc-200 hover:text-white underline font-bold flex items-center space-x-1"
                    >
                      <LogOut className="w-3 h-3" />
                      <span>EXIT SESSION</span>
                    </button>
                  </div>
                ) : (
                  <span>INSERT CARD OR SELECT PRESET ABOVE</span>
                )}
              </div>

            </div>

            {/* Right Hardware Side Buttons (F5 - F8) */}
            <div className="col-span-1 hidden md:flex flex-col space-y-8 justify-around py-6">
              {[5, 6, 7, 8].map(idx => (
                <button
                  key={`right-${idx}`}
                  type="button"
                  onClick={() => {
                    resetUserActivity();
                    if (screen === 'MENU') {
                      if (idx === 5) setScreen('TRANSFER');
                      if (idx === 6) setScreen('CHANGE_PIN');
                      if (idx === 7) handleExtendSession();
                      if (idx === 8) handleLogout();
                    }
                  }}
                  className="atm-side-btn h-11 w-full rounded flex items-center justify-center text-xs font-mono font-bold text-zinc-400 hover:text-white"
                >
                  ▶
                </button>
              ))}
            </div>

          </div>

          {/* ========================================================== */}
          {/* HARDWARE PERIPHERALS: CARD SLOT, CASH DISPENSER, KEYPAD */}
          {/* ========================================================== */}
          <div className="mt-8 pt-6 border-t border-zinc-800 grid grid-cols-1 md:grid-cols-12 gap-8 items-start">
            
            {/* Left Hardware Slots: Card Slot & Cash Dispenser */}
            <div className="md:col-span-5 space-y-6">
              
              {/* Illuminated Card Reader Slot */}
              <div className="classic-card p-4 rounded-xl border border-zinc-800 space-y-2">
                <div className="flex justify-between items-center text-xs font-mono">
                  <span className="text-zinc-400 uppercase tracking-wider">EMV CHIP CARD READER</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${token ? 'bg-zinc-200 text-zinc-950' : 'bg-zinc-900 text-zinc-400 border border-zinc-700'}`}>
                    {token ? 'CARD ENGAGED' : 'READY FOR INSERT'}
                  </span>
                </div>
                {/* Visual Slot */}
                <div className="h-4 bg-black rounded-full border border-zinc-700 relative overflow-hidden flex items-center justify-center">
                  <div className={`h-1.5 w-24 rounded-full ${token ? 'bg-amber-400 shadow-[0_0_12px_#f59e0b]' : 'bg-zinc-700 animate-pulse'}`} />
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-zinc-500">
                  <span>INSERT CHIP FORWARD</span>
                  <span>STAN: 0981</span>
                </div>
              </div>

              {/* Cash Dispenser Shutter Slot */}
              <div className="classic-card p-4 rounded-xl border border-zinc-800 space-y-2">
                <div className="flex justify-between items-center text-xs font-mono">
                  <span className="text-zinc-400 uppercase tracking-wider">CASH DISPENSER TRAY</span>
                  <span className="text-[10px] font-mono text-zinc-400">SHUTTER SECURED</span>
                </div>
                {/* Visual Shutter */}
                <div className="h-8 bg-black rounded border-2 border-zinc-700 flex items-center justify-center relative overflow-hidden">
                  <div className="w-full h-1 bg-zinc-800" />
                  {currentReceipt && currentReceipt.type === 'WITHDRAWAL' && (
                    <div className="absolute inset-0 bg-zinc-200 text-zinc-950 flex items-center justify-center font-mono text-[10px] font-extrabold animate-pulse">
                      💵 NOTES READY: PLEASE TAKE YOUR CASH
                    </div>
                  )}
                </div>
              </div>

            </div>

            {/* Right Hardware: Classic Tactile Physical Numeric Keypad */}
            <div className="md:col-span-7 classic-card p-6 rounded-2xl border border-zinc-700 shadow-2xl">
              <div className="flex justify-between items-center mb-4 text-xs font-mono text-zinc-400 border-b border-zinc-800 pb-2">
                <span className="uppercase tracking-widest text-zinc-300 font-bold">TACTILE NUMERIC PIN PAD</span>
                <span>PCI-PTS ENCRYPTED</span>
              </div>

              <div className="grid grid-cols-4 gap-3 max-w-sm mx-auto">
                {/* Row 1 */}
                <button type="button" onClick={() => handleKeypadPress('1')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">1</button>
                <button type="button" onClick={() => handleKeypadPress('2')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">2</button>
                <button type="button" onClick={() => handleKeypadPress('3')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">3</button>
                <button 
                  type="button" 
                  onClick={handleLogout} 
                  className="atm-key h-12 rounded-lg font-mono text-xs font-extrabold tracking-wider bg-zinc-900 border border-zinc-700 text-zinc-300 hover:text-white"
                >
                  CANCEL
                </button>

                {/* Row 2 */}
                <button type="button" onClick={() => handleKeypadPress('4')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">4</button>
                <button type="button" onClick={() => handleKeypadPress('5')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">5</button>
                <button type="button" onClick={() => handleKeypadPress('6')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">6</button>
                <button 
                  type="button" 
                  onClick={handleKeypadClear} 
                  className="atm-key h-12 rounded-lg font-mono text-xs font-extrabold tracking-wider bg-zinc-800 border border-zinc-600 text-zinc-200 hover:text-white"
                >
                  CLEAR
                </button>

                {/* Row 3 */}
                <button type="button" onClick={() => handleKeypadPress('7')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">7</button>
                <button type="button" onClick={() => handleKeypadPress('8')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">8</button>
                <button type="button" onClick={() => handleKeypadPress('9')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white">9</button>
                <button 
                  type="button" 
                  onClick={handleKeypadBackspace} 
                  className="atm-key h-12 rounded-lg font-mono text-xs font-extrabold tracking-wider bg-zinc-800 border border-zinc-600 text-zinc-200 hover:text-white"
                >
                  BKSP
                </button>

                {/* Row 4 */}
                <button type="button" onClick={() => handleKeypadPress('0')} className="atm-key h-12 rounded-lg font-mono text-lg font-bold text-white col-span-2">0</button>
                <button type="button" onClick={() => handleKeypadPress('00')} className="atm-key h-12 rounded-lg font-mono text-sm font-bold text-white">00</button>
                <button 
                  type="button" 
                  onClick={() => {
                    if (screen === 'LOGIN') handleLogin();
                    else if (screen === 'WITHDRAW') {
                      const amt = parseInt(customAmount);
                      if (amt && amt > 0) handleWithdraw(amt);
                    }
                  }} 
                  className="btn-cyber-primary h-12 rounded-lg font-mono text-xs font-black tracking-wider text-black"
                >
                  ENTER
                </button>
              </div>
            </div>

          </div>

        </div>

      </div>

      {/* ============================================================== */}
      {/* VINTAGE / CLASSIC THERMAL RECEIPT MODAL */}
      {/* ============================================================== */}
      {showReceiptModal && currentReceipt && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="receipt-paper max-w-sm w-full p-6 rounded shadow-2xl relative border-t-8 border-b-8 border-zinc-300">
            
            {/* Close button */}
            <button
              onClick={() => setShowReceiptModal(false)}
              className="absolute right-3 top-3 text-zinc-600 hover:text-black"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Receipt Header */}
            <div className="text-center space-y-1 pb-4 border-b border-dashed border-zinc-400">
              <div className="font-classic font-extrabold text-sm tracking-widest text-black">
                SECUREVAULT BANK & TRUST
              </div>
              <div className="text-[10px] text-zinc-600">
                ATM TERMINAL: {selectedAtm?.atm_code || 'SV-ATM-101'}
              </div>
              <div className="text-[10px] text-zinc-600">
                BRANCH: {selectedAtm?.city || 'MUMBAI'} • ADDRESS: {selectedAtm?.address}
              </div>
              <div className="text-[10px] font-mono text-zinc-500 pt-1">
                {new Date(currentReceipt.created_at).toLocaleString()}
              </div>
            </div>

            {/* Receipt Body */}
            <div className="py-4 space-y-2 text-xs font-mono text-zinc-800">
              <div className="flex justify-between">
                <span>RECEIPT NO:</span>
                <span className="font-bold">{currentReceipt.receipt_no}</span>
              </div>
              <div className="flex justify-between">
                <span>CARD NUMBER:</span>
                <span>•••• •••• •••• {cardNumber.slice(-4)}</span>
              </div>
              <div className="flex justify-between">
                <span>TRANSACTION:</span>
                <span className="font-bold">{currentReceipt.type}</span>
              </div>
              <div className="flex justify-between">
                <span>STATUS:</span>
                <span className="font-bold">{currentReceipt.status}</span>
              </div>
              <div className="flex justify-between pt-2 border-t border-dashed border-zinc-400 text-sm font-bold text-black">
                <span>AMOUNT:</span>
                <span>₹{Number(currentReceipt.amount).toLocaleString()}.00</span>
              </div>
              <div className="flex justify-between text-[11px] text-zinc-600">
                <span>RISK EVALUATION:</span>
                <span>{currentReceipt.risk_level} (SCORE: {currentReceipt.risk_score}/100)</span>
              </div>
            </div>

            {/* Receipt Footer */}
            <div className="pt-4 border-t border-dashed border-zinc-400 text-center space-y-1 text-[10px] text-zinc-500">
              <p>THANK YOU FOR BANKING WITH SECUREVAULT.</p>
              <p className="font-mono text-[9px] text-zinc-400 truncate">
                SHA-256 HASH: {currentReceipt.receipt_no.slice(0, 24)}...
              </p>
            </div>

            {/* Print button */}
            <div className="mt-4 pt-3 flex justify-center">
              <button
                onClick={() => window.print()}
                className="px-4 py-2 bg-black text-white text-xs font-mono rounded hover:bg-zinc-800 transition flex items-center space-x-2"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>PRINT RECEIPT</span>
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
