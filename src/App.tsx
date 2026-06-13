import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Search, 
  ShieldCheck, 
  Mail, 
  Globe, 
  Layout, 
  AlertCircle, 
  CheckCircle2, 
  Loader2,
  ChevronRight,
  Activity,
  Server,
  Lock,
  Cpu,
  History,
  ShieldAlert,
  FileWarning,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import {
  fetchProfiles,
  fetchHistory,
  analyzeDomain,
  aiFixGuide,
  aiSecurityChat,
  aiMxChat,
  testSmtp,
  testMx,
  emailAudit,
  type ChatMessage,
} from './lib/api';

interface AnalysisResult {
  domain: string;
  score: number;
  dns: {
    a: string[];
    mx: { exchange: string; priority: number }[];
    ns: string[];
    txt: string[];
    spf: string | null;
    dmarc: string | null;
  };
  ssl: {
    valid: boolean;
    issuer?: string;
    validTo?: string;
    protocol?: string;
    error?: string;
  };
  emailHealth: {
    provider: string;
    status: 'optimal' | 'error' | 'neutral';
    issues: string[];
  };
  security: {
    headers: {
      hsts: boolean;
      csp: boolean;
      xfo: boolean;
      xss: boolean;
      nosniff: boolean;
      permissions: boolean;
      referrer: boolean;
    };
    exposures: string[];
    serverHeader: string | null;
  };
  wordpress: {
    detected: boolean;
    statusCode: number;
  };
  vite?: {
    detected: boolean;
    deepScan?: {
      enabled: boolean;
      findings: { path: string; message: string }[];
    };
  };
  hosting: {
    isNamecheap: boolean;
    isGoDaddy?: boolean;
    nameservers: string[];
  };
  aiReport?: string;
}

interface AuditHistory {
  id: number;
  domain: string;
  timestamp: string;
  score: number;
  results: AnalysisResult;
}

export default function App() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<AuditHistory[]>([]);
  const [profiles, setProfiles] = useState<{ domain: string }[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [deepViteScan, setDeepViteScan] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [isAiLoading, setIsAiLoading] = useState(false);
  
  const [activeTab, setActiveTab] = useState<'audit' | 'email'>('audit');
  
  // Email Tools State
  const [smtpHost, setSmtpHost] = useState('');
  const [smtpPort, setSmtpPort] = useState('465');
  const [smtpSecure, setSmtpSecure] = useState(true);
  const [smtpUser, setSmtpUser] = useState('');
  const [smtpPass, setSmtpPass] = useState('');
  const [smtpResult, setSmtpResult] = useState<any>(null);
  const [smtpLoading, setSmtpLoading] = useState(false);

  const [mxDomain, setMxDomain] = useState('');
  const [mxResult, setMxResult] = useState<any>(null);
  const [mxLoading, setMxLoading] = useState(false);

  const [emailAuditDomain, setEmailAuditDomain] = useState('');
  const [emailAuditResult, setEmailAuditResult] = useState<any>(null);
  const [emailAuditLoading, setEmailAuditLoading] = useState(false);

  // Email Chat State
  const [emailChatMessages, setEmailChatMessages] = useState<ChatMessage[]>([]);
  const [emailChatInput, setEmailChatInput] = useState('');
  const [isEmailAiLoading, setIsEmailAiLoading] = useState(false);

  useEffect(() => {
    fetchProfilesHandler();
  }, []);

  const fetchProfilesHandler = async () => {
    try {
      const data = await fetchProfiles();
      setProfiles(data);
    } catch (err) {
      console.error('Failed to fetch profiles', err);
    }
  };

  const fetchHistoryHandler = async (targetDomain: string) => {
    try {
      const data = await fetchHistory(targetDomain);
      setHistory(data);
    } catch (err) {
      console.error('Failed to fetch history', err);
    }
  };

  const handleAnalyze = async (e?: React.FormEvent, targetDomain?: string) => {
    if (e) e.preventDefault();
    const d = targetDomain || domain;
    if (!d) return;
    
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const cleanDomain = d.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
      const data = await analyzeDomain(cleanDomain, deepViteScan);
      setResult(data);
      fetchHistoryHandler(cleanDomain);
      fetchProfilesHandler();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const generateAiReport = async () => {
    if (!result) return;
    setIsAiLoading(true);
    try {
      const text = await aiFixGuide(result);
      setResult({ ...result, aiReport: text });
    } catch (err: any) {
      console.error('AI Report error:', err);
      setError('Failed to generate AI report: ' + err.message);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || !result) return;

    const userMsg: ChatMessage = { role: 'user', text: chatInput };
    setChatMessages((prev) => [...prev, userMsg]);
    const message = chatInput;
    setChatInput('');
    setIsAiLoading(true);

    try {
      const text = await aiSecurityChat(result, message, chatMessages);
      setChatMessages((prev) => [...prev, { role: 'model', text }]);
    } catch (err: any) {
      console.error('Chat error:', err);
      setChatMessages((prev) => [...prev, { role: 'model', text: 'Error: ' + err.message }]);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleEmailSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailChatInput.trim()) return;

    const userMsg: ChatMessage = { role: 'user', text: emailChatInput };
    setEmailChatMessages((prev) => [...prev, userMsg]);
    const message = emailChatInput;
    setEmailChatInput('');
    setIsEmailAiLoading(true);

    try {
      const text = await aiMxChat(message, { smtpResult, mxResult, emailAuditResult }, emailChatMessages);
      setEmailChatMessages((prev) => [...prev, { role: 'model', text }]);
    } catch (err: any) {
      console.error('Email Chat error:', err);
      setEmailChatMessages((prev) => [...prev, { role: 'model', text: 'Error: ' + err.message }]);
    } finally {
      setIsEmailAiLoading(false);
    }
  };

  const handleSmtpTest = async (e: React.FormEvent) => {
    e.preventDefault();
    setSmtpLoading(true);
    setSmtpResult(null);
    try {
      const data = await testSmtp({
        host: smtpHost,
        port: smtpPort,
        secure: smtpSecure,
        user: smtpUser,
        pass: smtpPass,
      });
      setSmtpResult(data);
    } catch (err: any) {
      setSmtpResult({ success: false, error: err.message });
    } finally {
      setSmtpLoading(false);
    }
  };

  const handleMxTest = async (e: React.FormEvent) => {
    e.preventDefault();
    setMxLoading(true);
    setMxResult(null);
    try {
      const data = await testMx(mxDomain);
      setMxResult(data);
    } catch (err: any) {
      setMxResult({ success: false, error: err.message });
    } finally {
      setMxLoading(false);
    }
  };

  const handleEmailAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailAuditLoading(true);
    setEmailAuditResult(null);
    try {
      const data = await emailAudit(emailAuditDomain);
      setEmailAuditResult(data);
    } catch (err: any) {
      setEmailAuditResult({ success: false, error: err.message });
    } finally {
      setEmailAuditLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-zinc-100 font-sans selection:bg-emerald-500/30">
      {/* Background Elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-emerald-500/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-500/5 rounded-full blur-[120px]" />
      </div>

      <main className="relative z-10 max-w-7xl mx-auto px-6 py-12">
        {/* Header */}
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-16">
          <div className="text-left">
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold tracking-wider uppercase mb-4"
            >
              <ShieldCheck size={14} />
              Security & DNS Audit Suite
            </motion.div>
            <motion.h1 
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-4xl md:text-6xl font-bold tracking-tight bg-gradient-to-b from-white to-zinc-500 bg-clip-text text-transparent"
            >
              DNS Sentinel
            </motion.h1>
          </div>

          <div className="flex items-center gap-4">
            {profiles.length > 0 && (
              <div className="relative group">
                <select 
                  onChange={(e) => handleAnalyze(undefined, e.target.value)}
                  className="bg-zinc-900 border border-white/10 rounded-xl px-4 py-2 text-sm focus:ring-emerald-500 focus:border-emerald-500 outline-none appearance-none pr-10"
                >
                  <option value="">Saved Profiles</option>
                  {profiles.map(p => (
                    <option key={p.domain} value={p.domain}>{p.domain}</option>
                  ))}
                </select>
                <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
              </div>
            )}
            <button 
              onClick={() => setShowHistory(!showHistory)}
              className={`p-2 rounded-xl border transition-all ${showHistory ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400' : 'bg-zinc-900 border-white/10 text-zinc-500 hover:text-zinc-300'}`}
            >
              <History size={20} />
            </button>
            {result && (
              <button 
                onClick={() => setIsChatOpen(!isChatOpen)}
                className={`p-2 rounded-xl border transition-all ${isChatOpen ? 'bg-blue-500/20 border-blue-500/50 text-blue-400' : 'bg-zinc-900 border-white/10 text-zinc-500 hover:text-zinc-300'}`}
              >
                <Activity size={20} />
              </button>
            )}
          </div>
        </header>

        {/* Tabs */}
        <div className="flex border-b border-white/10 mb-8">
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === 'audit' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
          >
            Domain Audit
          </button>
          <button
            onClick={() => setActiveTab('email')}
            className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === 'email' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
          >
            Email Tools
          </button>
        </div>

        {activeTab === 'audit' && (
          <>
            {/* Search Bar */}
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="max-w-3xl mx-auto mb-16"
            >
          <form onSubmit={handleAnalyze} className="relative group">
            <div className="absolute inset-0 bg-emerald-500/20 rounded-2xl blur-xl transition-all group-focus-within:bg-emerald-500/30 opacity-0 group-focus-within:opacity-100" />
            <div className="relative flex items-center bg-zinc-900 border border-white/10 rounded-2xl p-2 transition-all focus-within:border-emerald-500/50">
              <div className="pl-4 text-zinc-500">
                <Globe size={20} />
              </div>
              <input 
                type="text" 
                placeholder="Enter domain to audit (e.g. example.com)"
                className="flex-1 bg-transparent border-none focus:ring-0 px-4 py-3 text-lg placeholder:text-zinc-600"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
              <button 
                type="submit"
                disabled={loading}
                className="bg-emerald-500 hover:bg-emerald-400 text-black font-bold px-8 py-3 rounded-xl transition-all flex items-center gap-2 disabled:opacity-50"
              >
                {loading ? <Loader2 className="animate-spin" size={20} /> : <ShieldCheck size={20} />}
                {loading ? 'Auditing...' : 'Run Audit'}
              </button>
            </div>
          </form>

          <div className="flex items-center justify-center gap-6">
            <label className="flex items-center gap-3 cursor-pointer group">
              <div 
                onClick={() => setDeepViteScan(!deepViteScan)}
                className={`w-10 h-5 rounded-full relative transition-all ${deepViteScan ? 'bg-emerald-500' : 'bg-zinc-800'}`}
              >
                <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${deepViteScan ? 'left-6' : 'left-1'}`} />
              </div>
              <span className="text-xs font-semibold text-zinc-500 group-hover:text-zinc-300 transition-colors uppercase tracking-wider">
                Explore Vite Builds (dist)
              </span>
            </label>
          </div>
          {error && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 p-3 rounded-xl"
            >
              <AlertCircle size={16} />
              {error}
            </motion.div>
          )}
        </motion.div>

        {/* Results Section */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Main Content */}
          <div className={`${(showHistory || isChatOpen) ? 'lg:col-span-8' : 'lg:col-span-12'} space-y-8 transition-all duration-500`}>
            <AnimatePresence mode="wait">
              {result && (
                <motion.div 
                  key="results"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  {/* Score & Quick Stats */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="glass-panel p-6 flex flex-col items-center justify-center text-center status-glow-green border-emerald-500/20">
                      <div className="text-sm font-semibold text-zinc-500 uppercase tracking-wider mb-2">Security Score</div>
                      <div className={`text-5xl font-black ${result.score > 80 ? 'text-emerald-400' : result.score > 50 ? 'text-blue-400' : 'text-red-400'}`}>
                        {result.score}
                      </div>
                      <div className="text-xs text-zinc-600 mt-2">out of 100 points</div>
                    </div>
                    <StatCard 
                      icon={<ShieldAlert className="text-red-400" />}
                      label="Vulnerabilities"
                      value={result.security.exposures.length > 0 ? `${result.security.exposures.length} Found` : 'Clean'}
                      subValue={result.security.exposures.length > 0 ? 'Exposure detected' : 'No common leaks'}
                      status={result.security.exposures.length > 0 ? 'error' : 'success'}
                    />
                    <StatCard 
                      icon={<Lock className="text-blue-400" />}
                      label="Framework"
                      value={result.wordpress.detected ? 'WordPress' : result.vite?.detected ? 'Vite Build' : 'Custom'}
                      subValue={result.wordpress.detected ? 'CMS Active' : result.vite?.detected ? 'SPA/Vite' : 'Unknown Stack'}
                      status={result.wordpress.detected || result.vite?.detected ? 'success' : 'neutral'}
                    />
                    <StatCard 
                      icon={<Server className="text-orange-400" />}
                      label="Hosting"
                      value={result.hosting.isNamecheap ? 'Namecheap' : result.hosting.isGoDaddy ? 'GoDaddy' : 'Other'}
                      subValue={result.dns.ns[0] || 'Unknown'}
                      status={result.hosting.isNamecheap ? 'success' : 'neutral'}
                    />
                  </div>

                  {/* Detailed Analysis */}
                  <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
                    <div className="xl:col-span-1 space-y-6">
                      {/* Email Sanity Check */}
                      <div className="glass-panel p-6">
                        <h3 className="text-sm font-semibold text-zinc-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                          <Mail size={16} />
                          Email Sanity Check
                        </h3>
                        <div className="space-y-3">
                          <div className="flex items-center justify-between text-sm py-2 border-b border-white/5">
                            <span className="text-zinc-500">Provider</span>
                            <span className="font-mono text-zinc-300">{result.emailHealth.provider}</span>
                          </div>
                          {result.emailHealth.issues.length === 0 ? (
                            <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-start gap-2">
                              <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 shrink-0" />
                              <div className="text-sm text-emerald-200">Email configuration is optimal.</div>
                            </div>
                          ) : (
                            <div className="space-y-2 mt-2">
                              {result.emailHealth.issues.map((issue, idx) => (
                                <div key={idx} className="p-3 rounded bg-orange-500/10 border border-orange-500/20 flex items-start gap-2">
                                  <AlertCircle size={16} className="text-orange-400 mt-0.5 shrink-0" />
                                  <div className="text-sm text-orange-200">{issue}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Technical Findings (Errors with Code) */}
                      <div className="glass-panel p-6">
                        <h3 className="text-sm font-semibold text-zinc-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                          <AlertCircle size={16} className="text-red-400" />
                          Technical Findings
                        </h3>
                        <div className="space-y-4">
                          {!result.ssl.valid && (
                            <div className="p-3 rounded bg-red-500/10 border border-red-500/20">
                              <div className="text-xs font-bold text-red-400 mb-1 uppercase">SSL_ERROR</div>
                              <div className="text-sm text-zinc-300">{result.ssl.error || 'Invalid Certificate'}</div>
                            </div>
                          )}
                          {Object.entries(result.security.headers).filter(([_, v]) => !v).map(([k]) => (
                            <div key={k} className="p-3 rounded bg-orange-500/10 border border-orange-500/20">
                              <div className="text-xs font-bold text-orange-400 mb-1 uppercase">MISSING_HEADER</div>
                              <div className="text-sm text-zinc-300">{k.toUpperCase()} not found. This can lead to {k === 'csp' ? 'XSS attacks' : k === 'hsts' ? 'MITM attacks' : 'security vulnerabilities'}.</div>
                            </div>
                          ))}
                          {result.security.serverHeader && (
                            <div className="p-3 rounded bg-yellow-500/10 border border-yellow-500/20">
                              <div className="text-xs font-bold text-yellow-400 mb-1 uppercase">SERVER_LEAKAGE</div>
                              <div className="text-sm text-zinc-300">Server header exposed: <code className="text-xs bg-black/30 px-1 rounded">{result.security.serverHeader}</code></div>
                            </div>
                          )}
                          {result.dns.mx.length > 0 && !result.dns.spf && (
                            <div className="p-3 rounded bg-blue-500/10 border border-blue-500/20">
                              <div className="text-xs font-bold text-blue-400 mb-1 uppercase">DNS_SPF_MISSING</div>
                              <div className="text-sm text-zinc-300">No SPF record found. Your domain is vulnerable to email spoofing.</div>
                            </div>
                          )}
                          {result.dns.mx.length > 0 && !result.dns.dmarc && (
                            <div className="p-3 rounded bg-blue-500/10 border border-blue-500/20">
                              <div className="text-xs font-bold text-blue-400 mb-1 uppercase">DNS_DMARC_MISSING</div>
                              <div className="text-sm text-zinc-300">No DMARC record found. Email security is incomplete.</div>
                            </div>
                          )}
                          {result.dns.mx.length === 0 && (
                            <div className="p-3 rounded bg-blue-500/10 border border-blue-500/20">
                              <div className="text-xs font-bold text-blue-400 mb-1 uppercase">DNS_MX_MISSING</div>
                              <div className="text-sm text-zinc-300">No mail exchange records detected.</div>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Security Headers */}
                      <div className="glass-panel p-6">
                        <h3 className="text-sm font-semibold text-zinc-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                          <ShieldCheck size={16} />
                          Header Status
                        </h3>
                        <div className="space-y-3">
                          <HeaderItem label="HSTS" active={result.security.headers.hsts} />
                          <HeaderItem label="CSP" active={result.security.headers.csp} />
                          <HeaderItem label="X-Frame-Options" active={result.security.headers.xfo} />
                          <HeaderItem label="Referrer Policy" active={result.security.headers.referrer} />
                          <HeaderItem label="Permissions Policy" active={result.security.headers.permissions} />
                          <HeaderItem label="No-Sniff" active={result.security.headers.nosniff} />
                        </div>
                      </div>

                      {/* Exposures */}
                      {result.security.exposures.length > 0 && (
                        <div className="glass-panel p-6 border-red-500/20 bg-red-500/5">
                          <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                            <FileWarning size={16} />
                            Security Risks
                          </h3>
                          <div className="space-y-2">
                            {result.security.exposures.map(exp => (
                              <div key={exp} className="flex items-center justify-between text-sm p-2 rounded bg-red-500/10 border border-red-500/20 text-red-200">
                                <span>{exp.endsWith('/') ? `Directory Listing (${exp})` : `/${exp}`}</span>
                                <ExternalLink size={14} className="opacity-50" />
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {result.vite?.deepScan?.enabled && result.vite.deepScan.findings.length > 0 && (
                        <div className="glass-panel p-6 border-orange-500/20 bg-orange-500/5">
                          <h3 className="text-sm font-semibold text-orange-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                            <Cpu size={16} />
                            Vite Deep Scan
                          </h3>
                          <div className="space-y-2">
                            {result.vite.deepScan.findings.map((f) => (
                              <div key={f.path} className="text-sm p-2 rounded bg-orange-500/10 border border-orange-500/20 text-orange-200">
                                <span className="font-mono">/{f.path}</span> — {f.message}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* AI Fix Guide */}
                    <div className="xl:col-span-2">
                      <div className="glass-panel p-8 min-h-[400px] flex flex-col">
                        <div className="flex items-center justify-between mb-8">
                          <h3 className="text-xl font-bold flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
                              <CheckCircle2 size={24} />
                            </div>
                            AI Fix Guide
                          </h3>
                          {!result.aiReport && !isAiLoading && (
                            <button 
                              onClick={generateAiReport}
                              className="text-xs bg-emerald-500 hover:bg-emerald-400 text-black font-bold px-4 py-2 rounded-lg transition-all"
                            >
                              Generate Fix Guide
                            </button>
                          )}
                        </div>
                        
                        {isAiLoading && !isChatOpen && (
                          <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 gap-4">
                            <Loader2 className="animate-spin" size={32} />
                            <p>Gemini is analyzing your results for the best fixes...</p>
                          </div>
                        )}

                        {result.aiReport ? (
                          <div className="markdown-body">
                            <ReactMarkdown>{result.aiReport}</ReactMarkdown>
                          </div>
                        ) : !isAiLoading && (
                          <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 border-2 border-dashed border-white/5 rounded-2xl">
                            <Activity size={48} className="mb-4 opacity-20" />
                            <p className="text-sm">Click "Generate Fix Guide" to get AI-powered remediation steps.</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Side Panels */}
          <div className={`${(showHistory || isChatOpen) ? 'lg:col-span-4' : 'hidden'} space-y-6 transition-all`}>
            {/* History Sidebar */}
            {showHistory && (
              <motion.div 
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                className="glass-panel p-6 sticky top-8"
              >
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-bold flex items-center gap-2">
                    <History size={18} className="text-emerald-400" />
                    Audit History
                  </h3>
                  <button onClick={() => setShowHistory(false)} className="text-zinc-500 hover:text-white">
                    <AlertCircle size={18} className="rotate-45" />
                  </button>
                </div>
                
                <div className="space-y-4 max-h-[70vh] overflow-y-auto pr-2 custom-scrollbar">
                  {history.length > 0 ? history.map(audit => (
                    <button 
                      key={audit.id}
                      onClick={() => setResult(audit.results)}
                      className="w-full text-left p-4 rounded-xl bg-white/5 border border-white/5 hover:border-emerald-500/30 transition-all group"
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className="font-semibold text-zinc-200 group-hover:text-emerald-400 transition-colors">{audit.domain}</span>
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${audit.score > 80 ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                          {audit.score}
                        </span>
                      </div>
                      <div className="text-[10px] text-zinc-500 flex items-center gap-2">
                        <Activity size={10} />
                        {new Date(audit.timestamp).toLocaleString()}
                      </div>
                    </button>
                  )) : (
                    <div className="text-center py-12 text-zinc-600 italic">
                      No previous audits found.
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {/* Chat Sidebar */}
            {isChatOpen && result && (
              <motion.div 
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                className="glass-panel flex flex-col h-[80vh] sticky top-8"
              >
                <div className="p-6 border-b border-white/5 flex items-center justify-between">
                  <h3 className="font-bold flex items-center gap-2">
                    <Activity size={18} className="text-blue-400" />
                    Security Chat
                  </h3>
                  <button onClick={() => setIsChatOpen(false)} className="text-zinc-500 hover:text-white">
                    <AlertCircle size={18} className="rotate-45" />
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto p-6 space-y-4 custom-scrollbar">
                  {chatMessages.length === 0 && (
                    <div className="text-center py-12 text-zinc-600 text-sm">
                      Ask a question about the audit results for <strong>{result.domain}</strong>.
                    </div>
                  )}
                  {chatMessages.map((msg, i) => (
                    <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div className={`max-w-[85%] p-3 rounded-2xl text-sm ${msg.role === 'user' ? 'bg-blue-500 text-white rounded-tr-none' : 'bg-zinc-800 text-zinc-300 rounded-tl-none border border-white/5'}`}>
                        <ReactMarkdown>{msg.text}</ReactMarkdown>
                      </div>
                    </div>
                  ))}
                  {isAiLoading && (
                    <div className="flex justify-start">
                      <div className="bg-zinc-800 p-3 rounded-2xl rounded-tl-none border border-white/5">
                        <Loader2 className="animate-spin text-blue-400" size={16} />
                      </div>
                    </div>
                  )}
                </div>

                <form onSubmit={handleSendMessage} className="p-4 border-t border-white/5">
                  <div className="relative">
                    <input 
                      type="text"
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      placeholder="Ask about these results..."
                      className="w-full bg-zinc-950 border border-white/10 rounded-xl px-4 py-2 text-sm focus:border-blue-500 outline-none pr-10"
                    />
                    <button 
                      type="submit"
                      disabled={isAiLoading || !chatInput.trim()}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-blue-400 disabled:opacity-50"
                    >
                      <ChevronRight size={20} />
                    </button>
                  </div>
                </form>
              </motion.div>
            )}
          </div>
        </div>

            {/* Empty State */}
            {!result && !loading && (
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="mt-20 text-center"
              >
                <div className="inline-block p-6 rounded-full bg-zinc-900/50 border border-white/5 mb-8">
                  <ShieldCheck size={64} className="text-zinc-700" />
                </div>
                <h2 className="text-3xl font-bold text-zinc-400">Security Audit Ready</h2>
                <p className="text-zinc-500 mt-4 max-w-md mx-auto">Enter your domain to perform a deep security scan, check for vulnerabilities, and receive AI-powered hardening advice.</p>
              </motion.div>
            )}
          </>
        )}

        {activeTab === 'email' && (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="grid grid-cols-1 md:grid-cols-2 gap-8"
          >
            {/* SMTP Tester */}
            <div className="glass-panel p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-emerald-400 flex items-center gap-2">
                  <Mail size={20} />
                  SMTP Connection Tester
                </h3>
                <div className="flex gap-2">
                  <button 
                    onClick={() => { setSmtpHost('smtp.gmail.com'); setSmtpPort('465'); setSmtpSecure(true); }}
                    className="text-[10px] font-semibold uppercase tracking-wider px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-zinc-400 transition-colors border border-white/10"
                  >
                    Gmail
                  </button>
                  <button 
                    onClick={() => { setSmtpHost('smtp.office365.com'); setSmtpPort('587'); setSmtpSecure(false); }}
                    className="text-[10px] font-semibold uppercase tracking-wider px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-zinc-400 transition-colors border border-white/10"
                  >
                    Outlook
                  </button>
                </div>
              </div>
              <form onSubmit={handleSmtpTest} className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="col-span-2">
                    <label className="block text-xs text-zinc-500 mb-1">SMTP Host</label>
                    <input type="text" value={smtpHost} onChange={e => setSmtpHost(e.target.value)} required className="w-full bg-zinc-900 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-emerald-500 outline-none" placeholder="smtp.example.com" />
                  </div>
                  <div className="col-span-1">
                    <label className="block text-xs text-zinc-500 mb-1">Port</label>
                    <input type="number" value={smtpPort} onChange={e => setSmtpPort(e.target.value)} required className="w-full bg-zinc-900 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-emerald-500 outline-none" placeholder="465" />
                  </div>
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <input type="checkbox" id="secure" checked={smtpSecure} onChange={e => setSmtpSecure(e.target.checked)} className="rounded border-white/10 bg-zinc-900 text-emerald-500 focus:ring-emerald-500" />
                  <label htmlFor="secure" className="text-sm text-zinc-400">Use TLS/SSL (Secure)</label>
                </div>
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">Username (Optional)</label>
                  <input type="text" value={smtpUser} onChange={e => setSmtpUser(e.target.value)} className="w-full bg-zinc-900 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-emerald-500 outline-none" placeholder="user@example.com" />
                </div>
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">Password (Optional)</label>
                  <input type="password" value={smtpPass} onChange={e => setSmtpPass(e.target.value)} className="w-full bg-zinc-900 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-emerald-500 outline-none" placeholder="••••••••" />
                </div>
                <button type="submit" disabled={smtpLoading} className="w-full mt-4 bg-emerald-500 hover:bg-emerald-600 text-white font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50">
                  {smtpLoading ? 'Testing Connection...' : 'Test SMTP Connection'}
                </button>
              </form>

              {smtpResult && (
                <div className={`mt-6 p-4 rounded-lg border ${smtpResult.success ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                  <div className="font-semibold mb-1">{smtpResult.success ? 'Success' : 'Connection Failed'}</div>
                  <div className="text-sm opacity-80">{smtpResult.message || smtpResult.error}</div>
                </div>
              )}
            </div>

            {/* MX Reachability */}
            <div className="glass-panel p-6">
              <h3 className="text-lg font-semibold text-blue-400 mb-6 flex items-center gap-2">
                <Server size={20} />
                MX Reachability Tester
              </h3>
              <p className="text-sm text-zinc-400 mb-6">
                Test if a domain's primary mail server is reachable on port 25 and read its SMTP banner.
              </p>
              <form onSubmit={handleMxTest} className="space-y-4">
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">Domain Name</label>
                  <input type="text" value={mxDomain} onChange={e => setMxDomain(e.target.value)} required className="w-full bg-zinc-900 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-blue-500 outline-none" placeholder="example.com" />
                </div>
                <button type="submit" disabled={mxLoading} className="w-full mt-4 bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50">
                  {mxLoading ? 'Testing MX Server...' : 'Test MX Reachability'}
                </button>
              </form>

              {mxResult && (
                <div className={`mt-6 p-4 rounded-lg border ${mxResult.success ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                  <div className="font-semibold mb-1">{mxResult.success ? 'Server Reachable' : 'Test Failed'}</div>
                  {mxResult.success ? (
                    <div className="space-y-2 mt-2">
                      <div className="text-xs text-zinc-500">Primary MX: <span className="text-zinc-300 font-mono">{mxResult.mx}</span></div>
                      <div className="text-xs text-zinc-500">Banner:</div>
                      <pre className="text-[10px] font-mono bg-black/30 p-2 rounded text-zinc-300 whitespace-pre-wrap">{mxResult.banner}</pre>
                    </div>
                  ) : (
                    <div className="text-sm opacity-80">{mxResult.error}</div>
                  )}
                </div>
              )}
            </div>

            {/* Email Health Audit */}
            <div className="glass-panel p-6 md:col-span-2">
              <h3 className="text-lg font-semibold text-purple-400 mb-6 flex items-center gap-2">
                <ShieldCheck size={20} />
                Domain Email Health Audit
              </h3>
              <p className="text-sm text-zinc-400 mb-6">
                Perform an MXTools-style audit to detect the email provider (Google Workspace, Microsoft 365, etc.) and check SPF/DMARC health.
              </p>
              <form onSubmit={handleEmailAudit} className="flex gap-4">
                <input type="text" value={emailAuditDomain} onChange={e => setEmailAuditDomain(e.target.value)} required className="flex-1 bg-zinc-900 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-purple-500 outline-none" placeholder="example.com" />
                <button type="submit" disabled={emailAuditLoading} className="bg-purple-500 hover:bg-purple-600 text-white font-medium py-2 px-6 rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap">
                  {emailAuditLoading ? 'Auditing...' : 'Run Audit'}
                </button>
              </form>

              {emailAuditResult && (
                <div className="mt-8 space-y-6">
                  {emailAuditResult.success ? (
                    <>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <StatCard 
                          icon={<Server size={18} className="text-purple-400" />}
                          label="Email Provider"
                          value={emailAuditResult.data.provider}
                          status={emailAuditResult.data.provider !== 'None' ? 'success' : 'error'}
                        />
                        <StatCard 
                          icon={<ShieldCheck size={18} className="text-emerald-400" />}
                          label="SPF Record"
                          value={emailAuditResult.data.spf ? 'Found' : 'Missing'}
                          status={emailAuditResult.data.spf ? 'success' : 'error'}
                        />
                        <StatCard 
                          icon={<Lock size={18} className="text-blue-400" />}
                          label="DMARC Record"
                          value={emailAuditResult.data.dmarc ? 'Found' : 'Missing'}
                          status={emailAuditResult.data.dmarc ? 'success' : 'error'}
                        />
                      </div>

                      {emailAuditResult.data.issues.length > 0 && (
                        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
                          <h4 className="text-red-400 font-semibold mb-2 flex items-center gap-2">
                            <AlertCircle size={16} />
                            Security Issues Detected
                          </h4>
                          <ul className="list-disc list-inside text-sm text-red-300/80 space-y-1">
                            {emailAuditResult.data.issues.map((issue: string, i: number) => (
                              <li key={i}>{issue}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-black/20 border border-white/5 rounded-xl p-4">
                          <RecordGroup label="MX Records" items={emailAuditResult.data.mx.map((m: any) => `${m.priority} ${m.exchange}`)} />
                        </div>
                        <div className="bg-black/20 border border-white/5 rounded-xl p-4">
                          <RecordGroup label="TXT Records" items={emailAuditResult.data.txt} />
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
                      <div className="font-semibold mb-1">Audit Failed</div>
                      <div className="text-sm opacity-80">{emailAuditResult.error}</div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Email Diagnostics AI Chat */}
            <div className="glass-panel p-6 md:col-span-2 flex flex-col h-[500px]">
              <h3 className="text-lg font-semibold text-blue-400 mb-4 flex items-center gap-2">
                <Activity size={20} />
                MX Diagnostics AI
              </h3>
              
              <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-black/20 rounded-xl border border-white/5 mb-4">
                {emailChatMessages.length === 0 && (
                  <div className="text-center py-12 text-zinc-600 text-sm">
                    Run an SMTP or MX test above, then ask me to diagnose the results.
                  </div>
                )}
                {emailChatMessages.map((msg, i) => (
                  <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[85%] p-3 rounded-2xl text-sm ${msg.role === 'user' ? 'bg-blue-500 text-white rounded-tr-none' : 'bg-zinc-800 text-zinc-300 rounded-tl-none border border-white/5'}`}>
                      <ReactMarkdown>{msg.text}</ReactMarkdown>
                    </div>
                  </div>
                ))}
                {isEmailAiLoading && (
                  <div className="flex justify-start">
                    <div className="bg-zinc-800 p-3 rounded-2xl rounded-tl-none border border-white/5">
                      <Loader2 className="animate-spin text-blue-400" size={16} />
                    </div>
                  </div>
                )}
              </div>

              <form onSubmit={handleEmailSendMessage} className="relative">
                <input 
                  type="text"
                  value={emailChatInput}
                  onChange={(e) => setEmailChatInput(e.target.value)}
                  placeholder="Ask the diagnostic AI..."
                  className="w-full bg-zinc-950 border border-white/10 rounded-xl px-4 py-3 text-sm focus:border-blue-500 outline-none pr-12"
                />
                <button 
                  type="submit"
                  disabled={isEmailAiLoading || !emailChatInput.trim()}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-blue-400 disabled:opacity-50 p-2 hover:bg-white/5 rounded-lg transition-colors"
                >
                  <ChevronRight size={20} />
                </button>
              </form>
            </div>
          </motion.div>
        )}
      </main>

      <footer className="max-w-7xl mx-auto px-6 py-12 border-t border-white/5 text-center text-zinc-600 text-sm">
        <p>© 2026 DNS Sentinel Security Suite. Authorized webmaster access only.</p>
      </footer>
    </div>
  );
}

function StatCard({ icon, label, value, subValue, status }: { 
  icon: React.ReactNode, 
  label: string, 
  value: string, 
  subValue?: string,
  status: 'success' | 'warning' | 'error' | 'neutral'
}) {
  const glowClass = {
    success: 'status-glow-green border-emerald-500/20',
    warning: 'status-glow-blue border-blue-500/20',
    error: 'status-glow-red border-red-500/20',
    neutral: 'border-white/10'
  }[status];

  return (
    <div className={`glass-panel p-5 transition-all hover:scale-[1.02] ${glowClass}`}>
      <div className="flex items-center gap-3 mb-3">
        <div className="p-2 rounded-lg bg-white/5">
          {icon}
        </div>
        <span className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">{label}</span>
      </div>
      <div className="text-xl font-bold mb-1">{value}</div>
      {subValue && <div className="text-xs text-zinc-500 truncate">{subValue}</div>}
    </div>
  );
}

function HeaderItem({ label, active }: { label: string, active: boolean }) {
  return (
    <div className="flex items-center justify-between text-sm py-1">
      <span className={active ? 'text-zinc-300' : 'text-zinc-500'}>{label}</span>
      {active ? (
        <CheckCircle2 size={14} className="text-emerald-500" />
      ) : (
        <AlertCircle size={14} className="text-red-500/50" />
      )}
    </div>
  );
}

function RecordGroup({ label, items }: { label: string, items: string[] }) {
  return (
    <div>
      <div className="text-[10px] font-bold text-zinc-600 uppercase mb-2 tracking-widest">{label}</div>
      <div className="space-y-1">
        {items.length > 0 ? items.map((item, i) => (
          <div key={i} className="text-[11px] font-mono text-zinc-400 truncate bg-white/5 px-2 py-1 rounded border border-white/5">
            {item}
          </div>
        )) : (
          <div className="text-[10px] italic text-zinc-700">None</div>
        )}
      </div>
    </div>
  );
}
