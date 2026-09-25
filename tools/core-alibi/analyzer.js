/*
 * Core Alibi analyzer: turns an Open5GS + Kamailio IMS + RTPEngine "all.log"
 * (lines prefixed "[YYYY-MM-DD HH:MM:SS] [SOURCE] ...") into per-UE and per-call
 * verdicts on whether the core/IMS or the radio/phone side ended each service.
 *
 * Browser: exposes window.CoreAlibi. Node: `node analyzer.js all.log [ping_*.log ...] [--json out.json]`.
 * Times are wall-clock milliseconds encoded as if UTC (render with getUTC*).
 */
(function (root) {
  'use strict';

  const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const OPEN5GS_NF = new Set(['AMF', 'SMF', 'UPF', 'PCF', 'SCP', 'NRF', 'AUSF', 'UDM', 'UDR', 'BSF', 'NSSF', 'SEPP', 'MME', 'SGWC', 'SGWU', 'HSS', 'PCRF']);

  const RADIO_CAUSE = ['unspecified', 'txnrelocoverall-expiry', 'successful-handover', 'release-due-to-ngran-generated-reason',
    'release-due-to-5gc-generated-reason', 'handover-cancelled', 'partial-handover', 'ho-failure-in-target-5GC-ngran-node-or-target-system',
    'ho-target-not-allowed', 'tngrelocoverall-expiry', 'tngrelocprep-expiry', 'cell-not-available', 'unknown-targetID',
    'no-radio-resources-available-in-target-cell', 'unknown-local-UE-NGAP-ID', 'inconsistent-remote-UE-NGAP-ID',
    'handover-desirable-for-radio-reason', 'time-critical-handover', 'resource-optimisation-handover', 'reduce-load-in-serving-cell',
    'user-inactivity', 'radio-connection-with-ue-lost', 'radio-resources-not-available', 'invalid-qos-combination',
    'failure-in-radio-interface-procedure', 'interaction-with-other-procedure', 'unknown-PDU-session-ID', 'unknown-qos-flow-ID',
    'multiple-PDU-session-ID-instances', 'multiple-qos-flow-ID-instances', 'encryption-and-or-integrity-protection-algorithms-not-supported',
    'ng-intra-system-handover-triggered', 'ng-inter-system-handover-triggered', 'xn-handover-triggered', 'not-supported-5QI-value',
    'ue-context-transfer', 'ims-voice-eps-fallback-or-rat-fallback-triggered', 'up-integrity-protection-not-possible',
    'up-confidentiality-protection-not-possible', 'slice-not-supported', 'ue-in-rrc-inactive-state-not-reachable', 'redirection',
    'resources-not-available-for-the-slice', 'ue-max-integrity-protected-data-rate-reason', 'release-due-to-cn-detected-mobility'];
  const CAUSE_GROUP = {
    1: ['radioNetwork', RADIO_CAUSE],
    2: ['transport', ['transport-resource-unavailable', 'unspecified']],
    3: ['nas', ['normal-release', 'authentication-failure', 'deregister', 'unspecified']],
    4: ['protocol', ['transfer-syntax-error', 'abstract-syntax-error-reject', 'abstract-syntax-error-ignore-and-notify',
      'message-not-compatible-with-receiver-state', 'semantic-error', 'abstract-syntax-error-falsely-constructed-message', 'unspecified']],
    5: ['misc', ['control-processing-overload', 'not-enough-user-plane-processing-resources', 'hardware-failure', 'om-intervention',
      'unknown-PLMN-or-SNPN', 'unspecified']]
  };
  function causeText(g, c) {
    const grp = CAUSE_GROUP[g];
    if (!grp) return `cause ${g}/${c}`;
    return `${grp[0]}: ${grp[1][c] || 'cause ' + c}`;
  }

  const IP_RE = /\d{1,3}(?:\.\d{1,3}){3}/;
  const hexIp = (h) => [0, 2, 4, 6].map((i) => parseInt(h.slice(i, i + 2), 16)).join('.');
  const userOf = (uri) => { const m = /^(?:sips?|tel):\+?([^@;>]+)/.exec(uri || ''); return m ? m[1] : null; };
  const isImsi = (u) => !!u && /^\d{14,15}$/.test(u);
  const imsiFromSuci = (s) => { const m = /suci-\d+-(\d{3})-(\d{2,3})-\d+-\d+-\d+-(\d+)/.exec(s); return m ? m[1] + m[2] + m[3] : null; };

  function createAnalyzer(opts) {
    opts = opts || {};
    const S = {
      lines: 0, bytes: 0, start: null, end: null, sources: {}, tzOffsetSec: null,
      dedupe: new Set(), dedupeQ: [], dedupeMax: 60000,
      prefixKey: '', prefixYear: 0, prefixMs: 0,
      pendInit: null, pendRel: null, pendSpoof: null,
      ran: [], core: [], sessions: [], causes: [], qosRejects: [], smCtx: [], trig: [],
      lifecycle: [], pfcp: [], gnb: [], tun: [], eagain: [], spoof: [], errors: new Map(),
      ipMap: [], msisdnMap: new Map(), lastImpu: null,
      sip: [], coreSipIPs: new Set(), dialogs: new Map(), imsMarkers: [], imsTcp: [],
      rtp: new Map(), pings: []
    };

    function seen(key) {
      if (S.dedupe.has(key)) return true;
      S.dedupe.add(key); S.dedupeQ.push(key);
      if (S.dedupeQ.length > S.dedupeMax) S.dedupe.delete(S.dedupeQ.shift());
      return false;
    }
    function prefixTime(line) {
      const k = line.slice(1, 20);
      if (k !== S.prefixKey) {
        S.prefixKey = k;
        S.prefixYear = +k.slice(0, 4);
        S.prefixMs = Date.UTC(S.prefixYear, +k.slice(5, 7) - 1, +k.slice(8, 10), +k.slice(11, 13), +k.slice(14, 16), +k.slice(17, 19));
      }
      return S.prefixMs;
    }
    function sysTime(rest) {
      const m = /^([A-Z][a-z]{2}) +(\d+) (\d\d):(\d\d):(\d\d)/.exec(rest);
      if (!m || MON[m[1]] === undefined) return S.prefixMs;
      return Date.UTC(S.prefixYear, MON[m[1]], +m[2], +m[3], +m[4], +m[5]);
    }
    function mapIp(ip, imsi, t, via) { if (ip && imsi && ip !== '0.0.0.0') S.ipMap.push({ ip, imsi, t, via }); }
    function addError(comp, level, msg, t) {
      const tpl = msg.replace(/\(\.\.\/[^)]*\)/g, '').replace(/imsi-\d+|suci-[\d-]+/g, '<UE>').replace(IP_RE, '<IP>')
        .replace(/0x[0-9a-f]+/gi, '<X>').replace(/\d+/g, 'N').replace(/\s+/g, ' ').trim().slice(0, 160);
      const key = comp + '|' + tpl;
      let e = S.errors.get(key);
      if (!e) { e = { comp, level, template: tpl, sample: msg.slice(0, 240), count: 0, first: t, last: t }; S.errors.set(key, e); }
      e.count++; e.last = t;
    }

    function onOpen5gs(nf, rest) {
      const m = /(\d\d)\/(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}): \[([\w-]+)\] (\w+): (.*)$/.exec(rest);
      if (!m) return;
      const payloadKey = nf + '|' + rest.slice(m.index);
      if (seen(payloadKey)) return;
      const t = Date.UTC(S.prefixYear, +m[1] - 1, +m[2], +m[3], +m[4], +m[5], +m[6]);
      const mod = m[7], lvl = m[8];
      const msg = m[9].replace(/\s*\(\.\.\/(?:src|lib)\/[^)]*\)\s*$/, '');
      const body = msg.trim();
      if (lvl === 'ERROR' || lvl === 'FATAL') addError(nf, lvl, body, t);

      // NF lifecycle
      if (/initialize\.\.\.done/.test(body)) S.lifecycle.push({ t, nf, kind: 'start' });
      else if (/SIGTERM received/.test(body)) S.lifecycle.push({ t, nf, kind: 'stop' });
      else if (lvl === 'FATAL' || /Failed to initialize/.test(body)) S.lifecycle.push({ t, nf, kind: 'crash', text: body });

      if (/PFCP (de-)?associated/.test(body)) {
        const pm = /PFCP (de-)?associated \[?([\d.]+)/.exec(body);
        S.pfcp.push({ t, nf, up: !pm[1], peer: pm[2] });
      }

      if (nf === 'AMF') return onAmf(t, mod, lvl, body, msg);
      if (nf === 'SMF') return onSmf(t, lvl, body);
      if (nf === 'UPF') return onUpf(t, lvl, body);
    }

    function onAmf(t, mod, lvl, body, msg) {
      let mm;
      if (body === 'InitialUEMessage') { S.pendInit = { t, imsi: null, kind: null, rlf: false }; return; }
      if (/^UE Context Release \[Action:(\d)\]/.test(body)) {
        S.pendRel = { t, action: +/Action:(\d)/.exec(body)[1] }; return;
      }
      if ((mm = /^SUCI\[(suci-[^\]]+)\]/.exec(body))) {
        const imsi = imsiFromSuci(mm[1]);
        if (S.pendRel && t - S.pendRel.t <= 50) { S.ran.push({ t: S.pendRel.t, imsi, type: 'release', action: S.pendRel.action }); S.pendRel = null; return; }
        if (S.pendInit && t - S.pendInit.t <= 50 && !S.pendInit.imsi) { S.pendInit.imsi = imsi; flushInit(); }
        return;
      }
      if ((mm = /^\[(suci-[^\]]+)\]\s+(?:5G-S_TMSI|Known UE by 5G-S_TMSI)/.exec(body))) {
        if (S.pendInit && t - S.pendInit.t <= 50 && !S.pendInit.imsi) { S.pendInit.imsi = imsiFromSuci(mm[1]); flushInit(); }
        return;
      }
      if ((mm = /^\[(suci-[^\]]+|imsi-\d+)\] Holding NG Context/.exec(body))) {
        const imsi = mm[1].startsWith('imsi') ? mm[1].slice(5) : imsiFromSuci(mm[1]);
        S.ran.push({ t, imsi, type: 'rlf' }); return;
      }
      if (mod === 'gmm' && /^(Registration|Service) request$/.test(body)) {
        const last = S.ran.length ? S.ran[S.ran.length - 1] : null;
        if (last && last.type === 'reconnect' && t - last.t <= 50 && !last.kind) last.kind = body.startsWith('Reg') ? 'registration' : 'service';
        else if (S.pendInit && t - S.pendInit.t <= 50) S.pendInit.kind = body.startsWith('Reg') ? 'registration' : 'service';
        return;
      }
      if ((mm = /^\[imsi-(\d+)\] (?:De-?[Rr]egistration request)/.exec(body))) { S.ran.push({ t, imsi: mm[1], type: 'ue_dereg' }); return; }
      if ((mm = /^\[imsi-(\d+)\] Registration complete/.exec(body))) { S.ran.push({ t, imsi: mm[1], type: 'reg_complete' }); return; }
      if ((mm = /^\[imsi-(\d+):(\d+):(\d+)\]\[/.exec(body))) {
        const st = +mm[3];
        if ([12, 51, 52, 53].includes(st)) S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: st });
        if (st === 11 || st === 16) S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: st });
        return;
      }
      if ((mm = /^\[imsi-(\d+):(\d+)\] Receive Update SM context\(([A-Z0-9_-]+)\)/.exec(body))) {
        S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: mm[3] }); return;
      }
      if ((mm = /^\[imsi-(\d+):(\d+)\] Release SM [Cc]ontext \[state:(\d+)\]/.exec(body))) {
        S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: 'REL' + mm[3] }); return;
      }
      if (/No PDUSessionResourceModifyListModRes/.test(body)) { S.qosRejects.push({ t }); return; }
      if ((mm = /^\[imsi-(\d+)\] (Mobile Reachable Timer Expired|Implicit De-registered|Do Network-initiated De-register UE|Paging failed\. Stop)/.exec(body))) {
        S.core.push({ t, imsi: mm[1], type: mm[2].startsWith('Paging') ? 'paging_failed' : mm[2].startsWith('Mobile') ? 'mobile_unreachable' : mm[2].startsWith('Implicit') ? 'implicit_dereg' : 'net_dereg' });
        return;
      }
      if ((mm = /gNB-N2\[([\d.]+)\] connection refused/.exec(body))) { S.gnb.push({ t, type: 'link_lost', ip: mm[1] }); return; }
      if ((mm = /gNB-N2 accepted\[([\d.]+)\]/.exec(body))) { S.gnb.push({ t, type: 'link_up', ip: mm[1] }); return; }
      if (/^NGReset/.test(body)) { S.gnb.push({ t, type: 'ng_reset' }); return; }
      if ((mm = /Number of gNBs is now (\d+)/.exec(body))) { S.gnb.push({ t, type: 'count', n: +mm[1] }); return; }
      if ((mm = /LOCAL \[[^\]]+\] Timezone\[(-?\d+)\]/.exec(body))) { S.tzOffsetSec = +mm[1]; return; }
      if (/reject/i.test(body) && !/Unsuccessful/.test(body)) {
        const im = /imsi-(\d+)/.exec(body), sm = /(suci-[\d-]+)/.exec(body);
        S.core.push({ t, imsi: im ? im[1] : sm ? imsiFromSuci(sm[1]) : null, type: 'reject', text: body });
      }
    }
    function flushInit() {
      const p = S.pendInit; S.pendInit = null;
      if (p && p.imsi) S.ran.push({ t: p.t, imsi: p.imsi, type: 'reconnect', kind: p.kind });
    }

    function onSmf(t, lvl, body) {
      let mm;
      if ((mm = /Cause\[Group:(\d+) Cause:(\d+)\]/.exec(body))) { S.causes.push({ t, g: +mm[1], c: +mm[2] }); return; }
      if ((mm = /UE SUPI\[imsi-(\d+)\] DNN\[([^\]]+)\] IPv4\[([\d.]*)\]/.exec(body))) {
        S.sessions.push({ t, imsi: mm[1], dnn: mm[2], ip: mm[3], up: true }); mapIp(mm[3], mm[1], t, 'smf'); return;
      }
      if ((mm = /Removed Session: UE IMSI:\[imsi-(\d+)\] DNN:\[([^:\]]+):(\d+)\] IPv4:\[([\d.]*)\]/.exec(body))) {
        S.sessions.push({ t, imsi: mm[1], dnn: mm[2], psi: +mm[3], ip: mm[4], up: false }); mapIp(mm[4], mm[1], t, 'smf'); return;
      }
      if ((mm = /^\[imsi-(\d+):(\d+)\] Session Release \[PFCP-Delete-Trigger:(\d+)\]/.exec(body))) {
        S.trig.push({ t, imsi: mm[1], psi: +mm[2], trigger: +mm[3] });
      }
    }

    function onUpf(t, lvl, body) {
      let mm;
      if (/ogs_tun_write\(\) failed/.test(body)) { S.tun.push(t); return; }
      if (/ogs_sendto\(\) failed \(11:/.test(body)) { S.eagain.push(t); return; }
      if ((mm = /Source IP-4 Spoofing APN:(\S+)/.exec(body))) { S.pendSpoof = { t, apn: mm[1] }; return; }
      if ((mm = /SRC:([0-9A-F]{8}), UE:([0-9A-F]{8})/.exec(body)) && S.pendSpoof) {
        S.spoof.push({ t: S.pendSpoof.t, apn: S.pendSpoof.apn, src: hexIp(mm[1]), ue: hexIp(mm[2]) }); S.pendSpoof = null;
      }
    }

    function onKamailio(tag, rest) {
      let mm;
      if (tag === 'SCSCF') {
        if (rest.includes('Dialog call-id: ')) {
          const cid = rest.slice(rest.indexOf('Dialog call-id: ') + 16).trim();
          const d = S.dialogs.get(cid);
          if (d) d.last = S.prefixMs; else S.dialogs.set(cid, { first: S.prefixMs, last: S.prefixMs });
          return;
        }
        if (rest.includes('Public Identity ')) {
          mm = /Public Identity (?:tel:|sips?:)\+?(\d+)/.exec(rest); S.lastImpu = mm ? mm[1] : null; return;
        }
        if (rest.includes('Contact #')) {
          mm = /Contact #\d+ - sips?:(\d+)@(\d{1,3}(?:\.\d{1,3}){3})/.exec(rest);
          if (mm) {
            if (isImsi(mm[1])) {
              mapIp(mm[2], mm[1], S.prefixMs, 'ims-contact');
              if (S.lastImpu && !isImsi(S.lastImpu)) S.msisdnMap.set(S.lastImpu, mm[1]);
            }
          }
          return;
        }
        if (rest.includes('contact in the new contact list')) {
          mm = /= \[sips?:(\d+)@[^\]]*\] \(sips?:\d+@(\d{1,3}(?:\.\d{1,3}){3})/.exec(rest);
          if (mm && isImsi(mm[1])) mapIp(mm[2], mm[1], S.prefixMs, 'ims-contact');
          return;
        }
      }
      const isReq = rest.includes('CSCF: ');
      const isErr = rest.includes(' ERROR: ') || rest.includes(' CRITICAL: ');
      const isMark = /dlg_ontimeout|dlg_terminate|Sorry no QoS|Connection timed out|failed \(timeout\)/.test(rest);
      if (!isReq && !isErr && !isMark) return;
      if (seen(tag + '|' + rest)) return;
      const t = sysTime(rest);
      if (isReq && (mm = /(PCSCF|SCSCF|ICSCF): ([A-Z]+) (\S+) \((\S+) \(([0-9a-fA-F.:]+?):(\d+)\) to (.+?), (\S+)\)\s*$/.exec(rest))) {
        const [, node, method, ruri, from, srcIp, , to, cid] = mm;
        if (node !== 'PCSCF') { S.coreSipIPs.add(srcIp); return; }
        const rIp = (/@(\d{1,3}(?:\.\d{1,3}){3})/.exec(ruri) || [])[1] || null;
        S.sip.push({ t, method, ruriUser: userOf(ruri), ruriIp: rIp, fromUser: userOf(from), toUser: userOf(to), srcIp, cid });
        if (method === 'REGISTER' && isImsi(userOf(from))) mapIp(srcIp, userOf(from), t, 'register');
        return;
      }
      if ((mm = /Connection timed out \(110\) \(\[([\d.]+)\]:(\d+)/.exec(rest))) S.imsTcp.push({ t, ip: mm[1], port: +mm[2], node: tag });
      if (/dlg_ontimeout|dlg_terminate|Sorry no QoS/.test(rest)) S.imsMarkers.push({ t, node: tag, text: rest.replace(/^.*?(?:NOTICE|INFO|DEBUG|ERROR|WARNING): /, '').slice(0, 200) });
      if (isErr) {
        const em = /(ERROR|CRITICAL): (.*)$/.exec(rest);
        if (em && !/Connection timed out|tcp_read_req|failed \(timeout\)/.test(em[2])) addError(tag, em[1], em[2].replace(/^<[^>]+> /, ''), t);
      }
    }

    function onRtpengine(rest) {
      const mm = /rtpengine\[\d+\]: (\w+): \[([^\]\s]+)(?: port \d+)?\]: (.*)$/.exec(rest);
      if (!mm) {
        const em = /rtpengine\[\d+\]: (ERR|CRIT|ALERT|EMERG): (.*)$/.exec(rest);
        if (em) addError('RTPENGINE', em[1], em[2], sysTime(rest));
        return;
      }
      if (seen('RTP|' + rest)) return;
      const t = sysTime(rest), lvl = mm[1], cid = mm[2], msg = mm[3];
      let c = S.rtp.get(cid);
      if (!c) { c = { created: t, del: null, timeoutClose: null, streams: [], media: [], mos: {}, statsT: null, curTag: null, tagStreams: 0, pendSsrc: null }; S.rtp.set(cid, c); }
      let m;
      if (/^Received command 'delete'/.test(msg)) { if (!c.del) c.del = t; return; }
      if (/^Closing call due to timeout/.test(msg)) { c.timeoutClose = t; return; }
      if (/^Final packet stats:/.test(msg)) { c.statsT = t; return; }
      if ((m = /^--- Tag '([^']*)', created (\d+):(\d\d) ago/.exec(msg))) {
        c.curTag = m[1]; c.tagRtpIdx = 0; c.tagMedia = []; if (c.statsT) c.created = Math.min(c.created, c.statsT - ((+m[2]) * 60 + (+m[3])) * 1000); return;
      }
      if ((m = /^------ Media #(\d+) \((\w+) over/.exec(msg))) { c.tagMedia.push(m[2]); if (!c.media[+m[1] - 1]) c.media[+m[1] - 1] = m[2]; return; }
      if ((m = /^--------- Port\s+(\S+)\s+<>\s+(\S+?)\s*(\(RTCP\))?\s*, SSRC (\w+), (\d+) p, (\d+) b, (\d+) e, (\d+) ts/.exec(msg))) {
        const rip = (IP_RE.exec(m[2]) || [])[0] || null;
        const rtcp = !!m[3];
        if (!rtcp) c.tagRtpIdx = (c.tagRtpIdx || 0) + 1;
        const idx = Math.max(0, (c.tagRtpIdx || 1) - 1);
        const media = c.media[idx] || c.tagMedia[idx] || (idx === 0 ? 'audio' : 'video');
        c.streams.push({ tag: c.curTag, localDisabled: /^0\.0\.0\.0:0$/.test(m[1]), ip: rip, port: +(m[2].split(':')[1] || 0), rtcp, ssrc: m[4], packets: +m[5], bytes: +m[6], errors: +m[7], lastT: (c.statsT || t) - (+m[8]) * 1000, media });
        return;
      }
      if ((m = /^--- SSRC (\w+)/.exec(msg))) { c.pendSsrc = m[1]; return; }
      if ((m = /^------ Average MOS ([\d.]+), lowest MOS ([\d.]+)/.exec(msg)) && c.pendSsrc) { c.mos[c.pendSsrc] = { avg: +m[1], low: +m[2] }; c.pendSsrc = null; }
      if (lvl === 'ERR' || lvl === 'CRIT') addError('RTPENGINE', lvl, msg, t);
    }

    function pushLine(line) {
      S.lines++; S.bytes += line.length + 1;
      if (line.charCodeAt(0) !== 91 || line.charCodeAt(20) !== 93) return;
      const tagEnd = line.indexOf(']', 23);
      if (tagEnd < 0) return;
      let tag = line.slice(23, tagEnd);
      const rest = line.slice(tagEnd + 2);
      const t0 = prefixTime(line);
      if (S.start === null || t0 < S.start) S.start = t0;
      if (S.end === null || t0 > S.end) S.end = t0;
      S.sources[tag] = (S.sources[tag] || 0) + 1;
      if (tag.endsWith('-FILE')) tag = tag.slice(0, -5);
      if (OPEN5GS_NF.has(tag)) return onOpen5gs(tag, rest);
      if (tag === 'PCSCF' || tag === 'SCSCF' || tag === 'ICSCF') return onKamailio(tag, rest);
      if (tag === 'RTPENGINE') return onRtpengine(rest);
      if (/ERROR|Exception|SEVERE/.test(rest)) addError(tag, 'ERROR', rest.replace(/^[A-Z][a-z]{2} +\d+ [\d:]+ \S+ /, ''), sysTime(rest));
    }

    // ping_<ip>.log: lastModifiedEpochMs is the file's mtime (epoch, UTC)
    function addPingFile(name, text, lastModifiedEpochMs) {
      const ipm = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(name || '');
      const replies = []; let lostAfter = 0;
      const lines = (text || '').split(/\r?\n/);
      for (const ln of lines) {
        if (!ln) continue;
        const ok = /bytes from/.test(ln);
        let t = null, m;
        if ((m = /^\[(\d{9,11}(?:\.\d+)?)\]/.exec(ln))) t = { epoch: +m[1] * 1000 };
        else if ((m = /(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)/.exec(ln))) t = { wall: Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) };
        if (ok) replies.push(t); else if (/no answer|Unreachable|timeout|100% packet loss/i.test(ln)) lostAfter++;
      }
      S.pings.push({ ip: ipm ? ipm[1] : name, name, replies: replies.length, firstTs: replies.find((r) => r) || null,
        lastTs: [...replies].reverse().find((r) => r) || null, mtimeEpoch: lastModifiedEpochMs || null, empty: replies.length === 0 });
    }
    function addPingManual(ip, lastReplyWall, note) { S.pings.push({ ip, name: note || 'manual', replies: 1, manualWall: lastReplyWall }); }

    function finish(extra) { return buildResult(S, Object.assign({}, opts, extra || {})); }
    return { pushLine, addPingFile, addPingManual, finish, state: S };
  }

  /* ------------------------------------------------------------------ */
  function buildResult(S, opts) {
    const logStart = S.start, logEnd = S.end;
    const tz = S.tzOffsetSec !== null ? S.tzOffsetSec : (opts.tzOffsetSec !== undefined ? opts.tzOffsetSec : 0);
    const wallFromEpoch = (e) => e + tz * 1000;
    const fmt = (t) => t == null ? '—' : new Date(t).toISOString().slice(11, 19);

    // ---- IP -> IMSI (time-aware) ----
    // SMF session records are authoritative; REGISTER next; S-CSCF contacts last (they can be stale for days)
    const ipHist = new Map();
    for (const r of S.ipMap) { if (!ipHist.has(r.ip)) ipHist.set(r.ip, []); ipHist.get(r.ip).push(r); }
    for (const v of ipHist.values()) v.sort((a, b) => a.t - b.t);
    function imsiForIp(ip, t) {
      const h = ipHist.get(ip); if (!h) return null;
      const q = t || Infinity;
      for (const via of ['smf', 'register', 'ims-contact']) {
        const xs = h.filter((r) => r.via === via);
        if (!xs.length) continue;
        let best = null;
        for (const r of xs) { if (r.t <= q) best = r; else break; }
        if (best) return best.imsi;
      }
      return h[0].imsi;
    }
    // UE IPs = P-CSCF request sources that never appear as S-CSCF/I-CSCF sources
    const ueIPs = new Set();
    for (const r of S.sip) if (!S.coreSipIPs.has(r.srcIp) && r.srcIp !== '127.0.0.1') ueIPs.add(r.srcIp);
    for (const r of S.sip) {
      if (!ueIPs.has(r.srcIp)) continue;
      if (r.fromUser && !isImsi(r.fromUser) && (r.method === 'INVITE' || r.method === 'UPDATE' || r.method === 'BYE')) {
        const im = imsiForIp(r.srcIp, r.t); if (im && !S.msisdnMap.has(r.fromUser)) S.msisdnMap.set(r.fromUser, im);
      }
    }
    const imsiForUser = (u) => !u ? null : isImsi(u) ? u : (S.msisdnMap.get(u) || null);

    // ---- UEs ----
    const ues = new Map();
    function ue(imsi) {
      if (!imsi) return null;
      let u = ues.get(imsi);
      if (!u) {
        u = { imsi, msisdn: [], ips: {}, events: [], calls: [], last: {}, findings: [] };
        ues.set(imsi, u);
      }
      return u;
    }
    for (const [ms, im] of S.msisdnMap) { const u = ue(im); if (!u.msisdn.includes(ms)) u.msisdn.push(ms); }
    for (const r of S.ipMap) {
      const u = ue(r.imsi); const dnn = r.via === 'smf' ? null : 'ims';
      const s = S.sessions.find((x) => x.ip === r.ip && x.imsi === r.imsi);
      const key = s ? s.dnn : (dnn || 'ims');
      u.ips[key] = u.ips[key] || [];
      if (!u.ips[key].includes(r.ip)) u.ips[key].push(r.ip);
    }
    const ev = (imsi, e) => { const u = ue(imsi); if (u) u.events.push(e); return u; };

    // ---- causes -> setup failures / releases ----
    const nearestCause = (t) => {
      let best = null;
      for (const c of S.causes) { const d = Math.abs(c.t - t); if (d <= 1500 && (!best || d < best.d)) best = { d, c }; }
      return best ? best.c : null;
    };
    const setupFails = S.smCtx.filter((x) => x.state === 12);
    for (const f of setupFails) {
      const c = nearestCause(f.t);
      ev(f.imsi, { t: f.t, layer: 'ran', kind: 'setup_fail', sev: 'ran', label: 'gNB could not set up the radio bearer',
        detail: `PDU session ${f.psi} resource setup failed${c ? ' — ' + causeText(c.g, c.c) : ''}`, cause: c ? causeText(c.g, c.c) : null });
    }
    for (const q of S.qosRejects) {
      const near = S.smCtx.filter((x) => Math.abs(x.t - q.t) <= 3000).sort((a, b) => Math.abs(a.t - q.t) - Math.abs(b.t - q.t))[0];
      if (near) ev(near.imsi, { t: q.t, layer: 'ran', kind: 'qos_reject', sev: 'ran', label: 'gNB refused voice/video QoS flows', detail: 'PDU Session Resource Modify returned no modified flows (GBR voice/video bearer not admitted)' });
    }
    for (const r of S.ran) {
      if (!r.imsi) continue;
      if (r.type === 'reconnect') ev(r.imsi, { t: r.t, layer: 'ran', kind: 'reconnect', sev: 'info', label: r.kind === 'service' ? 'Reconnected (service request)' : 'Reconnected (registration)', detail: 'InitialUEMessage from the gNB' });
      else if (r.type === 'rlf') ev(r.imsi, { t: r.t, layer: 'ran', kind: 'rlf', sev: 'ran', label: 'Came back on a new radio connection', detail: 'The gNB still held the old UE context: the radio link dropped without the gNB telling the core' });
      else if (r.type === 'release') {
        if (r.action === 1) continue;
        const sf = setupFails.find((f) => f.imsi === r.imsi && r.t - f.t >= 0 && r.t - f.t <= 2000);
        const dr = S.ran.find((x) => x.type === 'ue_dereg' && x.imsi === r.imsi && r.t - x.t >= 0 && r.t - x.t <= 2000);
        if (dr) continue;
        const c = sf ? nearestCause(sf.t) : null;
        ev(r.imsi, { t: r.t, layer: 'ran', kind: 'gnb_release', sev: 'ran', label: sf ? 'gNB released the UE after a failed bearer setup' : 'Released to idle by the gNB',
          detail: sf ? (c ? causeText(c.g, c.c) : 'setup failure') : 'UE Context Release (radio connection ended)' });
      }
      else if (r.type === 'ue_dereg') ev(r.imsi, { t: r.t, layer: 'ue', kind: 'ue_dereg', sev: 'ue', label: 'Phone detached itself', detail: 'NAS Deregistration Request from the phone (power-off or airplane mode)' });
    }
    for (const x of S.smCtx) {
      if (x.state === 51) ev(x.imsi, { t: x.t, layer: 'ran', kind: 'gnb_lost', sev: 'ran', label: 'gNB link lost', detail: `Session ${x.psi} deactivated because the gNB's N2 link went down` });
      if (x.state === 52 || x.state === 53) ev(x.imsi, { t: x.t, layer: 'ran', kind: 'gnb_reset', sev: 'ran', label: 'gNB reset', detail: `Session ${x.psi} deactivated by an NG Reset from the gNB` });
    }
    // de-duplicate per-session gNB loss/reset to one per UE per second
    for (const u of ues.values()) {
      const seenKey = new Set();
      u.events = u.events.filter((e) => { if (e.kind !== 'gnb_lost' && e.kind !== 'gnb_reset') return true; const k = e.kind + Math.floor(e.t / 1000); if (seenKey.has(k)) return false; seenKey.add(k); return true; });
    }
    for (const c of S.core) {
      const map = { mobile_unreachable: ['Core marked the UE unreachable', 'Mobile reachable timer expired (no contact since the UE went idle)'],
        implicit_dereg: ['Core deregistered the UE (implicit)', 'Implicit deregistration after the UE stayed unreachable'],
        net_dereg: ['Core started network deregistration', 'Network-initiated deregistration'],
        paging_failed: ['Paging failed', 'Downlink data was waiting but the UE did not answer paging'],
        reject: ['Core rejected a request', c.text || 'reject'] }[c.type];
      if (c.imsi) ev(c.imsi, { t: c.t, layer: 'core', kind: c.type, sev: c.type === 'reject' ? 'core' : 'info', label: map[0], detail: map[1] });
    }

    // ---- sessions & network-initiated releases ----
    const findings = [];
    const sessionsByImsi = new Map();
    for (const s of S.sessions) {
      if (s.up) { ev(s.imsi, { t: s.t, layer: 'core', kind: 'session_up', sev: 'info', label: `${s.dnn} session up`, detail: `IP ${s.ip}` }); continue; }
      const near = (arr, pred, win) => arr.find((x) => pred(x) && s.t - x.t >= -win && s.t - x.t <= win);
      let why = null, blame = false;
      if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && x.state === 'N1-RELEASED', 5000)) why = 'released by the phone';
      else if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && /^REL3[234]$/.test(x.state), 3000)) why = 'dropped by the phone: it reported the session as gone when it reconnected';
      else if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && x.state === 'DUPLICATED_PDU_SESSION_ID', 3000)) why = 'replaced: the phone re-sent the session request';
      else if (near(S.core, (x) => x.imsi === s.imsi && /dereg/.test(x.type), 3000)) why = 'removed during deregistration';
      else if (near(S.ran, (x) => x.imsi === s.imsi && x.type === 'ue_dereg', 3000)) why = 'removed because the phone detached';
      else { const tr = near(S.trig, (x) => x.imsi === s.imsi && x.psi === s.psi, 3000); why = tr ? `released by the network (PFCP delete trigger ${tr.trigger})` : 'released by the network'; blame = true; }
      ev(s.imsi, { t: s.t, layer: 'core', kind: blame ? 'session_down_net' : 'session_down', sev: blame ? 'core' : 'info', label: `${s.dnn} session removed`, detail: `${s.ip || ''} — ${why}` });
      if (blame) findings.push({ t: s.t, sev: 'critical', comp: 'SMF', title: `Network released ${s.dnn} session of ${s.imsi}`, detail: `${why}; IP ${s.ip}`, imsi: [s.imsi] });
    }

    // ---- UE death evidence from IMS TCP timeouts ----
    for (const x of S.imsTcp) {
      const im = imsiForIp(x.ip, x.t);
      if (im) ev(im, { t: x.t, layer: 'ims', kind: 'ims_tcp_timeout', sev: 'info', label: 'IMS lost its TCP connection to the phone', detail: `${x.node} got no TCP acknowledgements from ${x.ip}:${x.port}; Linux gives up about 15 minutes after the phone stops answering` });
    }
    for (const x of S.spoof) {
      const im = imsiForIp(x.ue, x.t);
      if (im) ev(im, { t: x.t, layer: 'core', kind: 'spoof', sev: 'warn', label: 'UPF dropped packets from a stale IP', detail: `Phone sent from ${x.src} but its session IP is now ${x.ue} (${x.apn})` });
    }

    // ---- core health: lifecycle, PFCP, tun, EAGAIN ----
    const episodes = (arr, gapMs) => {
      const out = []; let cur = null;
      for (const t of arr.slice().sort((a, b) => a - b)) {
        if (cur && t - cur.end <= gapMs) { cur.end = t; cur.count++; } else { cur = { start: t, end: t, count: 1 }; out.push(cur); }
      }
      return out;
    };
    const warmup = logStart + 90 * 1000;
    const nfTimeline = {};
    for (const l of S.lifecycle) {
      (nfTimeline[l.nf] = nfTimeline[l.nf] || []).push(l);
      if (l.kind === 'crash') findings.push({ t: l.t, sev: 'critical', comp: l.nf, title: `${l.nf} crashed`, detail: l.text || 'FATAL' });
      else if (l.kind === 'start' && l.t > warmup) findings.push({ t: l.t, sev: 'critical', comp: l.nf, title: `${l.nf} restarted during the run`, detail: 'Process initialised again; sessions it held were lost' });
    }
    for (const p of S.pfcp) {
      if (!p.up && p.t > warmup && !S.lifecycle.some((l) => l.kind === 'stop' && Math.abs(l.t - p.t) < 5000)) {
        findings.push({ t: p.t, sev: 'critical', comp: p.nf, title: 'SMF–UPF PFCP association lost', detail: `${p.nf} lost PFCP with ${p.peer}` });
      }
    }
    // Which DNN is the dead tun serving? Tun write failures follow session activations on that DNN within seconds.
    const psiDnn = new Map();
    for (const s of S.sessions) if (!s.up && s.psi) psiDnn.set(s.imsi + ':' + s.psi, s.dnn);
    for (const s of S.sessions) if (s.up) {
      const act = S.smCtx.find((x) => x.imsi === s.imsi && x.state === 11 && x.t >= s.t && x.t - s.t <= 3000);
      if (act && !psiDnn.has(s.imsi + ':' + act.psi)) psiDnn.set(s.imsi + ':' + act.psi, s.dnn);
    }
    const activations = S.smCtx.filter((x) => x.state === 11).map((x) => ({ t: x.t, imsi: x.imsi, dnn: psiDnn.get(x.imsi + ':' + x.psi) || null }));
    const tunEp = episodes(S.tun, 600000);
    for (const e of tunEp) {
      const tally = {};
      for (const t of S.tun) {
        if (t < e.start || t > e.end) continue;
        const a = activations.filter((x) => x.dnn && t - x.t >= 0 && t - x.t <= 3000);
        for (const x of a) tally[x.dnn] = (tally[x.dnn] || 0) + 1;
      }
      const dnn = Object.keys(tally).sort((a, b) => tally[b] - tally[a])[0] || null;
      const affected = [...new Set([...S.sessions.filter((s) => !dnn || s.dnn === dnn).map((s) => s.imsi),
        ...activations.filter((x) => (!dnn || x.dnn === dnn) && x.t >= e.start - 600000 && x.t <= e.end).map((x) => x.imsi)])];
      findings.push({ t: e.start, end: e.end, sev: 'critical', comp: 'UPF', dnn, affected,
        title: `UPF discarded uplink packets${dnn ? ' on the ' + dnn + ' DNN' : ''} (tun interface down)`,
        detail: `${e.count} ogs_tun_write() failures from ${fmt(e.start)} to ${fmt(e.end)}. Packets from the phones never left the UPF${dnn ? ' on the ' + dnn + ' DNN' : ''}, so ${dnn === 'ims' ? 'SIP registration and calls could not work' : 'data could not flow'}. The ${dnn === 'ims' ? 'IMS ' : ''}tun interface (ogstun*) was down or had no address.` });
    }
    const eagEp = episodes(S.eagain, 600000);
    if (S.eagain.length) {
      findings.push({ t: S.eagain[0], end: S.eagain[S.eagain.length - 1], sev: 'warning', comp: 'UPF', title: 'UPF dropped some downlink packets (send buffer full)',
        detail: `${S.eagain.length} GTP-U sends failed with EAGAIN across the run. Short bursts cause packet loss, not disconnections. Raising net.core.wmem_default/wmem_max reduces them.`, count: S.eagain.length });
    }
    if (S.spoof.length) findings.push({ t: S.spoof[0].t, sev: 'warning', comp: 'UPF', title: 'UPF dropped packets sent from stale UE IPs', detail: `${S.spoof.length} packets: the phone kept using an old IP after its session was re-created`, count: S.spoof.length });
    for (const m of S.imsMarkers) findings.push({ t: m.t, sev: 'critical', comp: m.node, title: 'IMS tore down a dialog', detail: m.text });

    // ---- calls ----
    const byCid = new Map();
    for (const r of S.sip) { if (!byCid.has(r.cid)) byCid.set(r.cid, []); byCid.get(r.cid).push(r); }
    const calls = [];
    for (const [cid, reqs] of byCid) {
      const inv = reqs.filter((r) => r.method === 'INVITE');
      if (!inv.length) continue;
      const fromUe = reqs.filter((r) => ueIPs.has(r.srcIp));
      const first = fromUe.find((r) => r.method === 'INVITE') || inv[0];
      const callerIp = ueIPs.has(first.srcIp) ? first.srcIp : null;
      let calleeIp = (inv.find((r) => r.ruriIp && ueIPs.has(r.ruriIp) && r.ruriIp !== callerIp) || {}).ruriIp || null;
      if (!calleeIp) calleeIp = (fromUe.find((r) => r.srcIp !== callerIp) || {}).srcIp || null;
      const callerImsi = imsiForUser(first.fromUser) || imsiForIp(callerIp, first.t);
      const calleeImsi = imsiForUser(first.toUser) || imsiForIp(calleeIp, first.t);
      const rtp = S.rtp.get(cid) || null;
      const dlg = S.dialogs.get(cid) || null;
      const byes = fromUe.filter((r) => r.method === 'BYE' || r.method === 'CANCEL');
      const reinv = fromUe.filter((r) => r.method === 'INVITE' && r !== first);
      const updates = fromUe.filter((r) => r.method === 'UPDATE');
      const side = (ip) => {
        if (!rtp || !ip) return null;
        const st = rtp.streams.filter((s) => s.ip === ip && !s.rtcp);
        const a = st.filter((s) => s.media === 'audio'), v = st.filter((s) => s.media === 'video');
        const agg = (xs) => xs.length ? { packets: xs.reduce((n, s) => n + s.packets, 0), lastT: Math.max(...xs.map((s) => s.lastT)), mos: xs.map((s) => rtp.mos[s.ssrc]).filter(Boolean)[0] || null } : null;
        return { audio: agg(a), video: agg(v) };
      };
      const A = side(callerIp), B = side(calleeIp);
      const established = !!dlg || !!(A && A.audio && A.audio.packets > 20 && B && B.audio && B.audio.packets > 20);
      let end = null, endedBy = 'ongoing', byeFrom = [];
      if (byes.length) {
        end = byes[0].t; byeFrom = byes.filter((b) => b.t - end <= 3000).map((b) => b.srcIp === callerIp ? 'caller' : b.srcIp === calleeIp ? 'callee' : b.srcIp);
        byeFrom = [...new Set(byeFrom)]; endedBy = 'phone';
      } else {
        const cands = [dlg && dlg.last < logEnd - 30000 ? dlg.last : null, rtp && rtp.del, rtp && rtp.timeoutClose].filter(Boolean);
        if (cands.length) { end = Math.min(...cands); endedBy = 'network'; }
      }
      const call = { cid, start: first.t, end, endedBy, byeFrom, established,
        caller: { imsi: callerImsi, ip: callerIp, user: first.fromUser, media: A },
        callee: { imsi: calleeImsi, ip: calleeIp, user: first.toUser, media: B },
        hadVideo: !!((A && A.video && A.video.packets > 50) || (B && B.video && B.video.packets > 50)),
        reinvites: reinv.map((r) => ({ t: r.t, by: r.srcIp === callerIp ? 'caller' : 'callee' })),
        refreshes: updates.length, lastRefresh: updates.length ? updates[updates.length - 1].t : null,
        refreshInterval: updates.length > 2 ? Math.round((updates[updates.length - 1].t - updates[0].t) / (updates.length - 1) / 1000) : null,
        rtpTimeout: rtp && rtp.timeoutClose ? rtp.timeoutClose : null };
      calls.push(call);
    }
    calls.sort((a, b) => a.start - b.start);

    // core faults near a time (global or for given imsis)
    const touches = (f, imsis) => {
      if (!imsis) return true;
      const own = f.imsi || f.affected;
      return !own || own.some((i) => imsis.includes(i));
    };
    function coreFaultsNear(t, winBefore, winAfter, imsis) {
      return findings.filter((f) => f.sev === 'critical' && (f.end ? f.end >= t - winBefore && f.t <= t + winAfter : f.t >= t - winBefore && f.t <= t + winAfter) && touches(f, imsis));
    }
    const ranNear = (imsi, t, before, after) => (ues.get(imsi) ? ues.get(imsi).events : []).filter((e) => (e.sev === 'ran' || e.kind === 'ue_dereg') && e.t >= t - before && e.t <= t + after);

    for (const c of calls) {
      const names = { caller: c.caller, callee: c.callee };
      const nm = (p) => p.user || p.imsi || p.ip || '?';
      const reasons = []; let blame = 'ran', headline = '';
      if (c.caller.imsi) { const u = ue(c.caller.imsi); u.calls.push(c.cid); }
      if (c.callee.imsi) { const u = ue(c.callee.imsi); u.calls.push(c.cid); }
      // video
      if (c.hadVideo && c.end) {
        const vt = [c.caller.media && c.caller.media.video, c.callee.media && c.callee.media.video].filter(Boolean).map((v) => v.lastT);
        const vStop = vt.length ? Math.max(...vt) : null;
        if (vStop && vStop >= c.end - 60000) c.videoReason = 'Video ran until the call ended.';
        if (vStop && vStop < c.end - 60000) {
          const ri = c.reinvites.find((r) => Math.abs(r.t - vStop) <= 6000);
          c.videoStop = vStop; c.videoStopBy = ri ? ri.by : null;
          const who = ri ? nm(names[ri.by]) : null;
          const ranPre = [c.caller.imsi, c.callee.imsi].filter(Boolean).flatMap((im) => ranNear(im, vStop, 180000, 5000).map((e) => `${fmt(e.t)} ${im.slice(-3)}: ${e.label}`));
          const cf = coreFaultsNear(vStop, 120000, 5000, [c.caller.imsi, c.callee.imsi]);
          c.videoReason = (ri ? `Video stopped at ${fmt(vStop)} when ${who} sent a re-INVITE removing it (a phone decision).` : `Video stopped at ${fmt(vStop)}.`)
            + (cf.length ? ` Core fault at the same time: ${cf[0].title}.` : ranPre.length ? ` gNB events just before: ${ranPre.slice(0, 3).join('; ')}.` : ' No core or gNB event before it; phones usually do this when video quality is too poor.');
          c.videoBlame = cf.length ? 'core' : 'ran';
        }
      }
      if (!c.established) {
        headline = 'Call did not connect'; blame = 'unknown';
        reasons.push(c.byeFrom.length ? `${c.byeFrom.join(' & ')} cancelled before it connected` : 'No media was exchanged; the rejection code is not in these logs');
      } else if (c.endedBy === 'ongoing') {
        headline = 'Still up at the end of the log'; blame = 'none';
      } else if (c.endedBy === 'network') {
        const la = [c.caller.media && c.caller.media.audio, c.callee.media && c.callee.media.audio].filter(Boolean).map((a) => a.lastT);
        const lastMedia = la.length ? Math.max(...la) : null;
        if (lastMedia && lastMedia < c.end - 60000) {
          headline = 'IMS cleared a call after both phones had gone silent'; blame = 'ran';
          reasons.push(`No BYE from either phone. Media from both phones had stopped by ${fmt(lastMedia)}; the network removed the dead call at ${fmt(c.end)}.`);
        } else {
          headline = 'The network ended the call'; blame = 'core';
          reasons.push(`Neither phone sent a BYE, yet the dialog/media session was removed at ${fmt(c.end)} while media was still flowing.`);
          if (c.rtpTimeout) reasons.push(`RTPEngine closed the media session on timeout at ${fmt(c.rtpTimeout)}.`);
          findings.push({ t: c.end, sev: 'critical', comp: 'IMS', title: `IMS ended call ${nm(c.caller)} → ${nm(c.callee)}`, detail: reasons.join(' '), imsi: [c.caller.imsi, c.callee.imsi].filter(Boolean) });
        }
      } else {
        const who = c.byeFrom.includes('caller') && c.byeFrom.includes('callee') ? 'both' : c.byeFrom[0];
        const actor = who === 'both' ? 'Both phones' : nm(names[who] || {});
        const other = who === 'caller' ? c.callee : who === 'callee' ? c.caller : null;
        const self = who === 'caller' ? c.caller : who === 'callee' ? c.callee : null;
        const oa = other && other.media && other.media.audio;
        const sa = self && self.media && self.media.audio;
        if (other && oa && sa && oa.lastT < c.end - 8000 && sa.lastT < c.end - 8000) {
          const stopT = Math.max(oa.lastT, sa.lastT);
          headline = `Media stopped in both directions; ${actor} hung up`;
          reasons.push(`Media from both phones stopped reaching the core at ${fmt(stopT)}. ${actor} hung up ${Math.round((c.end - stopT) / 1000)} s later (no incoming media).`);
          c.silentSide = 'both'; c.silentAt = stopT;
        } else if (other && oa && oa.lastT < c.end - 8000) {
          headline = `${nm(other)} went silent; ${actor} hung up`;
          reasons.push(`${nm(other)} stopped sending media at ${fmt(oa.lastT)}. ${actor} hung up ${Math.round((c.end - oa.lastT) / 1000)} s later (no incoming media).`);
          c.silentSide = other.imsi; c.silentAt = oa.lastT;
        } else if (who === 'both') {
          headline = 'Both phones hung up at the same moment';
          reasons.push(`Both phones sent BYE at ${fmt(c.end)} while media was still reaching the core from both. The network did not ask them to.`);
        } else {
          headline = `${actor} hung up while media was flowing`;
          reasons.push(`${actor} sent BYE at ${fmt(c.end)} while audio was still arriving from both phones: a phone-side decision, not the network.`);
        }
        if (c.lastRefresh && c.refreshInterval) {
          const due = c.lastRefresh + c.refreshInterval * 1000;
          if (Math.abs(c.end - due) <= 5000) reasons.push(`It happened at the moment the next session refresh was due (${fmt(due)}); every earlier refresh (${c.refreshes}) succeeded.`);
        }
        const cf = coreFaultsNear(c.silentAt || c.end, 120000, 5000, [c.caller.imsi, c.callee.imsi]);
        if (cf.length) { blame = 'core'; reasons.push(`Core fault at that time: ${cf[0].title} (${fmt(cf[0].t)}).`); }
        else {
          const around = [c.caller.imsi, c.callee.imsi].filter(Boolean).flatMap((im) => ranNear(im, c.end, 180000, 5000).map((e) => `${fmt(e.t)} ${im.slice(-3)}: ${e.label}`));
          reasons.push(around.length ? `gNB events just before: ${around.slice(0, 3).join('; ')}.` : 'No core, IMS or gNB event around the drop.');
        }
      }
      // media quality
      for (const p of [c.caller, c.callee]) {
        if (p.media && p.media.audio && c.end && c.established) {
          const dur = Math.max(1, (Math.min(p.media.audio.lastT, c.end) - c.start) / 1000);
          p.media.audio.pps = +(p.media.audio.packets / dur).toFixed(2);
        }
      }
      const lowPps = [c.caller, c.callee].filter((p) => p.media && p.media.audio && p.media.audio.pps !== undefined && p.media.audio.pps < 3);
      if (lowPps.length && c.established) reasons.push(`Very little audio reached the core from ${lowPps.map(nm).join(' and ')} (${lowPps.map((p) => p.media.audio.pps + ' pkt/s').join(', ')}; about 6+ expected even in silence), so the radio link was losing most voice packets.`);
      c.headline = headline; c.blame = blame; c.reasons = reasons;
    }

    // ---- pings -> data reachability per UE ----
    const manualMap = opts.ipMap || {};
    function imsiForPingIp(ip, t) {
      if (manualMap[ip]) return { imsi: manualMap[ip], how: 'set by you' };
      const im = imsiForIp(ip, t);
      if (im) return { imsi: im, how: 'from core logs' };
      const n = +String(ip).split('.').pop();
      const cands = [...ues.keys()].filter((x) => +x.slice(-3) === n);
      if (cands.length === 1) return { imsi: cands[0], how: 'guessed from IP number' };
      return { imsi: null, how: '' };
    }
    const pingInfo = [];
    for (const p of S.pings) {
      let last = null, src = '';
      if (p.manualWall) { last = p.manualWall; src = p.name; }
      else if (p.lastTs) { last = p.lastTs.epoch ? wallFromEpoch(p.lastTs.epoch) : p.lastTs.wall; src = 'last reply timestamp'; }
      else if (p.mtimeEpoch && !p.empty) { last = wallFromEpoch(p.mtimeEpoch); src = 'file modified time'; }
      const m = imsiForPingIp(p.ip, last);
      pingInfo.push({ ip: p.ip, imsi: m.imsi, mappedBy: m.how, last, source: src, empty: !!(p.empty && !p.manualWall), name: p.name });
      if (!m.imsi) continue;
      const u = ue(m.imsi);
      u.ips.internet = u.ips.internet || [];
      if (!u.ips.internet.includes(p.ip)) u.ips.internet.push(p.ip);
      if (last) { u.last.ping = last; u.pingSource = src; u.pingMappedBy = m.how; }
      else if (p.empty && !p.manualWall) u.pingEmpty = true;
    }

    // ---- per-UE last activity & verdicts ----
    for (const u of ues.values()) {
      const ips = new Set(Object.values(u.ips).flat());
      const sip = S.sip.filter((r) => ips.has(r.srcIp) && imsiForIp(r.srcIp, r.t) === u.imsi);
      u.last.sip = sip.length ? sip[sip.length - 1].t : null;
      let rtpLast = null;
      for (const c of calls) for (const p of [c.caller, c.callee]) {
        if (p.imsi === u.imsi && p.media && p.media.audio) rtpLast = Math.max(rtpLast || 0, p.media.audio.lastT);
      }
      u.last.media = rtpLast;
      const nas = u.events.filter((e) => ['reconnect', 'gnb_release', 'setup_fail', 'rlf', 'ue_dereg', 'qos_reject'].includes(e.kind));
      u.last.nas = nas.length ? nas[nas.length - 1].t : null;
      u.events.sort((a, b) => a.t - b.t);
      u.first = u.events.length ? u.events[0].t : logStart;
    }

    const gnbEvents = S.gnb.filter((g) => g.type !== 'count');
    const lbl = (e) => e.label.charAt(0).toLowerCase() + e.label.slice(1);
    for (const u of ues.values()) {
      const V = { status: 'ok', blame: 'none', headline: '', reasons: [], dropT: null, dropBasis: '', coreImpact: [] };
      const tcp = u.events.filter((e) => e.kind === 'ims_tcp_timeout');
      const inCall = calls.filter((c) => c.silentAt && (c.silentSide === u.imsi || (c.silentSide === 'both' && (c.caller.imsi === u.imsi || c.callee.imsi === u.imsi))));
      const lastSign = Math.max(u.last.sip || 0, u.last.media || 0, u.last.nas || 0) || null;
      if (u.last.ping) {
        if (u.last.ping < logEnd - 180000) { V.dropT = u.last.ping; V.dropBasis = 'last ping reply'; }
      } else if (inCall.length) {
        const c = inCall[inCall.length - 1];
        const laterActivity = Math.max(u.last.sip || 0, u.last.nas || 0) > c.silentAt + 60000;
        if (!laterActivity) { V.dropT = c.silentAt; V.dropBasis = 'last media packet in its call'; }
      }
      const lastActive = V.dropT || u.last.ping || lastSign || logEnd;
      V.coreImpact = findings.filter((f) => f.sev === 'critical' && touches(f, [u.imsi]) && (f.end || f.t) >= u.first && f.t <= lastActive)
        .map((f) => ({ t: f.t, end: f.end || null, title: f.title, detail: f.detail, named: !!(f.imsi || f.affected) }));

      if (!V.dropT) {
        if (u.pingEmpty && !u.last.ping) { V.status = 'nodata'; V.headline = 'Never answered pings in this run'; V.reasons.push('Its ping log was empty.'); }
        else if (V.coreImpact.length) {
          V.status = 'impaired'; V.blame = 'core'; V.headline = 'Service broken by a core fault';
          for (const f of V.coreImpact.slice(0, 3)) V.reasons.push(`${f.title}${f.end ? ` (${fmt(f.t)}–${fmt(f.end)})` : ` at ${fmt(f.t)}`}. ${f.detail}`);
        } else {
          V.status = 'ok'; V.headline = u.last.ping ? 'Reachable until the end of the log' : 'No drop detected';
          V.reasons.push(u.last.ping ? `Last ping reply ${fmt(u.last.ping)}.` : `Last activity ${fmt(lastSign)}. Nothing in the core or IMS logs shows it failing. Add its ping log to check data reachability.`);
        }
        u.verdict = V; continue;
      }
      const T = V.dropT;
      V.status = 'dropped';
      const cf = coreFaultsNear(T, 180000, 30000, [u.imsi]);
      const dereg = u.events.find((e) => e.kind === 'ue_dereg' && e.t >= T - 60000 && e.t <= T + 180000);
      const gdown = gnbEvents.find((g) => (g.type === 'link_lost' || g.type === 'ng_reset') && g.t >= T - 60000 && g.t <= T + 90000);
      const rel = u.events.filter((e) => ['gnb_release', 'setup_fail', 'rlf'].includes(e.kind) && e.t >= T - 180000 && e.t <= T + 60000);
      const after = u.events.filter((e) => e.t > T + 60000 && ['reconnect', 'ue_dereg', 'gnb_reset', 'gnb_lost', 'implicit_dereg', 'mobile_unreachable'].includes(e.kind));
      const cameBack = after.find((e) => e.kind === 'reconnect');
      if (cf.length) {
        V.blame = 'core'; V.headline = `Core/IMS fault: ${cf[0].title}`;
        V.reasons.push(`${cf[0].detail}`);
      } else if (dereg) {
        V.blame = 'ue'; V.headline = 'Phone detached itself';
        V.reasons.push(`The phone sent a Deregistration Request at ${fmt(dereg.t)} (switch-off, airplane mode or low battery).`);
      } else if (gdown) {
        V.blame = 'ran'; V.headline = gdown.type === 'ng_reset' ? 'gNB reset' : 'gNB link to the core dropped';
        V.reasons.push(`${gdown.type === 'ng_reset' ? 'The gNB sent an NG Reset' : "The gNB's N2 (SCTP) link went down"} at ${fmt(gdown.t)}.`);
      } else if (rel.length && !cameBack) {
        V.blame = 'ran'; V.headline = 'gNB released the UE and it never came back';
        V.reasons.push(rel.map((e) => `${fmt(e.t)} ${lbl(e)}${e.detail ? ' (' + e.detail + ')' : ''}`).join('; ') + '.');
      } else {
        V.blame = 'ran'; V.headline = 'Phone went silent on the radio side';
        V.reasons.push(`No release from the gNB, no detach from the phone, and no core or IMS fault around ${fmt(T)}.`);
        const holdUntil = after.find((e) => ['gnb_reset', 'gnb_lost', 'reconnect', 'implicit_dereg', 'mobile_unreachable'].includes(e.kind));
        V.reasons.push(holdUntil ? `The core still treated it as attached until ${fmt(holdUntil.t)} (${lbl(holdUntil)}).` : 'The core still treated it as attached until the end of the log.');
        if (rel.length) V.reasons.push(`Radio events shortly before: ${rel.map((e) => `${fmt(e.t)} ${lbl(e)}`).join('; ')}.`);
      }
      for (const c of inCall) V.reasons.push(`In its call, media from it stopped at ${fmt(c.silentAt)}${c.silentSide === 'both' ? ' (both directions)' : ''}.`);
      // A read timeout on an established SIP/TCP connection means the phone stopped answering at the latest ~15 min earlier.
      const imsLoss = tcp.map((e) => ({ e, d: e.t - 930000 })).find((x) => (u.last.media && Math.abs(x.d - u.last.media) <= 300000) || (x.d >= T - 300000 && x.d <= T + 1800000));
      if (imsLoss && u.last.ping && imsLoss.d < T - 300000) V.reasons.push(`Its IMS path (SIP and media) died around ${fmt(Math.min(imsLoss.d, u.last.media || imsLoss.d))}, while data pings kept working until ${fmt(u.last.ping)}. IMS confirmed it: TCP to the phone timed out at ${fmt(imsLoss.e.t)}.`);
      else if (imsLoss) V.reasons.push(`IMS also lost contact with it: TCP to the phone timed out at ${fmt(imsLoss.e.t)}.`);
      const cleanup = u.events.filter((e) => e.t > T && ['mobile_unreachable', 'implicit_dereg', 'paging_failed'].includes(e.kind));
      if (cleanup.length) V.reasons.push(`Later core cleanup (a consequence, not the cause): ${cleanup.map((e) => `${fmt(e.t)} ${lbl(e)}`).join('; ')}.`);
      if (V.blame !== 'core' && V.coreImpact.length) V.reasons.push(`Earlier in the night it was hit by a core fault: ${V.coreImpact[0].title}.`);
      u.verdict = V;
    }

    // ---- global ----
    const coreCrit = findings.filter((f) => f.sev === 'critical');
    const ueList = [...ues.values()].filter((u) => u.events.length || u.calls.length || u.last.ping || u.pingEmpty)
      .sort((a, b) => (a.imsi > b.imsi ? 1 : -1));
    const drops = ueList.filter((u) => u.verdict && u.verdict.status === 'dropped');
    const summary = {
      ues: ueList.length, drops: drops.length,
      coreBlamed: ueList.filter((u) => u.verdict && u.verdict.blame === 'core').length + calls.filter((c) => c.blame === 'core').length,
      impaired: ueList.filter((u) => u.verdict && u.verdict.status === 'impaired').length,
      ueDrops: { core: drops.filter((u) => u.verdict.blame === 'core').length, ran: drops.filter((u) => u.verdict.blame === 'ran').length, ue: drops.filter((u) => u.verdict.blame === 'ue').length },
      calls: calls.length, callsEstablished: calls.filter((c) => c.established).length,
      callsCore: calls.filter((c) => c.blame === 'core').length, callsVideoDropped: calls.filter((c) => c.videoStop).length,
      coreFaults: coreCrit.length, coreWarnings: findings.filter((f) => f.sev === 'warning').length
    };
    const hourly = (arr) => { const m = new Map(); for (const t of arr) { const h = Math.floor(t / 3600000) * 3600000; m.set(h, (m.get(h) || 0) + 1); } return [...m.entries()].sort((a, b) => a[0] - b[0]).map(([t, n]) => ({ t, n })); };
    const nfNames = [...new Set(Object.keys(S.sources).map((s) => s.replace(/-FILE$/, '')))].sort();
    const errors = [...S.errors.values()].sort((a, b) => b.count - a.count);
    const health = nfNames.map((nf) => {
      const lc = (nfTimeline[nf] || []);
      const errs = errors.filter((e) => e.comp === nf);
      return { nf, lines: (S.sources[nf] || 0) + (S.sources[nf + '-FILE'] || 0), starts: lc.filter((l) => l.kind === 'start').length,
        restartsMidRun: lc.filter((l) => l.kind === 'start' && l.t > warmup).length, crashes: lc.filter((l) => l.kind === 'crash').length,
        stops: lc.filter((l) => l.kind === 'stop').length, errors: errs.reduce((n, e) => n + e.count, 0), topErrors: errs.slice(0, 4) };
    });
    findings.sort((a, b) => a.t - b.t);
    return {
      meta: { lines: S.lines, bytes: S.bytes, start: logStart, end: logEnd, tzOffsetSec: tz, sources: S.sources },
      summary, findings, calls, pings: pingInfo,
      ues: ueList.map((u) => ({ imsi: u.imsi, msisdn: u.msisdn,
        ips: Object.fromEntries(Object.entries(u.ips).map(([k, v]) => [k, { latest: v.slice(-3), count: v.length }])),
        last: u.last, pingSource: u.pingSource || null, pingMappedBy: u.pingMappedBy || null, verdict: u.verdict, calls: u.calls, events: u.events })),
      gnb: gnbEvents, health, errors: errors.slice(0, 40),
      series: { eagainHourly: hourly(S.eagain), tunHourly: hourly(S.tun) },
      pfcp: S.pfcp, lifecycle: S.lifecycle
    };
  }

  // ---- streaming helper for browsers: File/Blob -> analyzer ----
  async function analyzeBlob(analyzer, blob, onProgress) {
    let stream = blob.stream();
    if (/\.gz$/i.test(blob.name || '') && typeof DecompressionStream !== 'undefined') stream = stream.pipeThrough(new DecompressionStream('gzip'));
    const reader = stream.pipeThrough(new TextDecoderStream()).getReader();
    let buf = '', done = 0, lastTick = 0;
    for (;;) {
      const { value, done: fin } = await reader.read();
      if (fin) break;
      buf += value; done += value.length;
      let i, s = 0;
      while ((i = buf.indexOf('\n', s)) >= 0) { const e = buf.charCodeAt(i - 1) === 13 ? i - 1 : i; analyzer.pushLine(buf.slice(s, e)); s = i + 1; }
      buf = buf.slice(s);
      if (onProgress && done - lastTick > 4e6) { lastTick = done; onProgress(done); await new Promise((r) => setTimeout(r, 0)); }
    }
    if (buf) analyzer.pushLine(buf);
  }

  const api = { createAnalyzer, analyzeBlob, causeText };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.CoreAlibi = api;

  // ---- Node CLI ----
  if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
    const fs = require('fs'), readline = require('readline');
    const args = process.argv.slice(2);
    const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null;
    const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--json' && args[i - 1] !== '--ping');
    const manual = args.map((a, i) => (args[i - 1] === '--ping' ? a : null)).filter(Boolean);
    if (!files.length) { console.error('usage: node analyzer.js all.log [ping_<ip>.log ...] [--ping IP=YYYY-MM-DDTHH:MM:SS] [--json out.json]'); process.exit(1); }
    (async () => {
      const an = createAnalyzer();
      for (const f of files) {
        if (/ping/i.test(require('path').basename(f))) { an.addPingFile(require('path').basename(f), fs.readFileSync(f, 'utf8'), fs.statSync(f).mtimeMs); continue; }
        const rl = readline.createInterface({ input: fs.createReadStream(f), crlfDelay: Infinity });
        for await (const line of rl) an.pushLine(line);
      }
      for (const m of manual) { const [ip, ts] = m.split('='); an.addPingManual(ip, Date.parse(ts + 'Z'), 'ping (given)'); }
      const r = an.finish();
      if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(r));
      const f = (t) => (t == null ? '—' : new Date(t).toISOString().replace('T', ' ').slice(0, 19));
      console.log(`Log ${f(r.meta.start)} → ${f(r.meta.end)}  (${r.meta.lines} lines)`);
      console.log(`UEs ${r.summary.ues}, drops ${r.summary.drops}, calls ${r.summary.calls}, core faults ${r.summary.coreFaults}, warnings ${r.summary.coreWarnings}`);
      for (const x of r.findings) console.log(`  [${x.sev}] ${f(x.t)} ${x.comp}: ${x.title}`);
      for (const u of r.ues) console.log(`\n${u.imsi} ${u.msisdn.join(',')} ${Object.entries(u.ips).map(([k, v]) => k + ':' + v.latest.join('/') + (v.count > 3 ? ' (+' + (v.count - 3) + ')' : '')).join(' ')} ${u.pingMappedBy ? '[ping ' + u.pingMappedBy + ']' : ''}\n  ${u.verdict.status}/${u.verdict.blame} @ ${f(u.verdict.dropT)}: ${u.verdict.headline}\n  - ${u.verdict.reasons.join('\n  - ')}`);
      for (const c of r.calls) console.log(`\nCALL ${f(c.start)} ${c.caller.user}(${(c.caller.imsi || '').slice(-3)}) → ${c.callee.user}(${(c.callee.imsi || '').slice(-3)}) end ${f(c.end)} [${c.blame}] ${c.headline}\n  video: ${c.videoReason || '-'}\n  - ${c.reasons.join('\n  - ')}`);
    })();
  }
})(typeof window !== 'undefined' ? window : globalThis);
